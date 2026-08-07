#include "agent.h"
#include "agent_commands.h"
#include "agent_prompt.h"
#include "config.h"
#include "local_admin.h"
#include "llm.h"
#include "login.h"
#include "tools.h"
#include "user_tools.h"
#include "json_util.h"
#include "messages.h"
#include "ratelimit.h"
#include "memory.h"
#include "nvs_keys.h"
#include "telegram.h"
#include "cJSON.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>

static const char *TAG = "agent";

// Queues
static QueueHandle_t s_input_queue;
static QueueHandle_t s_channel_output_queue;
static QueueHandle_t s_telegram_output_queue;
static int64_t s_last_start_response_us = 0;
static int64_t s_last_non_command_response_us = 0;
static char s_last_non_command_text[CHANNEL_RX_BUF_SIZE] = {0};
static bool s_messages_paused = false;
static char s_system_prompt_buf[2048];

static agent_persona_t s_persona = AGENT_PERSONA_NEUTRAL;

#ifdef TEST_BUILD
static char s_test_persona_value[16] = {0};
#endif

// Conversation history (rolling message buffer)
static conversation_msg_t s_history[MAX_HISTORY_TURNS * 2];
static int s_history_len = 0;

// Buffers (static to avoid stack overflow)
static char s_response_buf[LLM_RESPONSE_BUF_SIZE];
static char s_tool_result_buf[TOOL_RESULT_BUF_SIZE];

typedef struct {
    int64_t started_us;
    uint64_t llm_us_total;
    uint64_t tool_us_total;
    int llm_calls;
    int tool_calls;
    int rounds;
} request_metrics_t;

static uint64_t elapsed_us_since(int64_t started_us)
{
    int64_t now_us = esp_timer_get_time();
    if (now_us <= started_us) {
        return 0;
    }
    return (uint64_t)(now_us - started_us);
}

static uint32_t us_to_ms_u32(uint64_t duration_us)
{
    uint64_t duration_ms = duration_us / 1000ULL;
    if (duration_ms > UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)duration_ms;
}

static void metrics_log_request(const request_metrics_t *metrics, const char *outcome)
{
    if (!metrics) {
        return;
    }

    ESP_LOGI(TAG,
             "METRIC request outcome=%s total_ms=%" PRIu32 " llm_ms=%" PRIu32
             " tool_ms=%" PRIu32 " rounds=%d llm_calls=%d tool_calls=%d",
             outcome ? outcome : "unknown",
             us_to_ms_u32(elapsed_us_since(metrics->started_us)),
             us_to_ms_u32(metrics->llm_us_total),
             us_to_ms_u32(metrics->tool_us_total),
             metrics->rounds,
             metrics->llm_calls,
             metrics->tool_calls);
}

static void history_rollback_to(int marker, const char *reason)
{
    if (marker < 0 || marker > s_history_len || marker == s_history_len) {
        return;
    }

    ESP_LOGW(TAG, "Rolling back conversation history (%d -> %d): %s",
             s_history_len, marker, reason ? reason : "unknown");
    memset(&s_history[marker], 0, (s_history_len - marker) * sizeof(conversation_msg_t));
    s_history_len = marker;
}

// Add a message to history
static void history_add(const char *role, const char *content,
                        bool is_tool_use, bool is_tool_result,
                        const char *tool_id, const char *tool_name)
{
    // Drop one oldest message when full.
    // Tool interactions can span more than 2 messages, so pair-based trimming is unsafe.
    if (s_history_len >= MAX_HISTORY_TURNS * 2) {
        memmove(&s_history[0], &s_history[1], (MAX_HISTORY_TURNS * 2 - 1) * sizeof(conversation_msg_t));
        s_history_len -= 1;
    }

    conversation_msg_t *msg = &s_history[s_history_len++];
    strncpy(msg->role, role, sizeof(msg->role) - 1);
    msg->role[sizeof(msg->role) - 1] = '\0';
    strncpy(msg->content, content, sizeof(msg->content) - 1);
    msg->content[sizeof(msg->content) - 1] = '\0';
    msg->is_tool_use = is_tool_use;
    msg->is_tool_result = is_tool_result;

    if (tool_id) {
        strncpy(msg->tool_id, tool_id, sizeof(msg->tool_id) - 1);
        msg->tool_id[sizeof(msg->tool_id) - 1] = '\0';
    } else {
        msg->tool_id[0] = '\0';
    }

    if (tool_name) {
        strncpy(msg->tool_name, tool_name, sizeof(msg->tool_name) - 1);
        msg->tool_name[sizeof(msg->tool_name) - 1] = '\0';
    } else {
        msg->tool_name[0] = '\0';
    }
}

static void queue_channel_response(const char *text)
{
    if (!s_channel_output_queue) {
        return;
    }

    channel_output_msg_t msg;
    strncpy(msg.text, text, CHANNEL_TX_BUF_SIZE - 1);
    msg.text[CHANNEL_TX_BUF_SIZE - 1] = '\0';

    if (xQueueSend(s_channel_output_queue, &msg, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to send response to channel queue");
    }
}

static void queue_telegram_response(const char *text, int64_t chat_id)
{
    if (!s_telegram_output_queue) {
        return;
    }

    telegram_msg_t msg;
    strncpy(msg.text, text, TELEGRAM_MAX_MSG_LEN - 1);
    msg.text[TELEGRAM_MAX_MSG_LEN - 1] = '\0';
    msg.chat_id = chat_id;

    if (xQueueSend(s_telegram_output_queue, &msg, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to send response to Telegram queue");
    }
}

static void send_response(const char *text, int64_t chat_id)
{
    queue_channel_response(text);
    queue_telegram_response(text, chat_id);
}

static bool agent_is_valid_role(const char *role)
{
    return role && (strcmp(role, "admin") == 0 || strcmp(role, "user") == 0);
}

#ifndef TEST_BUILD
static bool persona_store_get(char *value, size_t max_len)
{
    return memory_get(NVS_KEY_PERSONA, value, max_len);
}
#else
static bool persona_store_get(char *value, size_t max_len)
{
    if (!value || max_len == 0 || s_test_persona_value[0] == '\0') {
        return false;
    }
    strncpy(value, s_test_persona_value, max_len - 1);
    value[max_len - 1] = '\0';
    return true;
}
#endif

static void load_persona_from_store(void)
{
    char stored[32] = {0};
    agent_persona_t parsed = AGENT_PERSONA_NEUTRAL;

    s_persona = AGENT_PERSONA_NEUTRAL;
    if (!persona_store_get(stored, sizeof(stored))) {
        return;
    }

    for (size_t i = 0; stored[i] != '\0'; i++) {
        stored[i] = (char)tolower((unsigned char)stored[i]);
    }

    if (!agent_parse_persona_name(stored, &parsed)) {
        ESP_LOGW(TAG, "Ignoring invalid stored persona '%s'", stored);
        return;
    }

    s_persona = parsed;
    ESP_LOGI(TAG, "Loaded persona: %s", agent_persona_name(s_persona));
}

static void handle_diag_command(const char *user_message, int64_t chat_id, request_metrics_t *metrics)
{
    char error[120] = {0};
    cJSON *tool_input = cJSON_CreateObject();
    bool ok;
    int64_t started_us;

    if (!tool_input) {
        send_response("Error: diagnostics unavailable (allocation failed)", chat_id);
        metrics_log_request(metrics, "diag_no_mem");
        return;
    }

    if (!agent_parse_diag_command_args(user_message, tool_input, error, sizeof(error))) {
        send_response(error, chat_id);
        cJSON_Delete(tool_input);
        metrics_log_request(metrics, "diag_invalid_args");
        return;
    }

    s_tool_result_buf[0] = '\0';
    started_us = esp_timer_get_time();
    ok = tools_execute("get_diagnostics", tool_input, s_tool_result_buf, sizeof(s_tool_result_buf));
    metrics->tool_us_total += elapsed_us_since(started_us);
    metrics->tool_calls++;
    cJSON_Delete(tool_input);

    if (!ok) {
        if (s_tool_result_buf[0] == '\0') {
            snprintf(s_tool_result_buf, sizeof(s_tool_result_buf), "Error: diagnostics failed");
        }
        send_response(s_tool_result_buf, chat_id);
        metrics_log_request(metrics, "diag_failed");
        return;
    }

    send_response(s_tool_result_buf, chat_id);
    metrics_log_request(metrics, "diag_handled");
}

static void handle_gpio_command(const char *user_message, int64_t chat_id, request_metrics_t *metrics)
{
    char error[120] = {0};
    cJSON *tool_input = cJSON_CreateObject();
    const char *tool_name = NULL;
    bool ok;
    int64_t started_us;

    if (!tool_input) {
        send_response("Error: GPIO read unavailable (allocation failed)", chat_id);
        metrics_log_request(metrics, "gpio_no_mem");
        return;
    }

    if (!agent_parse_gpio_command_args(user_message, &tool_name, tool_input, error, sizeof(error))) {
        send_response(error, chat_id);
        cJSON_Delete(tool_input);
        metrics_log_request(metrics, "gpio_invalid_args");
        return;
    }

    s_tool_result_buf[0] = '\0';
    started_us = esp_timer_get_time();
    ok = tools_execute(tool_name, tool_input, s_tool_result_buf, sizeof(s_tool_result_buf));
    metrics->tool_us_total += elapsed_us_since(started_us);
    metrics->tool_calls++;
    cJSON_Delete(tool_input);

    if (!ok) {
        if (s_tool_result_buf[0] == '\0') {
            snprintf(s_tool_result_buf, sizeof(s_tool_result_buf), "Error: GPIO read failed");
        }
        send_response(s_tool_result_buf, chat_id);
        metrics_log_request(metrics, "gpio_failed");
        return;
    }

    send_response(s_tool_result_buf, chat_id);
    metrics_log_request(metrics, "gpio_handled");
}

static bool is_local_admin_command(const char *user_message)
{
    return agent_is_command(user_message, "gpio") ||
           agent_is_command(user_message, "diag") ||
           local_admin_is_command(user_message);
}

static void handle_local_admin_command(const char *user_message,
                                       message_source_t source,
                                       int64_t chat_id,
                                       request_metrics_t *metrics)
{
    char response[CHANNEL_TX_BUF_SIZE];
    local_admin_action_t action = LOCAL_ADMIN_ACTION_NONE;

    if (source != MSG_SOURCE_CHANNEL) {
        send_response("Error: local admin commands are only available on the USB serial console.", chat_id);
        metrics_log_request(metrics, "local_admin_remote_denied");
        return;
    }

    if (agent_is_command(user_message, "diag")) {
        handle_diag_command(user_message, chat_id, metrics);
        return;
    }

    if (agent_is_command(user_message, "gpio")) {
        handle_gpio_command(user_message, chat_id, metrics);
        return;
    }

    if (!local_admin_handle_command(user_message, response, sizeof(response), &action)) {
        send_response(response, chat_id);
        metrics_log_request(metrics, "local_admin_invalid");
        return;
    }

    send_response(response, chat_id);
    metrics_log_request(metrics, "local_admin_handled");
    local_admin_perform_action(action);
}

static void handle_start_command(int64_t chat_id)
{
    static const char *START_HELP_TEXT =
        "zclaw online.\n\n"
        "Talk to me in normal language. You do not need command syntax.\n\n"
        "Examples:\n"
        "- what are all GPIO states\n"
        "- turn GPIO 5 on\n"
        "- remind me daily at 8:15 to water plants\n"
        "- remember that GPIO 4 controls the arcade machine\n"
        "- create a tool called arcade_on that turns GPIO 4 on\n"
        "- turn the arcade on in 10 minutes\n"
        "- switch to witty persona\n"
        "\n"
        "Chat commands:\n"
        "- /help (show this message)\n"
        "- /settings (show status)\n"
        "- /stop (pause intake)\n"
        "- /resume (resume)\n"
        "- /audit-log (show authentication audit logs, admin only)\n"
        "- /analyse-log (AI analysis of authentication logs, admin only)\n"
        "- /incident-response (AI incident response recommendations, admin only\n)"
        "\n"
        "USB local admin commands:\n"
        "- /gpio [all|pin|pin high|pin low]\n"
        "- /diag [scope] [verbose]\n"
        "- /reboot\n"
        "- /wifi [status|scan]\n"
        "- /bootcount\n"
        "- /factory-reset confirm";
    send_response(START_HELP_TEXT, chat_id);
}

static void handle_settings_command(int64_t chat_id)
{
    char settings_text[600];
    snprintf(settings_text, sizeof(settings_text),
             "zclaw settings:\n"
             "- Message intake: %s\n"
             "- Persona: %s\n"
             "- Chat commands: /start, /help, /settings, /stop, /resume\n"
             "- USB local admin: /gpio, /diag, /reboot, /wifi, /bootcount, /factory-reset\n"
             "- /login <username> <password> to authenticate\n"
             "- /logout to end your session\n"
             "- /user-add <username> <password> <role> to add users (admin only after first user)\n"
             "- /user-list to show configured users\n"
             "- /gpio supports reads and writes (e.g. /gpio 9 low)\n"
             "- Persona changes: ask in normal chat (handled via tool calls)\n"
             "- Device settings are global (e.g., timezone <name>)",
             s_messages_paused ? "paused" : "active",
             agent_persona_name(s_persona));
    send_response(settings_text, chat_id);
}

static void handle_login_command(const char *user_message,
                                 message_source_t source,
                                 int64_t chat_id)
{
    char reason[128] = {0};
    if (!login_can_attempt(source, chat_id, reason, sizeof(reason))) {
        login_audit_log_event("login_blocked", source, chat_id, "unknown", NULL, reason);
        send_response(reason, chat_id);
        return;
    }

    const char *payload = agent_command_payload(user_message, "login");
    char username[LOGIN_USERNAME_MAX_LEN] = {0};
    char password[LOGIN_HASH_BUF_SIZE] = {0};
    int parts = sscanf(payload ? payload : "", "%31s %127s", username, password);
    if (parts != 2) {
        send_response("Usage: /login <username> <password>", chat_id);
        return;
    }

    if (login_authenticate(source, chat_id, username, password)) {
        login_reset_failed_attempts(source, chat_id);
        send_response("Login successful.", chat_id);
    } else {
        login_record_failed_attempt(source, chat_id);
        login_audit_log_event("login_failed", source, chat_id, username, NULL, NULL);
        send_response("Login failed. Check your username and password and try again.", chat_id);
    }
}

static void handle_token_login_command(const char *user_message,
                                       message_source_t source,
                                       int64_t chat_id)
{
    char reason[128] = {0};
    if (!login_can_attempt(source, chat_id, reason, sizeof(reason))) {
        login_audit_log_event("token_login_blocked", source, chat_id, "unknown", NULL, reason);
        send_response(reason, chat_id);
        return;
    }

    const char *payload = agent_command_payload(user_message, "token-login");
    char token[LOGIN_SESSION_TOKEN_MAX_LEN] = {0};
    int parts = sscanf(payload ? payload : "", "%32s", token);
    if (parts != 1 || token[0] == '\0') {
        send_response("Usage: /token-login <token>", chat_id);
        return;
    }

    if (login_authenticate_with_token(source, chat_id, token)) {
        login_reset_failed_attempts(source, chat_id);
        send_response("Token login successful.", chat_id);
    } else {
        login_record_failed_attempt(source, chat_id);
        login_audit_log_event("token_login_failed", source, chat_id, "unknown", NULL, NULL);
        send_response("Token login failed. Provide a valid one-time token.", chat_id);
    }
}

static void handle_logout_command(message_source_t source, int64_t chat_id)
{
    if (!login_is_authenticated(source, chat_id)) {
        send_response("Not logged in.", chat_id);
        return;
    }

    const char *user = login_session_username(source, chat_id);
    login_audit_log_event("logout", source, chat_id, user ? user : "unknown", NULL, NULL);
    login_logout(source, chat_id);
    send_response("Logged out.", chat_id);
}


static void handle_audit_log_command(message_source_t source, int64_t chat_id)
{
    if (!login_is_authenticated(source, chat_id) || !login_is_admin(source, chat_id)) {
        send_response("Admin privileges required.", chat_id);
        return;
    }

    char log_text[2048] = {0};
    if (login_get_audit_log(log_text, sizeof(log_text))) {
        send_response(log_text, chat_id);
    } else {
        send_response("Audit log is empty.", chat_id);
    }
}


static void handle_analyse_log_command(message_source_t source, int64_t chat_id)
{
    if (!login_is_authenticated(source, chat_id) ||
        !login_is_admin(source, chat_id)) {

        send_response("Admin privileges required.", chat_id);
        return;
    }

    /* Allocate large buffers on heap instead of the agent task stack */
    char *audit_logs = calloc(1, 2048);
    char *prompt = calloc(1, 4096);
    char *response = calloc(1, LLM_RESPONSE_BUF_SIZE);
    char *analysis = calloc(1, LLM_RESPONSE_BUF_SIZE);

    if (!audit_logs || !prompt || !response || !analysis) {
        ESP_LOGE(TAG, "Failed to allocate memory for AI analysis");

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Insufficient memory for AI analysis.",
            chat_id
        );

        return;
    }

    /* Get authentication audit logs */
    if (!login_get_audit_log(audit_logs, 2048)) {

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Audit log is empty.",
            chat_id
        );

        return;
    }

    /* Build the analysis prompt */
    snprintf(
        prompt,
        4096,
        "Analyse these authentication logs.\n\n"
        "Return no more than 2 short bullet points per section.\n"
        "Only report evidence visible in the logs.\n"
        "Do not claim an attack is confirmed unless there is clear evidence.\n\n"
        "Look specifically for repeated authentication failures, "
        "patterns involving the same actor, failures followed by "
        "successful logins, and activity involving privileged accounts.\n\n"
        "Do not assume an attack from a single failed login.\n"
        "Classify repeated suspicious behaviour as a potential threat "
        "even when an attack cannot be confirmed.\n\n"
        "Use exactly these four sections:\n"
        "Threat Level:\n"
        "Security Findings:\n"
        "Possible Attack Type:\n"
        "Recommendations:\n\n"
        "Use LOW If there is no confirmed malicious activity.\n"
        "Use MEDIUM or HIGH only when supported by the evidence.\n"
        "Logs:\n%s",
        audit_logs
    );

    /*
     * Convert the prompt into the JSON format expected
     * by the configured LLM backend.
     */
    char *request_json = json_build_request(
        "You are a cybersecurity log analyst. "
        "Analyse ONLY the evidence present in the provided authentication logs. "
        "Do not invent IP addresses, users, attacks, or events. "

        "Identify suspicious authentication patterns such as: "
        "- repeated failed logins by the same actor"
        "- multiple failed logins in a short sequence"
        "- failed logins followed by a successful login"
        "- repeated failures targetting an admin account"
        "- unexpected login activity involving unknown usernames"
        "- repeated login attempts involving the same username"

        "Do not assume an attack occurred unless the logs support it. "
        "Distinguish confirmed activity from potential threats. "
        "If evidence is insufficient, say so. "
        "You MUST provide all four sections below. "
        "Threat Level must be LOW, MEDIUM, or HIGH. "
        "Use threat level LOW for normal activity or isolated failed login."
        "Use threat level MEDIUM for suspicious patterns such as repeated failed logins or possible credential guessing."
        "Use threat level HIGH for strong evidence of compromise, such as repeated failures followed by an unexpected successful login."
        "Keep the response concise.\n\n"
        "Required format:\n"
        "Threat Level: LOW/MEDIUM/HIGH\n"
        "Security Findings:\n"
        "- ...\n"
        "Possible Attack Type:\n"
        "- ...\n"
        "Recommendations:\n"
        "- ...\n"
        "For normal failed login attempts, do not automatically classify them as an attack. "
        "If multiple failed logins are followed by a successful login, describe it as "
        "a potential brute-force or credential-guessing indicator, not a confirmed attack.",
        NULL,
        0,
        prompt,
        NULL,
        0
    );

    if (!request_json) {
        ESP_LOGE(TAG, "Failed to build analyse_log request");

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Failed to prepare AI analysis request.",
            chat_id
        );

        return;
    }

    ESP_LOGI(TAG, "Sending analyse_log request to LLM");

    esp_err_t err = llm_request(
        request_json,
        response,
        LLM_RESPONSE_BUF_SIZE
    );

    free(request_json);

    if (err != ESP_OK) {

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Failed to contact AI analysis service.",
            chat_id
        );

        return;
    }

    /*
     * Parse the JSON response returned by the LLM.
     */
    char tool_name[64] = {0};
    char tool_id[64] = {0};
    cJSON *tool_input = NULL;

    if (!json_parse_response(
            response,
            analysis,
            LLM_RESPONSE_BUF_SIZE,
            tool_name,
            sizeof(tool_name),
            tool_id,
            sizeof(tool_id),
            &tool_input)) {

        ESP_LOGE(TAG, "Failed to parse AI analysis response");

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Failed to parse AI analysis response.",
            chat_id
        );

        return;
    }

    /* Send the actual AI analysis to Telegram */
    send_response(analysis, chat_id);

    /* Clean up heap memory */
    free(audit_logs);
    free(prompt);
    free(response);
    free(analysis);
}


static void handle_incident_response_command(message_source_t source, int64_t chat_id)
{
    if (!login_is_authenticated(source, chat_id) ||
        !login_is_admin(source, chat_id)) {

        send_response("Admin privileges required.", chat_id);
        return;
    }

    char *audit_logs = calloc(1, 2048);
    char *prompt = calloc(1, 4096);
    char *response = calloc(1, LLM_RESPONSE_BUF_SIZE);
    char *analysis = calloc(1, LLM_RESPONSE_BUF_SIZE);

    if (!audit_logs || !prompt || !response || !analysis) {
        ESP_LOGE(TAG, "Failed to allocate memory for incident response");

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Insufficient memory for incident response.",
            chat_id
        );

        return;
    }

    /* Get authentication audit logs */
    if (!login_get_audit_log(audit_logs, 2048)) {

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Audit log is empty.",
            chat_id
        );

        return;
    }

    /* Build incident response prompt */
    snprintf(
        prompt,
        4096,
        "Review these authentication audit logs for a possible security incident.\n\n"
        "Interpret each login event exactly as recorded.\n"
        "FAILED means authentication was unsuccessful.\n"
        "SUCCESS means authentication was successful.\n"
        "Do not connect a successful login to a failed login unless the logs "
        "provide evidence that they are related.\n\n"
        "Determine:\n"
        "1. Threat Level: LOW, MEDIUM, or HIGH\n"
        "2. Incident Summary\n"
        "3. Evidence\n"
        "4. Recommended Response\n\n"
        "Only use evidence present in the logs.\n"
        "Do not invent attacks, users, IP addresses, or events.\n"
        "Do not classify normal failed logins as confirmed attacks.\n"
        "Distinguish suspicious activity from confirmed malicious activity.\n"
        "Keep the response concise.\n\n"
        "Audit Logs:\n%s",
        audit_logs
    );

    char *request_json = json_build_request(
        "You are an incident response assistant for an ESP32 authentication system. "
        "Analyse ONLY the supplied authentication audit logs. "
        "Carefully distinguish successful and failed authentication attempts. "
        "Never describe a failed login as successful. "
        "Never claim a user authenticated unless the logs explicitly show login_success. "
        "Do not invent IP addresses, users, events, or attack evidence. "
        "Do not assume that a failed login is malicious. "
        "Multiple failed logins for the same username may indicate possible "
        "credential guessing or brute-force activity, but this is not confirmed "
        "without additional evidence. "
        "If a different user successfully logs in after failed attempts against "
        "another account, do not treat that successful login as evidence that "
        "the failed-login user gained access. "
        "Use LOW for normal or inconclusive activity, MEDIUM for suspicious "
        "patterns, and HIGH only when the logs provide strong evidence of "
        "serious unauthorized activity. "

        "Keep the response concise.\n\n"
        "Required format:\n"
        "Threat Level: LOW/MEDIUM/HIGH\n"
        "Incident Summary:\n"
        "- ...\n"
        "Evidence:\n"
        "- ...\n"
        "Recommended Response:\n"
        "- ...",
        NULL,
        0,
        prompt,
        NULL,
        0
    );

    if (!request_json) {
        ESP_LOGE(TAG, "Failed to build incident response request");

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Failed to prepare incident response request.",
            chat_id
        );

        return;
    }

    ESP_LOGI(TAG, "Sending incident response request to LLM");

    esp_err_t err = llm_request(
        request_json,
        response,
        LLM_RESPONSE_BUF_SIZE
    );

    free(request_json);

    if (err != ESP_OK) {

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Failed to contact AI incident response service.",
            chat_id
        );

        return;
    }

    char tool_name[64] = {0};
    char tool_id[64] = {0};
    cJSON *tool_input = NULL;

    if (!json_parse_response(
            response,
            analysis,
            LLM_RESPONSE_BUF_SIZE,
            tool_name,
            sizeof(tool_name),
            tool_id,
            sizeof(tool_id),
            &tool_input)) {

        ESP_LOGE(TAG, "Failed to parse incident response");

        free(audit_logs);
        free(prompt);
        free(response);
        free(analysis);

        send_response(
            "Failed to parse AI incident response.",
            chat_id
        );

        return;
    }

    send_response(analysis, chat_id);

    free(audit_logs);
    free(prompt);
    free(response);
    free(analysis);
}


static void handle_set_login_command(const char *user_message,
                                     message_source_t source,
                                     int64_t chat_id)
{
    if (source != MSG_SOURCE_CHANNEL) {
        send_response("Error: /set-login is only available on the USB serial console.", chat_id);
        return;
    }

    send_response("The /set-login command is deprecated. Use /user-add <username> <password> <role> to create users.", chat_id);
}

static void handle_user_management_command(const char *user_message,
                                           message_source_t source,
                                           int64_t chat_id)
{
    if (!login_user_has_any() && source == MSG_SOURCE_CHANNEL && agent_is_command(user_message, "user-add")) {
        const char *payload = agent_command_payload(user_message, "user-add");
        char username[LOGIN_USERNAME_MAX_LEN];
        char password[LOGIN_HASH_BUF_SIZE];
        char role[LOGIN_ROLE_MAX_LEN];
        int parts = sscanf(payload ? payload : "", "%31s %127s %15s", username, password, role);
        if (parts < 3 || !agent_is_valid_role(role)) {
            send_response("Usage: /user-add <username> <password> <role>\nExample: /user-add admin Pa55word admin", chat_id);
            return;
        }
        char policy_reason[256];
        if (!login_password_policy_reason(password, policy_reason, sizeof(policy_reason))) {
            send_response(policy_reason, chat_id);
            return;
        }
        esp_err_t err = login_user_add(username, password, role);
        if (err == ESP_OK) {
            login_audit_log_event("user_add", source, chat_id, username, username, role);
            send_response("User added successfully.", chat_id);
        } else if (err == ESP_ERR_INVALID_STATE) {
            send_response("Error: user already exists.", chat_id);
        } else {
            send_response("Error: could not add user.", chat_id);
        }
        return;
    }

    if (!login_is_authenticated(source, chat_id) || !login_is_admin(source, chat_id)) {
        send_response("Admin privileges required.", chat_id);
        return;
    }

    if (agent_is_command(user_message, "user-add")) {
        const char *payload = agent_command_payload(user_message, "user-add");
        char username[LOGIN_USERNAME_MAX_LEN];
        char password[LOGIN_HASH_BUF_SIZE];
        char role[LOGIN_ROLE_MAX_LEN];
        int parts = sscanf(payload ? payload : "", "%31s %127s %15s", username, password, role);
        if (parts < 3 || !agent_is_valid_role(role)) {
            send_response("Usage: /user-add <username> <password> <role>\nExample: /user-add alice Pa55word user", chat_id);
            return;
        }
        char policy_reason[256];
        if (!login_password_policy_reason(password, policy_reason, sizeof(policy_reason))) {
            send_response(policy_reason, chat_id);
            return;
        }
        esp_err_t err = login_user_add(username, password, role);
        if (err == ESP_OK) {
            login_audit_log_event("user_add", source, chat_id, login_session_username(source, chat_id), username, role);
            send_response("User added successfully.", chat_id);
        } else if (err == ESP_ERR_INVALID_STATE) {
            send_response("Error: user already exists.", chat_id);
        } else {
            send_response("Error: could not add user.", chat_id);
        }
        return;
    }

    if (agent_is_command(user_message, "user-update")) {
        const char *payload = agent_command_payload(user_message, "user-update");
        char username[LOGIN_USERNAME_MAX_LEN];
        char password[LOGIN_HASH_BUF_SIZE] = {0};
        char role[LOGIN_ROLE_MAX_LEN] = {0};
        int parts = sscanf(payload ? payload : "", "%31s %127s %15s", username, password, role);
        if (parts < 1) {
            send_response("Usage: /user-update <username> [password] [role]", chat_id);
            return;
        }
        const char *password_arg = parts >= 2 ? password : NULL;
        const char *role_arg = parts == 3 ? role : NULL;
        char policy_reason[256];
        if (password_arg && password_arg[0] != '\0' &&
            !login_password_policy_reason(password_arg, policy_reason, sizeof(policy_reason))) {
            send_response(policy_reason, chat_id);
            return;
        }
        esp_err_t err = login_user_update(username, password_arg && password_arg[0] ? password_arg : NULL,
                                         role_arg && role_arg[0] ? role_arg : NULL);
        if (err == ESP_OK) {
            login_audit_log_event("user_update", source, chat_id, login_session_username(source, chat_id), username,
                                 role_arg ? role_arg : "");
            send_response("User updated successfully.", chat_id);
        } else if (err == ESP_ERR_NOT_FOUND) {
            send_response("Error: user not found.", chat_id);
        } else {
            send_response("Error: could not update user.", chat_id);
        }
        return;
    }

    if (agent_is_command(user_message, "user-delete")) {
        const char *payload = agent_command_payload(user_message, "user-delete");
        char username[LOGIN_USERNAME_MAX_LEN];
        int parts = sscanf(payload ? payload : "", "%31s", username);
        if (parts != 1) {
            send_response("Usage: /user-delete <username>", chat_id);
            return;
        }
        esp_err_t err = login_user_delete(username);
        if (err == ESP_OK) {
            login_audit_log_event("user_delete", source, chat_id, login_session_username(source, chat_id), username, NULL);
            send_response("User deleted successfully.", chat_id);
        } else if (err == ESP_ERR_NOT_FOUND) {
            send_response("Error: user not found.", chat_id);
        } else {
            send_response("Error: could not delete user.", chat_id);
        }
        return;
    }

    if (agent_is_command(user_message, "user-list")) {
        char list[512] = {0};
        if (login_user_list(list, sizeof(list))) {
            login_audit_log_event("user_list", source, chat_id, login_session_username(source, chat_id), NULL, NULL);
            send_response(list, chat_id);
        } else {
            send_response("No users configured.", chat_id);
        }
        return;
    }

    send_response("Unknown user management command.", chat_id);
}

static int64_t response_chat_id_for_source(message_source_t source, int64_t chat_id)
{
    if (source == MSG_SOURCE_TELEGRAM && chat_id != 0) {
        return chat_id;
    }
    return 0;
}

// Process a single user message
static void process_message(const char *user_message, message_source_t source, int64_t reply_chat_id)
{
    ESP_LOGI(TAG, "Processing: %s", user_message);
    int history_turn_start = s_history_len;
    bool is_non_command_message = !agent_is_slash_command(user_message);
    bool is_cron_trigger = agent_is_cron_trigger_message(user_message);
    bool telegram_polling_paused = false;
    request_metrics_t metrics = {
        .started_us = esp_timer_get_time(),
        .llm_us_total = 0,
        .tool_us_total = 0,
        .llm_calls = 0,
        .tool_calls = 0,
        .rounds = 0,
    };

    if (agent_is_command(user_message, "resume")) {
        if (!s_messages_paused) {
            send_response("zclaw is already active.", reply_chat_id);
            metrics_log_request(&metrics, "resume_noop");
            return;
        }
        s_messages_paused = false;
        send_response("zclaw resumed. Send /start for command help.", reply_chat_id);
        metrics_log_request(&metrics, "resumed");
        return;
    }

    if (agent_is_command(user_message, "settings")) {
        handle_settings_command(reply_chat_id);
        metrics_log_request(&metrics, "settings_handled");
        return;
    }

    if (agent_is_command(user_message, "login")) {
        handle_login_command(user_message, source, reply_chat_id);
        metrics_log_request(&metrics, "login_handled");
        return;
    }

    if (agent_is_command(user_message, "token-login")) {
        handle_token_login_command(user_message, source, reply_chat_id);
        metrics_log_request(&metrics, "token_login_handled");
        return;
    }

    if (agent_is_command(user_message, "logout")) {
        handle_logout_command(source, reply_chat_id);
        metrics_log_request(&metrics, "logout_handled");
        return;
    }

    if (agent_is_command(user_message, "audit-log")) {
        handle_audit_log_command(source, reply_chat_id);
        metrics_log_request(&metrics, "audit_log_handled");
        return;
    }

    if (agent_is_command(user_message, "analyse-log")) {
        handle_analyse_log_command(source, reply_chat_id);
        metrics_log_request(&metrics, "analyse_log_handled");
        return;
    }

    if (agent_is_command(user_message, "incident-response")) {
        handle_incident_response_command(source, reply_chat_id);
        metrics_log_request(&metrics, "incident_response_handled");
        return;
    }

    if (agent_is_command(user_message, "set-login")) {
        handle_set_login_command(user_message, source, reply_chat_id);
        metrics_log_request(&metrics, "set_login_handled");
        return;
    }

    if (agent_is_command(user_message, "user-add") ||
        agent_is_command(user_message, "user-update") ||
        agent_is_command(user_message, "user-delete") ||
        agent_is_command(user_message, "user-list")) {
        handle_user_management_command(user_message, source, reply_chat_id);
        metrics_log_request(&metrics, "user_management_handled");
        return;
    }

    if (!login_is_authenticated(source, reply_chat_id)) {
        send_response("Please login first with /login <username> <password>.", reply_chat_id);
        metrics_log_request(&metrics, "login_required");
        return;
    }

    if (is_local_admin_command(user_message)) {
        handle_local_admin_command(user_message, source, reply_chat_id, &metrics);
        return;
    }

    if (s_messages_paused) {
        ESP_LOGD(TAG, "Paused mode: ignoring message");
        metrics_log_request(&metrics, "paused_drop");
        return;
    }

    if (agent_is_command(user_message, "help")) {
        handle_start_command(reply_chat_id);
        metrics_log_request(&metrics, "help_handled");
        return;
    }

    if (agent_is_command(user_message, "stop")) {
        s_messages_paused = true;
        send_response("zclaw paused. I will ignore new messages until /resume.", reply_chat_id);
        metrics_log_request(&metrics, "paused");
        return;
    }

    if (agent_is_command(user_message, "start")) {
        int64_t now_us = esp_timer_get_time();
        uint32_t since_last_start_ms = 0;
        if (s_last_start_response_us > 0 && now_us > s_last_start_response_us) {
            since_last_start_ms = (uint32_t)((now_us - s_last_start_response_us) / 1000ULL);
        }

        if (s_last_start_response_us > 0 && since_last_start_ms < START_COMMAND_COOLDOWN_MS) {
            ESP_LOGW(TAG, "Suppressing repeated /start (%" PRIu32 "ms since last response)",
                     since_last_start_ms);
            metrics_log_request(&metrics, "start_suppressed");
            return;
        }

        s_last_start_response_us = now_us;
        handle_start_command(reply_chat_id);
        metrics_log_request(&metrics, "start_handled");
        return;
    }

    if (is_non_command_message) {
        int64_t now_us = esp_timer_get_time();
        uint32_t since_last_ms = 0;

        if (s_last_non_command_response_us > 0 && now_us > s_last_non_command_response_us) {
            since_last_ms = (uint32_t)((now_us - s_last_non_command_response_us) / 1000ULL);
        }

        if (s_last_non_command_text[0] != '\0' &&
            strcmp(user_message, s_last_non_command_text) == 0 &&
            s_last_non_command_response_us > 0 &&
            since_last_ms < MESSAGE_REPLAY_COOLDOWN_MS) {
            ESP_LOGW(TAG, "Suppressing repeated message replay (%" PRIu32 "ms since last response)",
                     since_last_ms);
            metrics_log_request(&metrics, "replay_suppressed");
            return;
        }
    }

    // Get tools
    int tool_count;
    const tool_def_t *tools = tools_get_all(&tool_count);

    telegram_pause_polling();
    telegram_polling_paused = true;

    // Add user message to history
    history_add("user", user_message, false, false, NULL, NULL);

    int rounds = 0;
    bool done = false;

    while (!done && rounds < MAX_TOOL_ROUNDS) {
        rounds++;
        metrics.rounds = rounds;

        // Build request JSON (user message already in history)
        char *request = json_build_request(
            agent_build_system_prompt(s_persona, s_system_prompt_buf, sizeof(s_system_prompt_buf)),
            s_history,
            s_history_len,
            NULL,  // User message already in history
            tools,
            tool_count
        );

        if (!request) {
            ESP_LOGE(TAG, "Failed to build request JSON");
            history_rollback_to(history_turn_start, "request build failed");
            send_response("Error: Failed to build request", reply_chat_id);
            telegram_resume_polling();
            telegram_polling_paused = false;
            metrics_log_request(&metrics, "request_build_error");
            return;
        }

        ESP_LOGI(TAG, "Request: %d bytes", (int)strlen(request));

        // Check rate limit before making request
        char rate_reason[128];
        if (!ratelimit_check(rate_reason, sizeof(rate_reason))) {
            free(request);
            history_rollback_to(history_turn_start, "rate limited");
            send_response(rate_reason, reply_chat_id);
            telegram_resume_polling();
            telegram_polling_paused = false;
            metrics_log_request(&metrics, "rate_limited");
            return;
        }

        // Send to LLM with retry
        esp_err_t err = ESP_FAIL;
        int retry_delay_ms = LLM_RETRY_BASE_MS;
        int64_t retry_window_started_us = esp_timer_get_time();

        for (int retry = 0; retry < LLM_MAX_RETRIES; retry++) {
            uint32_t retry_elapsed_ms = us_to_ms_u32(elapsed_us_since(retry_window_started_us));
            if (retry > 0 && retry_elapsed_ms >= LLM_RETRY_BUDGET_MS) {
                ESP_LOGW(TAG,
                         "LLM retry budget exhausted before attempt %d/%d (%" PRIu32 "ms/%dms)",
                         retry + 1, LLM_MAX_RETRIES, retry_elapsed_ms, LLM_RETRY_BUDGET_MS);
                break;
            }

            int64_t llm_started_us = esp_timer_get_time();
            err = llm_request(request, s_response_buf, sizeof(s_response_buf));
            metrics.llm_us_total += elapsed_us_since(llm_started_us);
            metrics.llm_calls++;
            if (err == ESP_OK) {
                break;
            }

            if (retry == LLM_MAX_RETRIES - 1) {
                break;
            }

            retry_elapsed_ms = us_to_ms_u32(elapsed_us_since(retry_window_started_us));
            if (retry_elapsed_ms >= LLM_RETRY_BUDGET_MS) {
                ESP_LOGW(TAG,
                         "LLM retry budget exhausted after attempt %d/%d (%" PRIu32 "ms/%dms)",
                         retry + 1, LLM_MAX_RETRIES, retry_elapsed_ms, LLM_RETRY_BUDGET_MS);
                break;
            }

            uint32_t remaining_budget_ms = (uint32_t)(LLM_RETRY_BUDGET_MS - retry_elapsed_ms);
            int delay_ms = retry_delay_ms;
            if ((uint32_t)delay_ms > remaining_budget_ms) {
                delay_ms = (int)remaining_budget_ms;
            }

            if (delay_ms <= 0) {
                ESP_LOGW(TAG,
                         "LLM retry budget left no delay before next attempt (%" PRIu32 "ms/%dms)",
                         retry_elapsed_ms, LLM_RETRY_BUDGET_MS);
                break;
            }

            ESP_LOGW(TAG,
                     "LLM request failed (attempt %d/%d), retrying in %dms (budget %" PRIu32 "/%dms)",
                     retry + 1, LLM_MAX_RETRIES, delay_ms, retry_elapsed_ms, LLM_RETRY_BUDGET_MS);
            vTaskDelay(pdMS_TO_TICKS(delay_ms));

            // Exponential backoff
            retry_delay_ms *= 2;
            if (retry_delay_ms > LLM_RETRY_MAX_MS) {
                retry_delay_ms = LLM_RETRY_MAX_MS;
            }
        }

        free(request);

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "LLM request failed after %d retries", LLM_MAX_RETRIES);
            history_rollback_to(history_turn_start, "llm request failed");
            send_response("Error: Failed to contact LLM API after retries", reply_chat_id);
            telegram_resume_polling();
            telegram_polling_paused = false;
            metrics_log_request(&metrics, "llm_error");
            return;
        }

        // Record successful request for rate limiting
        ratelimit_record_request();

        // Parse response
        char text_out[MAX_MESSAGE_LEN] = {0};
        char tool_name[32] = {0};
        char tool_id[64] = {0};
        cJSON *tool_input = NULL;

        if (!json_parse_response(s_response_buf, text_out, sizeof(text_out),
                                  tool_name, sizeof(tool_name),
                                  tool_id, sizeof(tool_id),
                                  &tool_input)) {
            ESP_LOGE(TAG, "Failed to parse response");
            history_rollback_to(history_turn_start, "llm response parse failed");
            send_response("Error: Failed to parse LLM response", reply_chat_id);
            json_free_parsed_response();
            telegram_resume_polling();
            telegram_polling_paused = false;
            metrics_log_request(&metrics, "parse_error");
            return;
        }

        // Check if it's a tool use
        if (tool_name[0] != '\0' && tool_input) {
            ESP_LOGI(TAG, "Tool call: %s (round %d)", tool_name, rounds);

            // Store the tool_input as JSON string for history
            char *input_str = cJSON_PrintUnformatted(tool_input);

            // Add tool_use to history
            history_add("assistant", input_str ? input_str : "{}",
                        true, false, tool_id, tool_name);
            free(input_str);

            // Check if it's a user-defined tool
            const user_tool_t *user_tool = user_tools_find(tool_name);
            metrics.tool_calls++;
            if (user_tool) {
                // User tool: return the action as "instruction" for Claude to execute
                snprintf(s_tool_result_buf, sizeof(s_tool_result_buf),
                         "Execute this action now: %s", user_tool->action);
                ESP_LOGI(TAG, "User tool '%s' action: %s", tool_name, user_tool->action);
            } else if (is_cron_trigger && strcmp(tool_name, "cron_set") == 0) {
                snprintf(s_tool_result_buf, sizeof(s_tool_result_buf),
                         "Error: cron_set is not allowed during scheduled task execution. "
                         "Execute the scheduled action now instead of creating a new schedule.");
                ESP_LOGW(TAG, "Blocked cron_set during cron-triggered turn");
            } else {
                // Built-in tool: execute directly
                int64_t tool_started_us = esp_timer_get_time();
                bool tool_ok = tools_execute(tool_name, tool_input,
                                             s_tool_result_buf, sizeof(s_tool_result_buf));
                metrics.tool_us_total += elapsed_us_since(tool_started_us);

                // Keep runtime persona state aligned when persona tools run via LLM.
                if (tool_ok && strcmp(tool_name, "set_persona") == 0) {
                    cJSON *persona_json = cJSON_GetObjectItem(tool_input, "persona");
                    agent_persona_t parsed_persona = AGENT_PERSONA_NEUTRAL;
                    if (persona_json && cJSON_IsString(persona_json) &&
                        agent_parse_persona_name(persona_json->valuestring, &parsed_persona)) {
                        s_persona = parsed_persona;
                    }
                } else if (tool_ok && strcmp(tool_name, "reset_persona") == 0) {
                    s_persona = AGENT_PERSONA_NEUTRAL;
                }

                ESP_LOGI(TAG, "Tool result: %s", s_tool_result_buf);
            }

            // Add tool_result to history
            history_add("user", s_tool_result_buf, false, true, tool_id, NULL);

            json_free_parsed_response();
            // Continue loop to let Claude see the result
        } else {
            // Text response - we're done
            if (text_out[0] != '\0') {
                history_add("assistant", text_out, false, false, NULL, NULL);
                send_response(text_out, reply_chat_id);
            } else {
                history_add("assistant", "(No response from Claude)", false, false, NULL, NULL);
                send_response("(No response from Claude)", reply_chat_id);
            }
            json_free_parsed_response();
            done = true;
        }
    }

    if (!done) {
        ESP_LOGW(TAG, "Max tool rounds reached");
        history_add("assistant", "(Reached max tool iterations)", false, false, NULL, NULL);
        send_response("(Reached max tool iterations)", reply_chat_id);
        telegram_resume_polling();
        telegram_polling_paused = false;
        metrics_log_request(&metrics, "max_rounds");
        return;
    }

    if (is_non_command_message) {
        strncpy(s_last_non_command_text, user_message, sizeof(s_last_non_command_text) - 1);
        s_last_non_command_text[sizeof(s_last_non_command_text) - 1] = '\0';
        s_last_non_command_response_us = esp_timer_get_time();
    }

    if (telegram_polling_paused) {
        telegram_resume_polling();
    }

    metrics_log_request(&metrics, "success");
}

#ifdef TEST_BUILD
void agent_test_reset(void)
{
    memset(s_history, 0, sizeof(s_history));
    s_history_len = 0;
    memset(s_response_buf, 0, sizeof(s_response_buf));
    memset(s_tool_result_buf, 0, sizeof(s_tool_result_buf));
    s_channel_output_queue = NULL;
    s_telegram_output_queue = NULL;
    s_last_start_response_us = 0;
    s_last_non_command_response_us = 0;
    memset(s_last_non_command_text, 0, sizeof(s_last_non_command_text));
    s_messages_paused = false;
    memset(s_test_persona_value, 0, sizeof(s_test_persona_value));
    local_admin_test_reset();
    load_persona_from_store();
}

void agent_test_set_queues(QueueHandle_t channel_output_queue,
                           QueueHandle_t telegram_output_queue)
{
    s_channel_output_queue = channel_output_queue;
    s_telegram_output_queue = telegram_output_queue;
}

void agent_test_process_message(const char *user_message)
{
    process_message(user_message, MSG_SOURCE_CHANNEL, 0);
}

void agent_test_process_message_for_chat(const char *user_message, int64_t reply_chat_id)
{
    process_message(user_message, MSG_SOURCE_TELEGRAM, reply_chat_id);
}
#endif

// Agent task
static void agent_task(void *arg)
{
    (void)arg;
    channel_msg_t msg;

    ESP_LOGI(TAG, "Agent task started");

    while (1) {
        if (xQueueReceive(s_input_queue, &msg, portMAX_DELAY) == pdTRUE) {
            process_message(msg.text, msg.source, response_chat_id_for_source(msg.source, msg.chat_id));
        }
    }
}

esp_err_t agent_start(QueueHandle_t input_queue,
                      QueueHandle_t channel_output_queue,
                      QueueHandle_t telegram_output_queue)
{
    if (!input_queue || !channel_output_queue) {
        ESP_LOGE(TAG, "Invalid queues for agent startup");
        return ESP_ERR_INVALID_ARG;
    }

    s_input_queue = input_queue;
    s_channel_output_queue = channel_output_queue;
    s_telegram_output_queue = telegram_output_queue;
    load_persona_from_store();

    if (xTaskCreate(agent_task, "agent", AGENT_TASK_STACK_SIZE, NULL,
                    AGENT_TASK_PRIORITY, NULL) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create agent task");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Agent started");
    return ESP_OK;
}
