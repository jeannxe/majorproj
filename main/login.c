#include "login.h"
#include "memory.h"
#include "nvs_keys.h"
#include "security.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_system.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#define LOGIN_USER_LIST_KEY       "lg_usr_ls_"
#define LOGIN_USER_KEY_PREFIX     "lg_usr_"
#define LOGIN_USER_ROLE_SUFFIX    "role"
#define LOGIN_MAX_AUTH_SESSIONS   4
#define LOGIN_MAX_FAILED_ATTEMPTS 5
#define LOGIN_BLOCK_SECONDS       20
#define LOGIN_HASH_BUF_SIZE       128
#define LOGIN_USERNAME_MAX_LEN    32
#define LOGIN_ROLE_MAX_LEN        16
#define LOGIN_AUDIT_LOG_MAX_ENTRIES 16

#define LOGIN_DEFAULT_ADMIN_USERNAME "admin"
#define LOGIN_DEFAULT_ADMIN_PASSWORD "Admin1234!Secure"
#define LOGIN_DEFAULT_ADMIN_ROLE     "admin"
#define LOGIN_AUDIT_ENTRY_MAX_LEN 192

#define LOGIN_AUDIT_NVS_START_KEY      "la_start"
#define LOGIN_AUDIT_NVS_COUNT_KEY      "la_count"
#define LOGIN_AUDIT_NVS_TIMESTAMP_PREFIX "la_tim_"
#define LOGIN_AUDIT_NVS_TEXT_PREFIX      "la_txt_"

#define LOGIN_FAILED_CHANNEL_ATTEMPTS_KEY "lf_ch_at"
#define LOGIN_FAILED_CHANNEL_BLOCKED_KEY  "lf_ch_bl"
#define LOGIN_FAILED_TELEGRAM_ID_PREFIX   "lf_tg_id_"
#define LOGIN_FAILED_TELEGRAM_ATT_PREFIX  "lf_tg_at_"
#define LOGIN_FAILED_TELEGRAM_BL_PREFIX   "lf_tg_bl_"

static struct {
    int64_t chat_id;
    char username[LOGIN_USERNAME_MAX_LEN];
    login_role_t role;
} s_authenticated_telegram[LOGIN_MAX_AUTH_SESSIONS];
static char s_authenticated_channel_username[LOGIN_USERNAME_MAX_LEN];
static login_role_t s_authenticated_channel_role = LOGIN_ROLE_NONE;

static struct {
    int64_t timestamp_us;
    message_source_t source;
    int64_t chat_id;
    char text[LOGIN_AUDIT_ENTRY_MAX_LEN];
} s_audit_log[LOGIN_AUDIT_LOG_MAX_ENTRIES];
static int s_audit_log_start = 0;
static int s_audit_log_count = 0;

static struct {
    int64_t chat_id;
    int failed_attempts;
    int64_t blocked_until_us;
} s_failed_telegram[LOGIN_MAX_AUTH_SESSIONS];
static int s_failed_channel_attempts = 0;
static int64_t s_failed_channel_blocked_until_us = 0;

static const char *TAG = "login";

static struct {
    char token[LOGIN_SESSION_TOKEN_MAX_LEN];
    char username[LOGIN_USERNAME_MAX_LEN];
    login_role_t role;
    int64_t expires_at_us;
} s_session_tokens[LOGIN_MAX_AUTH_SESSIONS];

static bool login_save_int64_to_nvs(const char *key, int64_t value);
static bool login_save_int_to_nvs(const char *key, int value);
static bool login_load_int64_from_nvs(const char *key, int64_t *out_value);
static bool login_load_int_from_nvs(const char *key, int *out_value);
static bool login_build_nvs_key(char *buf, size_t buf_size, const char *prefix, int index);
static bool login_password_matches(const char *username, const char *password);
static login_role_t login_role_from_string(const char *role);
static bool login_generate_token(char *token, size_t token_len);
static void login_clear_expired_tokens(void);
static int login_find_token_index(const char *token);
static void login_clear_token(int index);
static int64_t login_now_us(void);
static void login_boostrap_default_admin(void);
static void login_audit_add_entry(message_source_t source,
                                  int64_t chat_id,
                                  const char *event,
                                  const char *actor,
                                  const char *target,
                                  const char *role,
                                  const char *details);

static bool login_is_valid_username(const char *username)
{
    if (!username || username[0] == '\0' || strlen(username) >= LOGIN_USERNAME_MAX_LEN) {
        return false;
    }
    for (size_t i = 0; username[i] != '\0'; i++) {
        char c = username[i];
        if (!(c == '_' || c == '-' || c == '.' || (c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
            return false;
        }
    }
    return true;
}

static bool login_is_valid_role(const char *role)
{
    if (!role) {
        return false;
    }
    return strcmp(role, "admin") == 0 || strcmp(role, "user") == 0;
}

static bool login_save_int64_to_nvs(const char *key, int64_t value)
{
    char buf[32];
    int written = snprintf(buf, sizeof(buf), "%lld", (long long)value);
    if (written < 0 || (size_t)written >= sizeof(buf)) {
        return false;
    }
    return memory_set(key, buf) == ESP_OK;
}

static bool login_save_int_to_nvs(const char *key, int value)
{
    char buf[16];
    int written = snprintf(buf, sizeof(buf), "%d", value);
    if (written < 0 || (size_t)written >= sizeof(buf)) {
        return false;
    }
    return memory_set(key, buf) == ESP_OK;
}

static bool login_load_int64_from_nvs(const char *key, int64_t *out_value)
{
    char buf[32] = {0};
    if (!memory_get(key, buf, sizeof(buf))) {
        return false;
    }
    char *endptr = NULL;
    long long parsed = strtoll(buf, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }
    *out_value = (int64_t)parsed;
    return true;
}

static bool login_load_int_from_nvs(const char *key, int *out_value)
{
    char buf[16] = {0};
    if (!memory_get(key, buf, sizeof(buf))) {
        return false;
    }
    char *endptr = NULL;
    long parsed = strtol(buf, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }
    *out_value = (int)parsed;
    return true;
}

static bool login_build_nvs_key(char *buf, size_t buf_size,
                                const char *prefix,
                                int index)
{
    if (!buf || buf_size == 0 || !prefix || index < 0) {
        return false;
    }
    return snprintf(buf, buf_size, "%s%d", prefix, index) > 0;
}

bool login_password_policy_reason(const char *password,
                                  char *reason,
                                  size_t reason_len)
{
    if (!password || password[0] == '\0') {
        if (reason && reason_len > 0) {
            snprintf(reason, reason_len, "Password is required.");
        }
        return false;
    }

    size_t len = strlen(password);
    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_special = false;
    const char *special_chars = "!@#$%^&*";

    for (size_t i = 0; i < len; i++) {
        char c = password[i];
        if (c >= 'A' && c <= 'Z') {
            has_upper = true;
        } else if (c >= 'a' && c <= 'z') {
            has_lower = true;
        } else if (c >= '0' && c <= '9') {
            has_digit = true;
        } else if (strchr(special_chars, c)) {
            has_special = true;
        }
    }

    if (len < 14) {
        if (reason && reason_len > 0) {
            snprintf(reason, reason_len, "Password must be at least 14 characters long.");
        }
        return false;
    }

    if (!has_upper || !has_lower || !has_digit || !has_special) {
        if (reason && reason_len > 0) {
            char missing[128] = {0};
            bool first = true;
            if (!has_upper) {
                strlcat(missing, "uppercase letter", sizeof(missing));
                first = false;
            }
            if (!has_lower) {
                if (!first) {
                    strlcat(missing, ", ", sizeof(missing));
                }
                strlcat(missing, "lowercase letter", sizeof(missing));
                first = false;
            }
            if (!has_digit) {
                if (!first) {
                    strlcat(missing, ", ", sizeof(missing));
                }
                strlcat(missing, "number", sizeof(missing));
                first = false;
            }
            if (!has_special) {
                if (!first) {
                    strlcat(missing, ", ", sizeof(missing));
                }
                strlcat(missing, "special character (!@#$%^&*)", sizeof(missing));
            }
            snprintf(reason, reason_len,
                     "Password must include at least one %s.",
                     missing);
        }
        return false;
    }

    return true;
}

bool login_create_session_token(const char *username,
                                char *token,
                                size_t token_len)
{
    if (!login_is_valid_username(username) || !token || token_len == 0) {
        return false;
    }

    char role_str[LOGIN_ROLE_MAX_LEN] = {0};
    if (!login_user_role(username, role_str, sizeof(role_str))) {
        /* No role persisted for this user — assume 'user' role as a safe fallback.
           Attempt to persist it; if that fails, continue with the fallback anyway. */
        strncpy(role_str, "user", sizeof(role_str) - 1);
        role_str[sizeof(role_str) - 1] = '\0';
        if (login_user_update(username, NULL, role_str) != ESP_OK) {
            ESP_LOGW("login", "Failed to persist fallback role for user '%s'", username);
        }
    }

    login_role_t role = login_role_from_string(role_str);
    if (role == LOGIN_ROLE_NONE) {
        return false;
    }

    if (!login_generate_token(token, token_len)) {
        return false;
    }

    login_clear_expired_tokens();
    int slot = -1;
    for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
        if (s_session_tokens[i].token[0] == '\0') {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        slot = 0;
    }

    strncpy(s_session_tokens[slot].token, token, sizeof(s_session_tokens[slot].token) - 1);
    s_session_tokens[slot].token[sizeof(s_session_tokens[slot].token) - 1] = '\0';
    strncpy(s_session_tokens[slot].username, username, sizeof(s_session_tokens[slot].username) - 1);
    s_session_tokens[slot].username[sizeof(s_session_tokens[slot].username) - 1] = '\0';
    s_session_tokens[slot].role = role;
    s_session_tokens[slot].expires_at_us = login_now_us() + 300LL * 1000000LL;
    return true;
}

bool login_authenticate_with_token(message_source_t source,
                                   int64_t chat_id,
                                   const char *token)
{
    if (!token || token[0] == '\0') {
        return false;
    }

    int index = login_find_token_index(token);
    if (index < 0) {
        return false;
    }

    char username_copy[LOGIN_USERNAME_MAX_LEN];
    strncpy(username_copy, s_session_tokens[index].username, sizeof(username_copy) - 1);
    username_copy[sizeof(username_copy) - 1] = '\0';

    login_role_t role = s_session_tokens[index].role;

    const char *role_name = (role == LOGIN_ROLE_ADMIN) ? "admin" : "user";

    login_clear_token(index);
    const char *username = username_copy;

    ESP_LOGI(TAG, "login_authenticate_with_token: source=%d actor_ptr=%p username='%s' chat_id=%lld", source, (void*)username, username, (long long)chat_id);

    if (source == MSG_SOURCE_CHANNEL) {
        strncpy(s_authenticated_channel_username, username, sizeof(s_authenticated_channel_username) - 1);
        s_authenticated_channel_username[sizeof(s_authenticated_channel_username) - 1] = '\0';
        s_authenticated_channel_role = role;
        ESP_LOGI(TAG, "login_authenticate_with_token: channel actor_ptr=%p username='%s'", (void*)username, username);
        login_audit_add_entry(source, chat_id, "token_login", username, username, role_name, NULL);
        return true;
    }

    if (source == MSG_SOURCE_TELEGRAM) {
        if (chat_id == 0) {
            return false;
        }
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == chat_id) {
                strncpy(s_authenticated_telegram[i].username, username, sizeof(s_authenticated_telegram[i].username) - 1);
                s_authenticated_telegram[i].username[sizeof(s_authenticated_telegram[i].username) - 1] = '\0';
                s_authenticated_telegram[i].role = role;
                login_audit_add_entry(source, chat_id, "token_login", username, username, role_name, NULL);
                return true;
            }
        }
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == 0) {
                s_authenticated_telegram[i].chat_id = chat_id;
                strncpy(s_authenticated_telegram[i].username, username, sizeof(s_authenticated_telegram[i].username) - 1);
                s_authenticated_telegram[i].username[sizeof(s_authenticated_telegram[i].username) - 1] = '\0';
                s_authenticated_telegram[i].role = role;
                login_audit_add_entry(source, chat_id, "token_login", username, username, role_name, NULL);
                return true;
            }
        }
    }

    return false;
}

static int64_t login_now_us(void);
static void login_migrate_legacy_role_keys(void);

static void login_clear_expired_tokens(void)
{
    int64_t now_us = login_now_us();
    for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
        if (s_session_tokens[i].expires_at_us > 0 && now_us >= s_session_tokens[i].expires_at_us) {
            s_session_tokens[i].token[0] = '\0';
            s_session_tokens[i].username[0] = '\0';
            s_session_tokens[i].role = LOGIN_ROLE_NONE;
            s_session_tokens[i].expires_at_us = 0;
        }
    }
}

static bool login_generate_token(char *token, size_t token_len)
{
    if (!token || token_len < LOGIN_SESSION_TOKEN_MAX_LEN) {
        return false;
    }

    uint8_t rnd[16];
    esp_fill_random(rnd, sizeof(rnd));
    for (size_t i = 0; i < sizeof(rnd); i++) {
        snprintf(&token[i * 2], 3, "%02x", rnd[i]);
    }
    token[LOGIN_SESSION_TOKEN_MAX_LEN - 1] = '\0';
    return true;
}

static int login_find_token_index(const char *token)
{
    if (!token) {
        return -1;
    }
    login_clear_expired_tokens();
    for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
        if (s_session_tokens[i].token[0] != '\0' && strcmp(s_session_tokens[i].token, token) == 0) {
            return i;
        }
    }
    return -1;
}

static void login_clear_token(int index)
{
    if (index < 0 || index >= LOGIN_MAX_AUTH_SESSIONS) {
        return;
    }
    s_session_tokens[index].token[0] = '\0';
    s_session_tokens[index].username[0] = '\0';
    s_session_tokens[index].role = LOGIN_ROLE_NONE;
    s_session_tokens[index].expires_at_us = 0;
}

static bool login_password_meets_policy(const char *password)
{
    return login_password_policy_reason(password, NULL, 0);
}

static login_role_t login_role_from_string(const char *role)
{
    if (!role) {
        return LOGIN_ROLE_NONE;
    }
    if (strcmp(role, "admin") == 0) {
        return LOGIN_ROLE_ADMIN;
    }
    if (strcmp(role, "user") == 0) {
        return LOGIN_ROLE_USER;
    }
    return LOGIN_ROLE_NONE;
}

static bool password_hash(const char *password, char *out, size_t out_size)
{
    if (!password || !out || out_size == 0) {
        return false;
    }

    size_t len = strlen(password);
    if (len == 0) {
        return false;
    }

    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)password[i];
    }

    int written = snprintf(out, out_size, "%08x", hash);
    return written > 0 && (size_t)written < out_size;
}

static bool login_build_key(const char *username,
                            bool is_role_key,
                            char *buf,
                            size_t buf_size)
{
    /* NVS limits keys to 15 characters on ESP-IDF. Build readable keys when
       they fit; otherwise fall back to a compact hashed key to avoid
       ESP_ERR_NVS_KEY_TOO_LONG. */
    if (!username || !buf || buf_size == 0) {
        return false;
    }

    const int NVS_KEY_MAX_LEN = 15;
    char candidate[128];
    int r;
    if (is_role_key) {
        r = snprintf(candidate, sizeof(candidate), "%s%s%s",
                     LOGIN_USER_KEY_PREFIX, username, LOGIN_USER_ROLE_SUFFIX);
    } else {
        r = snprintf(candidate, sizeof(candidate), "%s%s",
                     LOGIN_USER_KEY_PREFIX, username);
    }
    if (r < 0) {
        return false;
    }

    if ((int)strlen(candidate) <= NVS_KEY_MAX_LEN) {
        strncpy(buf, candidate, buf_size - 1);
        buf[buf_size - 1] = '\0';
        return true;
    }

    /* Fallback: compute a simple 32-bit FNV-1a hash of the username and use
       a compact prefix so the total key remains within NVS limits. */
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)username; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }

    if (is_role_key) {
        /* use "lg_ur" + 8 hex chars => 5 + 8 = 13 chars */
        r = snprintf(buf, buf_size, "lg_ur%08" PRIx32, h);
    } else {
        /* use "lg_us" + 8 hex chars => 5 + 8 = 13 chars */
        r = snprintf(buf, buf_size, "lg_us%08" PRIx32, h);
    }
    if (r < 0) return false;
    buf[buf_size - 1] = '\0';
    return (int)strlen(buf) <= NVS_KEY_MAX_LEN;
}

static const char *login_source_to_string(message_source_t source)
{
    switch (source) {
        case MSG_SOURCE_CHANNEL: return "channel";
        case MSG_SOURCE_TELEGRAM: return "telegram";
        default: return "unknown";
    }
}

static bool login_persist_audit_metadata(void)
{
    if (!login_save_int_to_nvs(LOGIN_AUDIT_NVS_START_KEY, s_audit_log_start)) {
        return false;
    }
    if (!login_save_int_to_nvs(LOGIN_AUDIT_NVS_COUNT_KEY, s_audit_log_count)) {
        return false;
    }
    return true;
}

static bool login_persist_audit_entry(int index)
{
    if (index < 0 || index >= LOGIN_AUDIT_LOG_MAX_ENTRIES) {
        return false;
    }
    char key[24];
    if (!login_build_nvs_key(key, sizeof(key), LOGIN_AUDIT_NVS_TIMESTAMP_PREFIX, index)) {
        return false;
    }
    if (!login_save_int64_to_nvs(key, s_audit_log[index].timestamp_us)) {
        return false;
    }

    if (!login_build_nvs_key(key, sizeof(key), LOGIN_AUDIT_NVS_TEXT_PREFIX, index)) {
        return false;
    }
    return memory_set(key, s_audit_log[index].text) == ESP_OK;
}

static void login_load_audit_log_from_nvs(void)
{
    int start = 0;
    int count = 0;
    if (!login_load_int_from_nvs(LOGIN_AUDIT_NVS_START_KEY, &start) ||
        !login_load_int_from_nvs(LOGIN_AUDIT_NVS_COUNT_KEY, &count)) {
        return;
    }

    if (start < 0 || start >= LOGIN_AUDIT_LOG_MAX_ENTRIES ||
        count < 0 || count > LOGIN_AUDIT_LOG_MAX_ENTRIES) {
        return;
    }

    s_audit_log_start = start;
    s_audit_log_count = count;

    for (int i = 0; i < count; i++) {
        int index = (s_audit_log_start + i) % LOGIN_AUDIT_LOG_MAX_ENTRIES;
        char key[24];
        char buf[32] = {0};
        if (!login_build_nvs_key(key, sizeof(key), LOGIN_AUDIT_NVS_TIMESTAMP_PREFIX, index) ||
            !memory_get(key, buf, sizeof(buf))) {
            s_audit_log_count = i;
            return;
        }
        s_audit_log[index].timestamp_us = (int64_t)strtoll(buf, NULL, 10);

        if (!login_build_nvs_key(key, sizeof(key), LOGIN_AUDIT_NVS_TEXT_PREFIX, index) ||
            !memory_get(key, s_audit_log[index].text, sizeof(s_audit_log[index].text))) {
            s_audit_log_count = i;
            return;
        }
    }
}

static bool login_save_failed_state_nvs(int index)
{
    char key[24];

    if (!login_build_nvs_key(key, sizeof(key), LOGIN_FAILED_TELEGRAM_ID_PREFIX, index)) {
        return false;
    }
    if (s_failed_telegram[index].chat_id == 0) {
        memory_delete(key);
    } else if (!login_save_int64_to_nvs(key, s_failed_telegram[index].chat_id)) {
        return false;
    }

    if (!login_build_nvs_key(key, sizeof(key), LOGIN_FAILED_TELEGRAM_ATT_PREFIX, index)) {
        return false;
    }
    if (s_failed_telegram[index].chat_id == 0) {
        memory_delete(key);
    } else if (!login_save_int_to_nvs(key, s_failed_telegram[index].failed_attempts)) {
        return false;
    }

    if (!login_build_nvs_key(key, sizeof(key), LOGIN_FAILED_TELEGRAM_BL_PREFIX, index)) {
        return false;
    }
    if (s_failed_telegram[index].chat_id == 0) {
        memory_delete(key);
    } else if (!login_save_int64_to_nvs(key, s_failed_telegram[index].blocked_until_us)) {
        return false;
    }

    return true;
}

static void login_load_failed_state_from_nvs(void)
{
    int attempts = 0;
    int64_t blocked_until = 0;
    if (login_load_int_from_nvs(LOGIN_FAILED_CHANNEL_ATTEMPTS_KEY, &attempts)) {
        s_failed_channel_attempts = attempts;
    }
    if (login_load_int64_from_nvs(LOGIN_FAILED_CHANNEL_BLOCKED_KEY, &blocked_until)) {
        s_failed_channel_blocked_until_us = blocked_until;
    }

    for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
        char key[24];
        int64_t chat_id = 0;
        if (!login_build_nvs_key(key, sizeof(key), LOGIN_FAILED_TELEGRAM_ID_PREFIX, i) ||
            !login_load_int64_from_nvs(key, &chat_id) || chat_id == 0) {
            s_failed_telegram[i].chat_id = 0;
            s_failed_telegram[i].failed_attempts = 0;
            s_failed_telegram[i].blocked_until_us = 0;
            continue;
        }
        s_failed_telegram[i].chat_id = chat_id;
        login_load_int_from_nvs(key, &attempts);
        login_load_int64_from_nvs(key, &blocked_until);
        if (login_build_nvs_key(key, sizeof(key), LOGIN_FAILED_TELEGRAM_ATT_PREFIX, i)) {
            login_load_int_from_nvs(key, &attempts);
            s_failed_telegram[i].failed_attempts = attempts;
        }
        if (login_build_nvs_key(key, sizeof(key), LOGIN_FAILED_TELEGRAM_BL_PREFIX, i)) {
            login_load_int64_from_nvs(key, &blocked_until);
            s_failed_telegram[i].blocked_until_us = blocked_until;
        }
    }
}

static void login_audit_add_entry(message_source_t source,
                                  int64_t chat_id,
                                  const char *event,
                                  const char *actor,
                                  const char *target,
                                  const char *role,
                                  const char *details)
{
    int index;
    if (s_audit_log_count < LOGIN_AUDIT_LOG_MAX_ENTRIES) {
        index = (s_audit_log_start + s_audit_log_count) % LOGIN_AUDIT_LOG_MAX_ENTRIES;
        s_audit_log_count++;
    } else {
        index = s_audit_log_start;
        s_audit_log_start = (s_audit_log_start + 1) % LOGIN_AUDIT_LOG_MAX_ENTRIES;
    }

    s_audit_log[index].timestamp_us = esp_timer_get_time();
    s_audit_log[index].source = source;
    s_audit_log[index].chat_id = chat_id;

    ESP_LOGI(TAG, "login_audit_add_entry: event=%s actor=%p target=%p details=%p index=%d", event ? event : "(null)", (void*)actor, (void*)target, (void*)details, index);

    /* Avoid dereferencing potentially-invalid pointers coming from callers.
       Format the audit entry using pointer values instead of attempting to
       copy the pointed-to strings. This prevents LoadProhibited faults when
       callers pass garbage pointers. */
    int r = snprintf(s_audit_log[index].text,
                 sizeof(s_audit_log[index].text),
                 "%s:%lld %s actor=%s target=%s role=%s details=%s",
                 login_source_to_string(source),
                 (long long)chat_id,
                 event ? event : "",
                 actor ? actor : "-",
                 target ? target : "-",
                 role ? role : "-",
                 details ? details : "-");

    if (r < 0) {
        s_audit_log[index].text[0] = '\0';
    }

    if (!login_persist_audit_entry(index) || !login_persist_audit_metadata()) {
        ESP_LOGW(TAG, "Failed to persist audit log entry %d", index);
    }
}

static bool login_user_list_get(char *buf, size_t buf_size)
{
    if (!buf || buf_size == 0) {
        return false;
    }
    return memory_get(LOGIN_USER_LIST_KEY, buf, buf_size);
}

static void login_boostrap_default_admin(void)
{
    if (login_user_exists(LOGIN_DEFAULT_ADMIN_USERNAME)) {
        char role[LOGIN_ROLE_MAX_LEN] = {0};
        if (!login_user_role(LOGIN_DEFAULT_ADMIN_USERNAME, role, sizeof(role)) ||
            login_role_from_string(role) != LOGIN_ROLE_ADMIN) {
            if (login_user_update(LOGIN_DEFAULT_ADMIN_USERNAME, NULL, LOGIN_DEFAULT_ADMIN_ROLE) == ESP_OK) {
                ESP_LOGW(TAG, "Repaired default admin role for '%s'", LOGIN_DEFAULT_ADMIN_USERNAME);
            } else {
                ESP_LOGW(TAG, "Failed to repair role for default admin '%s'", LOGIN_DEFAULT_ADMIN_USERNAME);
            }
        }
        return;
    }

    esp_err_t err = login_user_add(LOGIN_DEFAULT_ADMIN_USERNAME,
                                   LOGIN_DEFAULT_ADMIN_PASSWORD,
                                   LOGIN_DEFAULT_ADMIN_ROLE);
    if (err == ESP_OK) {
        ESP_LOGW(TAG, "Created default admin user '%s'", LOGIN_DEFAULT_ADMIN_USERNAME);
        login_audit_log_event("user_add", MSG_SOURCE_CHANNEL, 0,
                             LOGIN_DEFAULT_ADMIN_USERNAME,
                             LOGIN_DEFAULT_ADMIN_USERNAME,
                             "default admin created");
    } else {
        ESP_LOGW(TAG, "Failed to create default admin user: %s", esp_err_to_name(err));
    }
}

static bool login_user_append_to_list(const char *username)
{
    char list[512] = {0};
    if (!login_user_list_get(list, sizeof(list))) {
        return memory_set(LOGIN_USER_LIST_KEY, username) == ESP_OK;
    }
    if (strstr(list, username) != NULL) {
        return true;
    }
    size_t existing = strlen(list);
    if (existing + strlen(username) + 2 > sizeof(list)) {
        return false;
    }
    if (existing > 0) {
        strlcat(list, ",", sizeof(list));
    }
    strlcat(list, username, sizeof(list));
    return memory_set(LOGIN_USER_LIST_KEY, list) == ESP_OK;
}

static bool login_user_remove_from_list(const char *username)
{
    char list[512] = {0};
    if (!login_user_list_get(list, sizeof(list))) {
        return false;
    }

    char out[512] = {0};
    char *token = strtok(list, ",");
    bool removed = false;
    while (token) {
        if (strcmp(token, username) != 0) {
            if (out[0] != '\0') {
                strlcat(out, ",", sizeof(out));
            }
            strlcat(out, token, sizeof(out));
        } else {
            removed = true;
        }
        token = strtok(NULL, ",");
    }

    if (!removed) {
        return false;
    }

    if (out[0] == '\0') {
        return memory_delete(LOGIN_USER_LIST_KEY) == ESP_OK;
    }
    return memory_set(LOGIN_USER_LIST_KEY, out) == ESP_OK;
}

static bool login_save_user_record(const char *username,
                                   const char *password,
                                   const char *role)
{
    char hashed[LOGIN_HASH_BUF_SIZE];
    if (!password_hash(password, hashed, sizeof(hashed))) {
        return false;
    }

    char user_key[LOGIN_USERNAME_MAX_LEN + 32];
    char role_key[LOGIN_USERNAME_MAX_LEN + 32];

    if (!login_build_key(username, false, user_key, sizeof(user_key)) ||
        !login_build_key(username, true, role_key, sizeof(role_key))) {
        return false;
    }

    if (memory_set(user_key, hashed) != ESP_OK) {
        return false;
    }
    if (memory_set(role_key, role) != ESP_OK) {
        return false;
    }
    return true;
}

void login_init(void)
{
    memset(s_authenticated_telegram, 0, sizeof(s_authenticated_telegram));
    memset(s_authenticated_channel_username, 0, sizeof(s_authenticated_channel_username));
    s_authenticated_channel_role = LOGIN_ROLE_NONE;
    memset(s_audit_log, 0, sizeof(s_audit_log));
    s_audit_log_start = 0;
    s_audit_log_count = 0;
    memset(s_failed_telegram, 0, sizeof(s_failed_telegram));
    s_failed_channel_attempts = 0;
    s_failed_channel_blocked_until_us = 0;
    login_load_audit_log_from_nvs();
    login_load_failed_state_from_nvs();

    /* Migrate any legacy role keys that may have been stored under long
       human-readable NVS keys (which can exceed the NVS limit). This preserves
       existing role entries that were previously truncated or stored under the
       short truncated key. */
    login_migrate_legacy_role_keys();

    login_boostrap_default_admin();
}

static void login_migrate_legacy_role_keys(void)
{
    char list[512] = {0};
    if (!login_user_list_get(list, sizeof(list))) {
        return;
    }

    char *token = strtok(list, ",");
    while (token) {
        char username[LOGIN_USERNAME_MAX_LEN] = {0};
        strncpy(username, token, sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0';

        char old_key[LOGIN_USERNAME_MAX_LEN + 32];
        snprintf(old_key, sizeof(old_key), "%s%s%s",
                 LOGIN_USER_KEY_PREFIX, username, LOGIN_USER_ROLE_SUFFIX);

        char new_key[LOGIN_USERNAME_MAX_LEN + 32];
        if (!login_build_key(username, true, new_key, sizeof(new_key))) {
            ESP_LOGW("login", "Failed to build new role key for '%s'", username);
            token = strtok(NULL, ",");
            continue;
        }

        /* If keys are identical, nothing to migrate. */
        if (strcmp(old_key, new_key) == 0) {
            token = strtok(NULL, ",");
            continue;
        }

        char value[LOGIN_ROLE_MAX_LEN] = {0};
        bool found = false;

        /* Try reading the original full key if it fits NVS limits. */
        if (strlen(old_key) <= MEMORY_NVS_KEY_MAX_LEN) {
            if (memory_get(old_key, value, sizeof(value))) {
                found = true;
                ESP_LOGI("login", "Migrating role for '%s' from '%s' to '%s'", username, old_key, new_key);
                if (memory_set(new_key, value) == ESP_OK) {
                    memory_delete(old_key);
                }
            }
        }

        /* If not found, try the truncated-old key (possible prior truncation). */
        if (!found) {
            char truncated_old[MEMORY_NVS_KEY_MAX_LEN + 1] = {0};
            strncpy(truncated_old, old_key, MEMORY_NVS_KEY_MAX_LEN);
            truncated_old[MEMORY_NVS_KEY_MAX_LEN] = '\0';
            if (strcmp(truncated_old, new_key) != 0) {
                if (memory_get(truncated_old, value, sizeof(value))) {
                    found = true;
                    ESP_LOGI("login", "Migrating role for '%s' from truncated key '%s' to '%s'", username, truncated_old, new_key);
                    if (memory_set(new_key, value) == ESP_OK) {
                        memory_delete(truncated_old);
                    }
                }
            }
        }

        token = strtok(NULL, ",");
    }
}

bool login_user_has_any(void)
{
    char list[512] = {0};
    if (!login_user_list_get(list, sizeof(list))) {
        return false;
    }
    return list[0] != '\0';
}

bool login_user_exists(const char *username)
{
    if (!login_is_valid_username(username)) {
        return false;
    }

    char user_key[LOGIN_USERNAME_MAX_LEN + 32];
    if (!login_build_key(username, false, user_key, sizeof(user_key))) {
        return false;
    }

    char stored[LOGIN_HASH_BUF_SIZE];
    return memory_get(user_key, stored, sizeof(stored));
}

const char *login_session_username(message_source_t source, int64_t chat_id)
{
    if (source == MSG_SOURCE_CHANNEL) {
        return s_authenticated_channel_username[0] ? s_authenticated_channel_username : NULL;
    }
    if (source == MSG_SOURCE_TELEGRAM) {
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == chat_id) {
                return s_authenticated_telegram[i].username[0] ? s_authenticated_telegram[i].username : NULL;
            }
        }
    }
    return NULL;
}

login_role_t login_session_role(message_source_t source, int64_t chat_id)
{
    if (source == MSG_SOURCE_CHANNEL) {
        return s_authenticated_channel_role;
    }
    if (source == MSG_SOURCE_TELEGRAM) {
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == chat_id) {
                return s_authenticated_telegram[i].role;
            }
        }
    }
    return LOGIN_ROLE_NONE;
}

esp_err_t login_user_add(const char *username,
                         const char *password,
                         const char *role)
{
    if (!login_is_valid_username(username) || !password || password[0] == '\0' || !login_is_valid_role(role) ||
        !login_password_meets_policy(password)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (login_user_exists(username)) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!login_save_user_record(username, password, role)) {
        return ESP_FAIL;
    }

    if (!login_user_append_to_list(username)) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t login_user_update(const char *username,
                            const char *password,
                            const char *role)
{
    if (!login_is_valid_username(username)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!login_user_exists(username)) {
        return ESP_ERR_NOT_FOUND;
    }

    if (role && !login_is_valid_role(role)) {
        return ESP_ERR_INVALID_ARG;
    }

    char role_key[LOGIN_USERNAME_MAX_LEN + 32];
    if (role && !login_build_key(username, true, role_key, sizeof(role_key))) {
        return ESP_ERR_INVALID_ARG;
    }

    if (password && password[0] != '\0') {
        if (!login_password_meets_policy(password)) {
            return ESP_ERR_INVALID_ARG;
        }

        char hashed[LOGIN_HASH_BUF_SIZE];
        if (!password_hash(password, hashed, sizeof(hashed))) {
            return ESP_ERR_INVALID_ARG;
        }
        char user_key[LOGIN_USERNAME_MAX_LEN + 32];
        if (!login_build_key(username, false, user_key, sizeof(user_key))) {
            return ESP_ERR_INVALID_ARG;
        }
        if (memory_set(user_key, hashed) != ESP_OK) {
            return ESP_FAIL;
        }
    }

    if (role) {
        if (memory_set(role_key, role) != ESP_OK) {
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

esp_err_t login_user_delete(const char *username)
{
    if (!login_is_valid_username(username)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!login_user_exists(username)) {
        return ESP_ERR_NOT_FOUND;
    }

    char user_key[LOGIN_USERNAME_MAX_LEN + 32];
    char role_key[LOGIN_USERNAME_MAX_LEN + 32];

    if (!login_build_key(username, false, user_key, sizeof(user_key)) ||
        !login_build_key(username, true, role_key, sizeof(role_key))) {
        return ESP_ERR_INVALID_ARG;
    }

    if (memory_delete(user_key) != ESP_OK) {
        return ESP_FAIL;
    }
    if (memory_delete(role_key) != ESP_OK) {
        return ESP_FAIL;
    }
    if (!login_user_remove_from_list(username)) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

bool login_user_list(char *out, size_t out_size)
{
    if (!out || out_size == 0) {
        return false;
    }
    return login_user_list_get(out, out_size);
}

bool login_user_role(const char *username, char *role, size_t role_len)
{
    if (!login_is_valid_username(username) || !role || role_len == 0) {
        return false;
    }

    char role_key[LOGIN_USERNAME_MAX_LEN + 32];
    if (!login_build_key(username, true, role_key, sizeof(role_key))) {
        return false;
    }
    return memory_get(role_key, role, role_len);
}

bool login_verify_password(const char *username, const char *password)
{
    if (!login_is_valid_username(username) || !password || password[0] == '\0') {
        return false;
    }

    return login_password_matches(username, password);
}

static bool login_password_matches(const char *username, const char *password)
{
    if (!login_is_valid_username(username) || !password || password[0] == '\0') {
        return false;
    }

    char user_key[LOGIN_USERNAME_MAX_LEN + 32];
    if (!login_build_key(username, false, user_key, sizeof(user_key))) {
        return false;
    }

    char stored[LOGIN_HASH_BUF_SIZE] = {0};
    if (!memory_get(user_key, stored, sizeof(stored))) {
        return false;
    }

    char hashed[LOGIN_HASH_BUF_SIZE];
    if (!password_hash(password, hashed, sizeof(hashed))) {
        return false;
    }

    return strcmp(stored, hashed) == 0;
}

static void login_clear_channel_session(void)
{
    memset(s_authenticated_channel_username, 0, sizeof(s_authenticated_channel_username));
    s_authenticated_channel_role = LOGIN_ROLE_NONE;
}

static void login_clear_telegram_session(int64_t chat_id)
{
    for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
        if (s_authenticated_telegram[i].chat_id == chat_id) {
            memset(&s_authenticated_telegram[i], 0, sizeof(s_authenticated_telegram[i]));
            return;
        }
    }
}

static int64_t login_now_us(void)
{
    return esp_timer_get_time();
}

static bool login_is_blocked(int64_t blocked_until_us)
{
    return blocked_until_us > 0 && login_now_us() < blocked_until_us;
}

static int login_blocked_seconds_remaining(int64_t blocked_until_us)
{
    if (!login_is_blocked(blocked_until_us)) {
        return 0;
    }
    int64_t delta_us = blocked_until_us - login_now_us();
    int remaining = (int)((delta_us + 999999) / 1000000);
    return remaining > 0 ? remaining : 1;
}

static bool login_find_failed_state(message_source_t source,
                                    int64_t chat_id,
                                    int *out_attempts,
                                    int64_t *out_blocked_until_us)
{
    if (source == MSG_SOURCE_CHANNEL) {
        if (out_attempts) {
            *out_attempts = s_failed_channel_attempts;
        }
        if (out_blocked_until_us) {
            *out_blocked_until_us = s_failed_channel_blocked_until_us;
        }
        return true;
    }
    if (source == MSG_SOURCE_TELEGRAM) {
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_failed_telegram[i].chat_id == chat_id) {
                if (out_attempts) {
                    *out_attempts = s_failed_telegram[i].failed_attempts;
                }
                if (out_blocked_until_us) {
                    *out_blocked_until_us = s_failed_telegram[i].blocked_until_us;
                }
                return true;
            }
        }
    }
    return false;
}

static void login_store_failed_state(message_source_t source,
                                     int64_t chat_id,
                                     int attempts,
                                     int64_t blocked_until_us)
{
    if (source == MSG_SOURCE_CHANNEL) {
        s_failed_channel_attempts = attempts;
        s_failed_channel_blocked_until_us = blocked_until_us;
        if (!login_save_int_to_nvs(LOGIN_FAILED_CHANNEL_ATTEMPTS_KEY, attempts) ||
            !login_save_int64_to_nvs(LOGIN_FAILED_CHANNEL_BLOCKED_KEY, blocked_until_us)) {
            ESP_LOGW(TAG, "Failed to persist channel failed login state");
        }
        return;
    }

    for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
        if (s_failed_telegram[i].chat_id == chat_id || s_failed_telegram[i].chat_id == 0) {
            s_failed_telegram[i].chat_id = chat_id;
            s_failed_telegram[i].failed_attempts = attempts;
            s_failed_telegram[i].blocked_until_us = blocked_until_us;
            if (!login_save_failed_state_nvs(i)) {
                ESP_LOGW(TAG, "Failed to persist telegram failed login state slot %d", i);
            }
            return;
        }
    }
}

bool login_can_attempt(message_source_t source,
                       int64_t chat_id,
                       char *reason,
                       size_t reason_len)
{
    int attempts = 0;
    int64_t blocked_until_us = 0;
    login_find_failed_state(source, chat_id, &attempts, &blocked_until_us);
    if (login_is_blocked(blocked_until_us)) {
        int remaining = login_blocked_seconds_remaining(blocked_until_us);
        if (reason && reason_len > 0) {
            snprintf(reason, reason_len,
                     "Too many failed login attempts. Try again in %d seconds.",
                     remaining);
        }
        return false;
    }

    if (reason && reason_len > 0) {
        reason[0] = '\0';
    }
    return true;
}

void login_record_failed_attempt(message_source_t source, int64_t chat_id)
{
    int attempts = 0;
    int64_t blocked_until_us = 0;
    login_find_failed_state(source, chat_id, &attempts, &blocked_until_us);

    if (login_is_blocked(blocked_until_us)) {
        return;
    }

    attempts++;
    if (attempts >= LOGIN_MAX_FAILED_ATTEMPTS) {
        blocked_until_us = login_now_us() + LOGIN_BLOCK_SECONDS * 1000000LL;
        attempts = 0;
    }

    login_store_failed_state(source, chat_id, attempts, blocked_until_us);
}

void login_reset_failed_attempts(message_source_t source, int64_t chat_id)
{
    login_store_failed_state(source, chat_id, 0, 0);
}

bool login_is_authenticated(message_source_t source, int64_t chat_id)
{
    if (source == MSG_SOURCE_CHANNEL) {
        return s_authenticated_channel_role != LOGIN_ROLE_NONE;
    }
    if (source == MSG_SOURCE_TELEGRAM) {
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == chat_id &&
                s_authenticated_telegram[i].role != LOGIN_ROLE_NONE) {
                return true;
            }
        }
    }
    return false;
}

bool login_is_admin(message_source_t source, int64_t chat_id)
{
    return login_session_role(source, chat_id) == LOGIN_ROLE_ADMIN;
}

void login_audit_log_event(const char *event,
                           message_source_t source,
                           int64_t chat_id,
                           const char *actor,
                           const char *target,
                           const char *details)
{
    login_audit_add_entry(source, chat_id, event, actor, target, "-", details);
}

bool login_get_audit_log(char *out, size_t out_size)
{
    if (!out || out_size == 0) {
        return false;
    }

    size_t offset = 0;
    for (int i = 0; i < s_audit_log_count; i++) {
        int index = (s_audit_log_start + i) % LOGIN_AUDIT_LOG_MAX_ENTRIES;
        int written = snprintf(out + offset, out_size - offset,
                               "%lld %s\n",
                               (long long)s_audit_log[index].timestamp_us,
                               s_audit_log[index].text);
        if (written < 0 || (size_t)written >= out_size - offset) {
            break;
        }
        offset += (size_t)written;
    }
    return offset > 0;
}

bool login_authenticate(message_source_t source,
                       int64_t chat_id,
                       const char *username,
                       const char *password)
{
    if (!login_password_matches(username, password)) {
        return false;
    }

    char role[LOGIN_ROLE_MAX_LEN] = {0};
    if (!login_user_role(username, role, sizeof(role))) {
        return false;
    }

    login_role_t session_role = login_role_from_string(role);
    if (session_role == LOGIN_ROLE_NONE) {
        return false;
    }

    const char *role_name = (session_role == LOGIN_ROLE_ADMIN) ? "admin" : "user";

    if (source == MSG_SOURCE_CHANNEL) {
        strncpy(s_authenticated_channel_username, username, sizeof(s_authenticated_channel_username) - 1);
        s_authenticated_channel_username[sizeof(s_authenticated_channel_username) - 1] = '\0';
        s_authenticated_channel_role = session_role;
        login_audit_add_entry(source, chat_id, "login_success", username, username, role_name, NULL);
        return true;
    }

    if (source == MSG_SOURCE_TELEGRAM) {
        if (chat_id == 0) {
            return false;
        }
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == chat_id) {
                strncpy(s_authenticated_telegram[i].username, username, sizeof(s_authenticated_telegram[i].username) - 1);
                s_authenticated_telegram[i].username[sizeof(s_authenticated_telegram[i].username) - 1] = '\0';
                s_authenticated_telegram[i].role = session_role;
                login_audit_add_entry(source, chat_id, "login_success", username, username, role_name, NULL);
                return true;
            }
        }
        for (int i = 0; i < LOGIN_MAX_AUTH_SESSIONS; i++) {
            if (s_authenticated_telegram[i].chat_id == 0) {
                s_authenticated_telegram[i].chat_id = chat_id;
                strncpy(s_authenticated_telegram[i].username, username, sizeof(s_authenticated_telegram[i].username) - 1);
                s_authenticated_telegram[i].username[sizeof(s_authenticated_telegram[i].username) - 1] = '\0';
                s_authenticated_telegram[i].role = session_role;
                login_audit_add_entry(source, chat_id, "login_success", username, username, role_name, NULL);
                return true;
            }
        }
    }

    return false;
}

void login_logout(message_source_t source, int64_t chat_id)
{
    if (source == MSG_SOURCE_CHANNEL) {
        login_clear_channel_session();
        return;
    }
    if (source == MSG_SOURCE_TELEGRAM) {
        login_clear_telegram_session(chat_id);
    }
}


void login_logout_all(void)
{
    login_clear_channel_session();
    memset(s_authenticated_telegram, 0, sizeof(s_authenticated_telegram));
}
