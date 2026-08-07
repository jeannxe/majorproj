#include "agent_prompt.h"
#include "config.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "agent_prompt";

const char *agent_persona_name(agent_persona_t persona)
{
    switch (persona) {
        case AGENT_PERSONA_FRIENDLY:
            return "friendly";
        case AGENT_PERSONA_TECHNICAL:
            return "technical";
        case AGENT_PERSONA_WITTY:
            return "witty";
        default:
            return "neutral";
    }
}

static const char *persona_instruction(agent_persona_t persona)
{
    switch (persona) {
        case AGENT_PERSONA_FRIENDLY:
            return "Use warm, approachable wording while staying concise.";
        case AGENT_PERSONA_TECHNICAL:
            return "Use precise technical language and concrete terminology.";
        case AGENT_PERSONA_WITTY:
            return "Use a lightly witty tone; at most one brief witty flourish per reply.";
        default:
            return "Use direct, plain wording.";
    }
}

static const char *device_target_name(void)
{
#ifdef CONFIG_IDF_TARGET
    return CONFIG_IDF_TARGET;
#else
    return "esp32-family";
#endif
}

static void build_gpio_policy_summary(char *buf, size_t buf_len)
{
    if (!buf || buf_len == 0) {
        return;
    }

    if (GPIO_ALLOWED_PINS_CSV[0] != '\0') {
        snprintf(buf, buf_len,
                 "Tool-safe GPIO pins on this device are restricted to allowlist: %s.",
                 GPIO_ALLOWED_PINS_CSV);
        return;
    }

    snprintf(buf, buf_len,
             "Tool-safe GPIO pins on this device are restricted to range %d-%d.",
             GPIO_MIN_PIN, GPIO_MAX_PIN);
}

bool agent_parse_persona_name(const char *name, agent_persona_t *out)
{
    if (!name || !out) {
        return false;
    }

    if (strcmp(name, "neutral") == 0) {
        *out = AGENT_PERSONA_NEUTRAL;
        return true;
    }
    if (strcmp(name, "friendly") == 0) {
        *out = AGENT_PERSONA_FRIENDLY;
        return true;
    }
    if (strcmp(name, "technical") == 0) {
        *out = AGENT_PERSONA_TECHNICAL;
        return true;
    }
    if (strcmp(name, "witty") == 0) {
        *out = AGENT_PERSONA_WITTY;
        return true;
    }

    return false;
}

const char *agent_build_system_prompt(agent_persona_t persona, char *buf, size_t buf_len)
{
    char gpio_policy[192] = {0};
    int written;

    if (!buf || buf_len == 0) {
        return SYSTEM_PROMPT;
    }

    build_gpio_policy_summary(gpio_policy, sizeof(gpio_policy));
    written = snprintf(
        buf,
        buf_len,
        "%s "
        "%s Device target is '%s'. %s "
        "When users ask about pin count or safe pins, answer using this configured"
        "device policy and avoid generic ESP32-family pin claims. "

        "You are also a security assistant. "
        "Answer security questions directly and concisely. "
        "Focus on authentication, audit logs, account security, "
        "access control, suspicious activity, and defensive practices. "
        "Do not ask the user for passwords, credentials, secrets, private keys, "
        "or other sensitive information. "
        "Only make security claims supported by available evidence. "
        "Do not invent attacks, users, IP addresses, security events, or vulnerabilities. "
        "If there is insufficient evidence, clearly say so. "
        "Distinguish between confirmed security events and potential threats. "
        "Only recommend security features relevant to the question. "
        "Do not introduce unrelated technologies or concepts. "
        "A single failed login is not automatically a security incident. "
        "Multiple failed logins may indicate brute-force or credential-guessing activity, "
        "but do not call it a confirmed attack without supporting evidence. "
        "Keep responses concise: normally 3 bullet points within 120 words. "

        "Persona mode is '%s'. Persona affects wording only and must never change "
        "tool choices, automation behavior, safety decisions, or policy handling. "

        "Keep responses short and practical unless the user explicitly asks for more detail.",
        SYSTEM_PROMPT,
        device_target_name(),
        gpio_policy,
        agent_persona_name(persona),
        persona_instruction(persona));

    if (written < 0 || (size_t)written >= buf_len) {
        ESP_LOGW(TAG, "Persona prompt composition overflow, using base system prompt");
        return SYSTEM_PROMPT;
    }

    return buf;
}
