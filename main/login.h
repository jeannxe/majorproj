#ifndef LOGIN_H
#define LOGIN_H

#include "messages.h"
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#define LOGIN_USERNAME_MAX_LEN 32
#define LOGIN_HASH_BUF_SIZE 128
#define LOGIN_ROLE_MAX_LEN 16
#define LOGIN_SESSION_TOKEN_MAX_LEN 33

typedef enum {
    LOGIN_ROLE_NONE = 0,
    LOGIN_ROLE_USER,
    LOGIN_ROLE_ADMIN,
} login_role_t;

void login_init(void);
bool login_user_has_any(void);
bool login_user_exists(const char *username);
const char *login_session_username(message_source_t source, int64_t chat_id);
login_role_t login_session_role(message_source_t source, int64_t chat_id);

bool login_can_attempt(message_source_t source, int64_t chat_id,
                       char *reason, size_t reason_len);
void login_record_failed_attempt(message_source_t source, int64_t chat_id);
void login_reset_failed_attempts(message_source_t source, int64_t chat_id);

esp_err_t login_user_add(const char *username,
                         const char *password,
                         const char *role);
esp_err_t login_user_update(const char *username,
                            const char *password,
                            const char *role);
esp_err_t login_user_delete(const char *username);
bool login_user_list(char *out, size_t out_size);
bool login_user_role(const char *username, char *role, size_t role_len);
bool login_create_session_token(const char *username,
                                char *token,
                                size_t token_len);
bool login_authenticate_with_token(message_source_t source,
                                   int64_t chat_id,
                                   const char *token);
bool login_verify_password(const char *username, const char *password);
bool login_password_policy_reason(const char *password,
                                  char *reason,
                                  size_t reason_len);

bool login_is_authenticated(message_source_t source, int64_t chat_id);
bool login_is_admin(message_source_t source, int64_t chat_id);
bool login_authenticate(message_source_t source,
                       int64_t chat_id,
                       const char *username,
                       const char *password);
void login_logout(message_source_t source, int64_t chat_id);
void login_logout_all(void);

void login_audit_log_event(const char *event,
                           message_source_t source,
                           int64_t chat_id,
                           const char *actor,
                           const char *target,
                           const char *details);
bool login_get_audit_log(char *out, size_t out_size);

#endif // LOGIN_H
