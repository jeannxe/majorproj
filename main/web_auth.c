#include "web_auth.h"
#include "login.h"
#include "config.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "esp_tls.h"
#include "esp_err.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "web_auth";
static httpd_handle_t s_httpd = NULL;

static const char *login_page =
"<!DOCTYPE html>"
"<html><head><meta charset=\"utf-8\"><title>zclaw Login</title></head>"
"<body><h1>zclaw Login</h1>"
"<form method=\"post\" action=\"/login\">"
"Username:<br><input type=\"text\" name=\"username\" required minlength=1 maxlength=32><br>"
"Password:<br><input type=\"password\" name=\"password\" required minlength=14 maxlength=128><br>"
"<button type=\"submit\">Login</button>"
"</form>" 
"</body></html>";

static size_t url_decode(char *dst, const char *src, size_t dst_size)
{
    if (!dst || !src || dst_size == 0) {
        return 0;
    }

    size_t out_len = 0;
    while (*src && out_len + 1 < dst_size) {
        if (*src == '+') {
            dst[out_len++] = ' ';
        } else if (*src == '%' && src[1] && src[2]) {
            char hex[3] = { src[1], src[2], '\0' };
            dst[out_len++] = (char) strtol(hex, NULL, 16);
            src += 2;
        } else {
            dst[out_len++] = *src;
        }
        src++;
    }
    dst[out_len] = '\0';
    return out_len;
}

static esp_err_t login_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, login_page, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    char buf[256] = {0};
    size_t ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to receive form data");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char form[256];
    strncpy(form, buf, sizeof(form) - 1);
    form[sizeof(form) - 1] = '\0';

    char username[LOGIN_USERNAME_MAX_LEN] = {0};
    char password[LOGIN_HASH_BUF_SIZE] = {0};
    char *pair = strtok(form, "&");
    while (pair) {
        if (strncmp(pair, "username=", strlen("username=")) == 0) {
            url_decode(username, pair + strlen("username="), sizeof(username));
        } else if (strncmp(pair, "password=", strlen("password=")) == 0) {
            url_decode(password, pair + strlen("password="), sizeof(password));
        }
        pair = strtok(NULL, "&");
    }

    if (username[0] == '\0' || password[0] == '\0') {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Username and password are required");
        return ESP_FAIL;
    }

    if (!login_verify_password(username, password)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Invalid username or password");
        return ESP_FAIL;
    }

    if (!login_create_session_token(username, buf, sizeof(buf))) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create session token");
        return ESP_FAIL;
    }

    char response[512];
    int len = snprintf(response, sizeof(response),
                       "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>zclaw Token</title></head>"
                       "<body><h1>Token Login Created</h1>"
                       "<p>Copy this token into Telegram using:</p>"
                       "<pre>/token-login %s</pre>"
                       "</body></html>",
                       buf);
    if (len < 0 || len >= (int)sizeof(response)) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Response buffer overflow");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, response, len);
    return ESP_OK;
}

static httpd_uri_t login_get_uri = {
    .uri       = "/login",
    .method    = HTTP_GET,
    .handler   = login_get_handler,
    .user_ctx  = NULL
};

static httpd_uri_t login_post_uri = {
    .uri       = "/login",
    .method    = HTTP_POST,
    .handler   = login_post_handler,
    .user_ctx  = NULL
};

esp_err_t web_auth_init(void)
{
    return ESP_OK;
}

esp_err_t web_auth_start(void)
{
    if (s_httpd) {
        return ESP_ERR_INVALID_STATE;
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.ctrl_port = 32768;

    esp_err_t ret = httpd_start(&s_httpd, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(ret));
        return ret;
    }

    httpd_register_uri_handler(s_httpd, &login_get_uri);
    httpd_register_uri_handler(s_httpd, &login_post_uri);
    return ESP_OK;
}

esp_err_t web_auth_stop(void)
{
    if (!s_httpd) {
        return ESP_ERR_INVALID_STATE;
    }
    httpd_stop(s_httpd);
    s_httpd = NULL;
    return ESP_OK;
}
