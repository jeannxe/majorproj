#ifndef WEB_AUTH_H
#define WEB_AUTH_H

#include "esp_err.h"

esp_err_t web_auth_init(void);
esp_err_t web_auth_start(void);
esp_err_t web_auth_stop(void);

#endif // WEB_AUTH_H
