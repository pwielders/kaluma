#pragma once 

#include <stdint.h>
#include <stdbool.h>

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  WIFI_AUTH_UNKNOWN,
  WIFI_AUTH_OPEN,
  WIFI_AUTH_WEP_PSK,
  WIFI_AUTH_WPA,
  WIFI_AUTH_WPA2,
  WIFI_AUTH_WPA2_PSK
} wifi_authentication;

void wifi_process();
void wifi_status(const char** ssid, const uint8_t* bssid[6]);

int  wifi_reset();
int  wifi_access_point(const char* ssid, const char* passwd, const ip_address_t* gateway, const ip_address_t* mask);
int  wifi_scan(const uint8_t seconds);
int  wifi_connect(const uint8_t seconds, const char* ssid, const uint8_t bssid[6], const wifi_authentication auth_mode, const char* password);
int  wifi_disconnect();

typedef void (*wifi_report)(const char* ssid, const uint8_t bssid[6], const wifi_authentication auth, const uint8_t channel, const int strength);
typedef void (*wifi_link)(const char* ssid, const uint8_t bssid[6], const bool connected);

typedef struct {
  wifi_report callback_report;
  wifi_link   callback_link;
} wifi_callbacks_t;

extern wifi_callbacks_t wifi_callbacks;

#ifdef __cplusplus
}
#endif

#define KALUMA_MAX_SOCKETS 16
