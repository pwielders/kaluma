#include <stdlib.h>

typedef enum {
  WIFI_AUTH_UNKNOWN,
  WIFI_AUTH_OPEN,
  WIFI_AUTH_WEP_PSK,
  WIFI_AUTH_WPA,
  WIFI_AUTH_WPA2,
  WIFI_AUTH_WPA2_PSK
} wifi_authentication;

int8_t socket_stream();
int8_t socket_datagram();

int socket_resolve (const uint8_t timeout, const char* name, ip_addr_t* ipv4);
int socket_bind    (const uint8_t fd, const ip_addr_t* ipv4, const uint16_t port);
int socket_listen  (const uint8_t fd);
int socket_connect (const uint8_t fd);
int socket_send    (const uint8_t fd, const uint16_t length, const uint8_t* buffer);
int socket_close   (const uint8_t fd);

extern void (*socket_connected) (const uint8_t fd);
extern void (*socket_received)  (const uint8_t fd, const uint16_t length, const uint8_t* buffer, const ip_addr_t* ipv4, const uint16_t port);
extern void (*socket_accepted)  (const uint8_t source, const uint8_t accepted);
extern void (*socket_closed)    (const uint8_t fd);

void wifi_reset();
void wifi_process();
void wifi_status(const char** ssid, const uint8_t* bssid[6]);

int  wifi_access_point(const char* ssid, const char* passwd, const ip_addr_t* gw, const ip_addr_t* mask);
int  wifi_scan(const uint8_t seconds);
int  wifi_connect(const char* ssid, const uint8_t bssid[6], const wifi_authentication auth_mode, const char* password);
int  wifi_disconnect();

extern void (*wifi_report)(const char* ssid, const uint8_t bssid[6], const wifi_authentication auth, const uint8_t channel, const int strength);
extern void (*wifi_link)(const char* ssid, const bool connected);

#define KALUMA_MAX_SOCKETS 16
