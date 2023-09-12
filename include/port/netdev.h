#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint32_t addr;
} ipv4_address_t;

#ifdef IPV6_ENABLED
typedef struct {
  u32_t addr[4];
  u8_t zone;
} ipv6_address_t;
#endif

typedef struct {
  #ifdef IPV6_ENABLED
  union {
    ipv4_address_t ipv4;
    ipv6_address_t ipv6;
  };
  uint8_t type;
  #else
  ipv4_address_t ipv4;
  #endif
} ip_address_t;

#ifdef IPV6_ENABLED
#define IS_IPV4(address)  address.type == 4
#define IS_IPV6(address)  address.type == 16
#define SET_IPV4(address) address.type = 4
#define SET_IPV6(address) address.type = 16
#else
#define IS_IPV4(address)  true
#define IS_IPV6(address)  false
#define SET_IPV4(address) 
#define SET_IPV6(address) 
#endif

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

int socket_resolve (const uint8_t timeout, const char* name, ip_address_t* address);
int socket_bind    (const uint8_t fd, const ip_address_t* address, const uint16_t port);
int socket_listen  (const uint8_t fd);
int socket_connect (const uint8_t fd);
int socket_send    (const uint8_t fd, const uint16_t length, const uint8_t* buffer);
int socket_close   (const uint8_t fd);

typedef void (*socket_connected) (const uint8_t fd);
typedef void (*socket_received)  (const uint8_t fd, const uint16_t length, const uint8_t* buffer, const ip_address_t* address, const uint16_t port);
typedef void (*socket_accepted)  (const uint8_t source, const uint8_t accepted);
typedef void (*socket_closed)    (const uint8_t fd);

typedef struct {
  socket_connected callback_connected;
  socket_received  callback_received;
  socket_accepted  callback_accepted;
  socket_closed    callback_closed;
} socket_callbacks_t;

extern socket_callbacks_t socket_callbacks;

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
