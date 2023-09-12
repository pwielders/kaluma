#include <stdlib.h>
#include <err.h>

#include <pico/cyw43_arch.h>

#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/dns.h>

#include <port/net.h>
#include <port/wifi.h>

#include <dhcpserver.h>

#define MAX_GPIO_NUM     2

typedef enum {
  NET_SOCKET_STATE_CLOSED    = 0x00,
  NET_SOCKET_STATE_BIND      = 0x01,
  NET_SOCKET_STATE_CONNECTED = 0x02,
  NET_SOCKET_STATE_LISTENING = 0x04,

  NET_SOCKET_STREAM          = 0x40, /* TCP SOCKET */
  NET_SOCKET_DGRAM           = 0x80  /* UDP SOCKET */
} socket_state;

const uint8_t socket_type_mask = 0xC0;

typedef enum {
  CYW43_STATUS_DISABLED    = 0x00,
  CYW43_STATUS_ACCESSPOINT = 0x01, /* BIT 0 */
  CYW43_STATUS_STATION     = 0x02, /* BIT 1 */
  CYW43_STATUS_DNS_DONE    = 0x04, /* BIT 2 */
  CYW43_STATUS_SCANNING    = 0x08  /* BIT 3 */
} wifi_state;

typedef enum {
  CYW43_WIFI_AUTH_OPEN    = 0x00,
  CYW43_WIFI_AUTH_WEP_PSK = 0x01, /* BIT 0 */
  CYW43_WIFI_AUTH_WPA     = 0x02, /* BIT 1 */
  CYW43_WIFI_AUTH_WPA2    = 0x04  /* BIT 2 */
} cyw43_authentication;

typedef struct {
  volatile socket_state state;
  uint16_t port;
  ip_addr_t addr;
  union {
    struct tcp_pcb* tcp_pcb;
    struct udp_pcb* udp_pcb;
  };
} socket_data_t;

typedef struct {
  char      ssid[33];
  uint8_t   bssid[6];
  ip_addr_t laddr;
} cyw43_driver_t;

static volatile wifi_state __cyw43_status = CYW43_STATUS_DISABLED;
static cyw43_driver_t      __cyw43_drv;
static socket_data_t       __socket_info[KALUMA_MAX_SOCKETS];
static dhcp_server_t       __dhcp_server;

socket_callbacks_t socket_callbacks;
wifi_callbacks_t   wifi_callbacks;

static uint8_t allocate_fd(const socket_state state, void* pcb);

// ----------------------------------------------------------------------------
// Socket abstraction for the Kaluma module to use..
// ----------------------------------------------------------------------------
static uint8_t determine_index(const socket_data_t* base) {
  return ((base - __socket_info) / sizeof(socket_data_t));
}

static err_t tcp_received_cb(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
  socket_data_t* info = (socket_data_t*)arg;

  assert (info != NULL);

  if ( (err == ERR_OK) && (info != NULL) ) {
    uint8_t index = determine_index(info);
    if (p == NULL) {
      socket_close(index);
    }
    else if (p->tot_len > 0) {
      uint8_t* buffer = (uint8_t *) calloc(sizeof(char), p->tot_len + 1);
      int offset = 0;
      for (struct pbuf *q = p; q != NULL; q = q->next) {
        memcpy(&(buffer[offset]), (const uint8_t*) q->payload, q->len);
        offset += q->len;
      }
      if (tpcb == NULL) {
        tcp_recved(tpcb, p->tot_len);
      }
      if(socket_callbacks.callback_received != NULL) {
        ip_address_t address;
        address.ipv4.addr = info->addr.addr;
        SET_IPV4(address);
        socket_callbacks.callback_received(index, p->tot_len, buffer, &address, info->port);
      }
      free(buffer);
    }
  }

  if (p != NULL) { 
    pbuf_free(p);
  }

  return (ERR_OK);
}

static void udp_received_cb(void *arg, struct udp_pcb *upcb, struct pbuf *p,
                               const struct ip4_addr *addr,
                               short unsigned int port) {
  socket_data_t* info = (socket_data_t*)arg;

  assert (info != NULL);

  if (info != NULL) {
    uint8_t index = determine_index(info);
    if (p == NULL) {
      socket_close(index);
    }
    else if (p->tot_len > 0) {
      uint8_t* buffer = (uint8_t *) calloc(sizeof(char), p->tot_len);
      int offset = 0;
      for (struct pbuf *q = p; q != NULL; q = q->next) {
        memcpy(&(buffer[offset]), (const uint8_t*) q->payload, q->len);
        offset += q->len;
      }
      if(socket_callbacks.callback_received != NULL) {
        ip_address_t address;
        address.ipv4.addr = addr->addr;
        SET_IPV4(address);
        socket_callbacks.callback_received(index, p->tot_len, buffer, &address, port);
      }
      free(buffer);
    }
  }

  if (p != NULL) { 
    pbuf_free(p);
  }
}

static err_t connect_cb(void *arg, struct tcp_pcb *tpcb, err_t err) {
  socket_data_t* info = (socket_data_t*)arg;

  assert (info != NULL);

  if ( (err == ERR_OK) && (info != NULL) ) {
    uint8_t index = determine_index(info);

    cyw43_arch_lwip_begin();

    if (info->state != NET_SOCKET_STATE_CLOSED) {
      info->state = NET_SOCKET_STATE_CONNECTED | (info->state & socket_type_mask);
    }
    cyw43_arch_lwip_end();

    if(socket_callbacks.callback_connected != NULL) {
      socket_callbacks.callback_connected(index);
    }
  }

  return ERR_OK;
}

static err_t accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
  socket_data_t* info = (socket_data_t*)arg;

  assert (info != NULL);

  if ( (err == ERR_OK) && (info != NULL) ) {
    uint8_t index = determine_index(info);
    uint8_t accepted;

    if ((accepted = allocate_fd(NET_SOCKET_STREAM, newpcb)) < KALUMA_MAX_SOCKETS) {
      cyw43_arch_lwip_end();
      __socket_info[accepted].state = NET_SOCKET_STATE_CONNECTED | 
                                      (__socket_info[accepted].state & socket_type_mask);
      cyw43_arch_lwip_end();

      if(socket_callbacks.callback_accepted != NULL) {
        socket_callbacks.callback_accepted(index, accepted);
      }
    }
  }
  return ERR_OK;
}

static void dns_found_cb(const char* name, const ip_addr_t* ipaddr, void* callback_arg) {
  if (ipaddr) {
    *(ip_addr_t *)callback_arg = *ipaddr;
  } else {
    IP4_ADDR((ip_addr_t *)callback_arg, 0, 0, 0, 0); // IP is not found.
  }

  cyw43_arch_lwip_begin();
  __cyw43_status &= (~CYW43_STATUS_DNS_DONE);
  cyw43_arch_lwip_end();
}

static bool stack_up_and_running() {
  bool active = false;
  if (__cyw43_status != CYW43_STATUS_DISABLED) {
    int wifi_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
    int wifi_ap_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_AP);
    active = ((wifi_status == CYW43_LINK_UP) || (wifi_ap_status == CYW43_LINK_UP));
  }
  return (active);
}

static uint8_t allocate_fd(const socket_state state, void* pcb) {
  uint8_t result = ~0;

  assert (state != socket_state::NET_SOCKET_STATE_CLOSED);

  if (stack_up_and_running() == true) {
    uint8_t index = 0;

    cyw43_arch_lwip_begin();

    while ( (index < KALUMA_MAX_SOCKETS) && 
            (__socket_info[index].state != NET_SOCKET_STATE_CLOSED) ) {
      index++;
    }

    if (index < KALUMA_MAX_SOCKETS) {
      socket_data_t* base = &(__socket_info[index]);

      base->port = 0;
      base->addr.addr = 0;

      if ((state & socket_type_mask) == NET_SOCKET_STREAM) {
        struct tcp_pcb* store = (pcb != NULL ? (struct tcp_pcb*) pcb : tcp_new_ip_type(IPADDR_TYPE_V4));

        base->tcp_pcb = store;
        base->state = state & socket_type_mask;

        tcp_arg(store, base);
        tcp_poll(store, NULL, 0);
        tcp_sent(store, NULL);
        tcp_err(store, NULL);
        tcp_recv(store, tcp_received_cb);

        result = index;
      }
      else if ((state & socket_type_mask) == NET_SOCKET_DGRAM) {
        struct udp_pcb* store = (pcb != NULL ? (struct udp_pcb*) pcb : udp_new_ip_type(IPADDR_TYPE_V4));

        base->udp_pcb = store;
        base->state = state & socket_type_mask;

        udp_recv(store, udp_received_cb, base);

        result = index;
      }
    }

    cyw43_arch_lwip_end();
  }

  return result;
}

int socket_resolve(const uint8_t timeout, const char* name, ip_address_t* address) {
  int result = ERR_INPROGRESS;

  ip_addr_t ipv4;

  cyw43_arch_lwip_begin();

  if ((__cyw43_status & CYW43_STATUS_DNS_DONE) == 0) {

    __cyw43_status |= CYW43_STATUS_DNS_DONE;

    cyw43_arch_lwip_end();

    result = dns_gethostbyname_addrtype(name, &ipv4,
                                         dns_found_cb, &ipv4,
                                         LWIP_DNS_ADDRTYPE_IPV4);

    if (result == ERR_INPROGRESS) {

      uint16_t slots = timeout * 5; // 3 Sec

      while ((slots != 0) && ((__cyw43_status & CYW43_STATUS_DNS_DONE) != 0)) {
        #if PICO_CYW43_ARCH_POLL
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(200));
        #else
        sleep_ms(200);
        #endif

        slots--;
      }

      if (ip4_addr_get_u32(&ipv4) != 0) {
        address->ipv4.addr = ipv4.addr;
        SET_IPV4(*address);
        result = ERR_OK;
      }
    }

    cyw43_arch_lwip_begin();
    __cyw43_status &= (~CYW43_STATUS_DNS_DONE);
    cyw43_arch_lwip_end();
  }

  return (result);
}

int8_t socket_stream() {
  uint8_t entry = allocate_fd(NET_SOCKET_STREAM, NULL);

  return (entry < KALUMA_MAX_SOCKETS ? entry : -1);
}

int8_t socket_datagram() {
  uint8_t entry = allocate_fd(NET_SOCKET_DGRAM, NULL);

  return (entry < KALUMA_MAX_SOCKETS ? entry : -1);
}

int socket_bind (const uint8_t fd, const ip_address_t* address, const uint16_t port) {
  int err = -1; 

  ip_addr_t ipv4;
  #if LWIP_IPV4 && LWIP_IPV6
  ipv4.ip4.addr = address->ipv4.addr;
  ipv4.type = 0;
  #else
  ipv4.addr = address->ipv4.addr;
  #endif

  cyw43_arch_lwip_begin();

  if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_STREAM) {
    __socket_info[fd].port = port;
    __socket_info[fd].addr = ipv4;
    __socket_info[fd].state |= NET_SOCKET_STATE_BIND;
    err = tcp_bind(__socket_info[fd].tcp_pcb, NULL, port);
  } 
  else if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_DGRAM) {
    __socket_info[fd].port = port;
    __socket_info[fd].addr = ipv4;
    __socket_info[fd].state |= NET_SOCKET_STATE_BIND;
    err = udp_bind(__socket_info[fd].udp_pcb, &ipv4, port);
  }
  cyw43_arch_lwip_end();

  return (err);
}

int socket_listen (const uint8_t fd) {
  int err = -1; 

  cyw43_arch_lwip_begin();

  if ( ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_STREAM) &&
       ((__socket_info[fd].state & NET_SOCKET_STATE_BIND) != 0) ) {
    __socket_info[fd].state |= NET_SOCKET_STATE_LISTENING;
    __socket_info[fd].tcp_pcb = tcp_listen(__socket_info[fd].tcp_pcb);

    tcp_accept(__socket_info[fd].tcp_pcb, accept_cb);
  } 
  cyw43_arch_lwip_end();

  return (err);
}

int socket_connect(const uint8_t fd) {

  int result = -1;

  assert (fd < KALUMA_MAX_SOCKETS);

  cyw43_arch_lwip_begin();

  if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_STREAM) {
    assert (__socket_info[fd].tcp_pcb != NULL);

    result = tcp_connect(
      __socket_info[fd].tcp_pcb, &(__socket_info[fd].addr),
      __socket_info[fd].port, connect_cb);

    cyw43_arch_lwip_end();
  }
  else if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_DGRAM) {

    result = udp_connect(__socket_info[fd].udp_pcb,
                          &(__socket_info[fd].addr),
                          __socket_info[fd].port);
    __socket_info[fd].state = NET_SOCKET_STATE_CONNECTED | 
                   (__socket_info[fd].state & socket_type_mask);

    cyw43_arch_lwip_end();

    if (result == ERR_OK) {
      if(socket_callbacks.callback_connected != NULL) {
        socket_callbacks.callback_connected(fd);
      }
    }
  }

  return (result);
}

int socket_send(const uint8_t fd, const uint16_t length, const uint8_t* buffer) {
  int err = -1;

  cyw43_arch_lwip_begin();

  if (((__socket_info[fd].state & socket_type_mask) & NET_SOCKET_STATE_CONNECTED) != 0) {
    if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_STREAM) {
      err = tcp_write(__socket_info[fd].tcp_pcb, buffer, length, TCP_WRITE_FLAG_COPY);
      if (err == ERR_OK) {
        err = tcp_output(__socket_info[fd].tcp_pcb);
      }
    }
    else if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_DGRAM) {
      struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, length, PBUF_POOL);
      if (p) {
        pbuf_take(p, buffer, length);
        err = udp_send(__socket_info[fd].udp_pcb, p);
        pbuf_free(p);
      }
    }
  }

  cyw43_arch_lwip_end();

  return (err);
}

int socket_close(const uint8_t fd) {
  err_t err = ERR_OK;

  cyw43_arch_lwip_begin();

  if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_STREAM) {
    assert(__socket_info[fd].tcp_pcb != NULL);
    err = tcp_close(__socket_info[fd].tcp_pcb);
    if (err != ERR_OK) {
      tcp_abort(__socket_info[fd].tcp_pcb);
    }
    __socket_info[fd].state   = NET_SOCKET_STATE_CLOSED;
    __socket_info[fd].tcp_pcb = NULL;
  }
  else if ((__socket_info[fd].state & socket_type_mask) == NET_SOCKET_DGRAM) {
    assert(__socket_info[fd].udp_pcb != NULL);
    udp_disconnect(__socket_info[fd].udp_pcb);
    udp_remove(__socket_info[fd].udp_pcb);
    __socket_info[fd].state   = NET_SOCKET_STATE_CLOSED;
    __socket_info[fd].udp_pcb = NULL;
  }
  
  cyw43_arch_lwip_end();

  if (socket_callbacks.callback_closed != NULL) {
    socket_callbacks.callback_closed(fd);
  }

  return (err);
}

// ----------------------------------------------------------------------------
// Wifi abstraction for the Kaluma module to use..
// ----------------------------------------------------------------------------
static int scan_cb(void *env, const cyw43_ev_scan_result_t* result) {
  (void)env;

  wifi_authentication auth_mode = WIFI_AUTH_UNKNOWN;

  if ((result->auth_mode & (CYW43_WIFI_AUTH_WPA | CYW43_WIFI_AUTH_WPA2)) == (CYW43_WIFI_AUTH_WPA | CYW43_WIFI_AUTH_WPA2)) {
     auth_mode = WIFI_AUTH_WPA2;
  } else if (result->auth_mode & CYW43_WIFI_AUTH_WPA2) {
     auth_mode = WIFI_AUTH_WPA2_PSK;
  } else if (result->auth_mode & CYW43_WIFI_AUTH_WPA) {
     auth_mode = WIFI_AUTH_WPA;
  } else if (result->auth_mode & CYW43_WIFI_AUTH_WEP_PSK) {
     auth_mode = WIFI_AUTH_WEP_PSK;
  } else if (result->auth_mode == CYW43_WIFI_AUTH_OPEN) {
     auth_mode = WIFI_AUTH_OPEN;
  }

  if (wifi_callbacks.callback_report != NULL) {
    wifi_callbacks.callback_report((const char*) result->ssid, result->bssid, auth_mode, result->channel, result->rssi);
  }

  return 0;
}

int wifi_reset() {
  if (__cyw43_status == CYW43_STATUS_DISABLED) {
    for (uint8_t index = 0; index < KALUMA_MAX_SOCKETS; index++) {
      __socket_info[index].state = NET_SOCKET_STATE_CLOSED;
    }
  }
  else {
    for (uint8_t index = 0; index < KALUMA_MAX_SOCKETS; index++) {
      socket_close(index);
    }
    cyw43_arch_deinit();
  }

  /* Reset and power up the WL chip */
  cyw43_hal_pin_low(CYW43_PIN_WL_REG_ON);
  cyw43_delay_ms(20);
  cyw43_hal_pin_high(CYW43_PIN_WL_REG_ON);
  cyw43_delay_ms(50);

  if (cyw43_arch_init() != 0) {
    uint8_t mac_addr[6] = {0};
    if (cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, mac_addr) >= 0) {
      struct netif*    netif = &(cyw43_state.netif[CYW43_ITF_STA]);
      const ip_addr_t* laddr = netif_ip_addr4(netif);
      __cyw43_drv.laddr = *laddr;
      __cyw43_status = CYW43_STATUS_STATION;
    }
  }
  return (__cyw43_status = CYW43_STATUS_STATION ? ERR_OK : -1);
}
 
void wifi_process() {
  cyw43_arch_poll();
}

int wifi_scan(const uint8_t seconds) {

  int result = ERR_INPROGRESS;

  assert (seconds > 0);

  cyw43_arch_lwip_begin();

  if ((__cyw43_status & CYW43_STATUS_SCANNING) == 0) {
    cyw43_arch_lwip_end();
  }
  else {
    __cyw43_status |= CYW43_STATUS_SCANNING;
    cyw43_arch_lwip_end();

    cyw43_wifi_scan_options_t scan_opt = {0};
    if (cyw43_wifi_scan(&cyw43_state, &scan_opt, NULL, scan_cb) < 0) {
      result = -1; // FAILED_TO_SCAN;
    }
    else {
      uint16_t slots = 5 * seconds;

      do {
        #if PICO_CYW43_ARCH_POLL
        cyw43_arch_poll();
        cyw43_arch_wait_for_work_until(make_timeout_time_ms(200));
        #else
        sleep_ms(200);
        #endif
        slots--;
      } while (slots);

      result = 0;
    }

    cyw43_arch_lwip_begin();
    __cyw43_status &= (~CYW43_STATUS_SCANNING);
    cyw43_arch_lwip_end();
  }
  return (result);
}

void wifi_status(const char** ssid, const uint8_t* bssid[6]) {

  int wifi_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);

  if (wifi_status != CYW43_LINK_UP) {
    *ssid = NULL;
    *bssid = NULL;
  }
  else {
    *ssid  = __cyw43_drv.ssid;
    *bssid = __cyw43_drv.bssid;
  }
}

int wifi_connect(const uint8_t seconds, const char* ssid, const uint8_t* bssid, const wifi_authentication auth_mode, const char* password) {
  cyw43_authentication auth = CYW43_AUTH_OPEN;

  if (auth_mode == WIFI_AUTH_WPA2) {
      auth = (CYW43_WIFI_AUTH_WPA | CYW43_WIFI_AUTH_WPA2);
  } else if (auth_mode == WIFI_AUTH_WPA2_PSK) {
      auth = CYW43_WIFI_AUTH_WPA2;
  } else if (auth_mode == WIFI_AUTH_WPA) {
      auth = CYW43_WIFI_AUTH_WPA;
  } else if (auth_mode == WIFI_AUTH_WEP_PSK) {
      auth = (cyw43_authentication) 0x00100001; // no idea if this works
  } else if (auth_mode == WIFI_AUTH_OPEN) {
      auth = CYW43_AUTH_OPEN;
  }

  if (ssid == NULL) {
    __cyw43_drv.ssid[0] = '\0';
  }
  else {
    strncpy(__cyw43_drv.ssid, ssid, sizeof(__cyw43_drv.ssid) - 1);
  }

  if (bssid == NULL) {
    memset(__cyw43_drv.bssid, 0, sizeof(__cyw43_drv.bssid));
  }
  else {
    memcpy(__cyw43_drv.bssid, bssid, sizeof(__cyw43_drv.bssid));
  }

  int result = cyw43_arch_wifi_connect_bssid_timeout_ms(ssid, bssid, password, auth, seconds * 1000);

  if (result == ERR_OK) {
    if (wifi_callbacks.callback_link != NULL) {
      wifi_callbacks.callback_link(__cyw43_drv.ssid, __cyw43_drv.bssid, true);
    }
  }

  return (result);
}

int wifi_disconnect() {
  int result = cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
  if (result == 0) {
    if (wifi_callbacks.callback_link != NULL) {
      wifi_callbacks.callback_link(__cyw43_drv.ssid, __cyw43_drv.bssid, false);
    }
    __cyw43_drv.ssid[0] = '\0';
  }
  return (result);
}

int wifi_access_point(const char* ssid, const char* passwd, const ip_address_t* gw, const ip_address_t* mask)  {
  int result = -1;

  if (cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_AP) == CYW43_LINK_UP) {
    result = ERR_OK;
    if (ssid != NULL) {
      if ((__cyw43_status & CYW43_STATUS_ACCESSPOINT) == 0) {
        cyw43_arch_enable_ap_mode(ssid, passwd, CYW43_AUTH_WPA2_AES_PSK);

        ip_addr_t real_gw;
        #if LWIP_IPV4 && LWIP_IPV6
        real_gw.ip4.addr = gw->ipv4.addr;
        real_gw.type = 0;
        #else
        real_gw.addr = gw->ipv4.addr;
        #endif

        ip_addr_t real_mask;
        #if LWIP_IPV4 && LWIP_IPV6
        real_mask.ip4.addr = mask->ipv4.addr;
        real_mask.type = 0;
        #else
        real_mask.addr = mask->ipv4.addr;
        #endif

        // start DHCP server
	dhcp_server_init(&__dhcp_server, &real_gw, &real_mask);
    
        cyw43_arch_lwip_begin();
        __cyw43_status |= CYW43_STATUS_ACCESSPOINT;
        cyw43_arch_lwip_end();
      }
    }
    else if ((__cyw43_status & CYW43_STATUS_ACCESSPOINT) != 0) {
      // deinit DHCP server
      dhcp_server_deinit(&__dhcp_server);

      wifi_reset();
      cyw43_arch_lwip_begin();
      __cyw43_status &= (~CYW43_STATUS_ACCESSPOINT);
      cyw43_arch_lwip_end();
    }
  }

  return (result);
}

//  bool ret = cyw43_arch_gpio_get(gpio);
//  cyw43_arch_gpio_put(gpio, value);
