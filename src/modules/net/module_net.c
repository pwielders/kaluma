/* Copyright (c) 2017 Kaluma
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <port/netdev.h>
#include <string.h>

#include "err.h"
#include "jerryscript.h"
#include "jerryxx.h"
#include "system.h"
#include "net_magic_strings.h"

typedef struct {
  uint8_t fd;
  jerry_value_t obj;
} socket_data_t;

socket_data_t socket_map[KALUMA_MAX_SOCKETS];

JERRYXX_FUN(net_ctor_fn) {
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_ctor_fn) {
  jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                              0);
  for (int i = 0; i < KM_MAX_SOCKET_NO; i++) {
    __socket_info.socket[i].fd = -1;
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_socket) {
  JERRYXX_CHECK_ARG_STRING(0, "domain");
  JERRYXX_CHECK_ARG_STRING(1, "protocol");
  JERRYXX_GET_ARG_STRING_AS_CHAR(0, domain);
  JERRYXX_GET_ARG_STRING_AS_CHAR(1, protocol);
  int protocol_param = NET_SOCKET_STREAM;
  if (strcmp(protocol, "STREAM") && strcmp(protocol, "DGRAM")) {
    return jerry_create_error(
        JERRY_ERROR_TYPE,
        (const jerry_char_t *)"un-supported domain or protocol.");
  } else {
    if (strcmp(protocol, "STREAM")) {
      protocol_param = NET_SOCKET_DGRAM;
    }
  }
  if (__cyw43_drv.status_flag == KM_CYW43_STATUS_DISABLED) {
    return jerry_create_error(
        JERRY_ERROR_COMMON,
        (const jerry_char_t *)"PICO-W CYW43 WiFi is not initialized.");
  }
  int wifi_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
  int wifi_ap_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_AP);
  if (wifi_status != CYW43_LINK_UP && wifi_ap_status != CYW43_LINK_UP) {
    return jerry_create_error(JERRY_ERROR_COMMON,
                              (const jerry_char_t *)"WiFi is not connected.");
  }
  int8_t fd = km_get_socket_fd();
  if (!km_is_valid_fd(fd)) {
    return jerry_create_error_from_value(create_system_error(EREMOTEIO), true);
  }
  __socket_info.socket[fd].server_fd = -1;
  __socket_info.socket[fd].tcp_server_pcb = NULL;
  __socket_info.socket[fd].state = NET_SOCKET_STATE_CLOSED;
  __socket_info.socket[fd].ptcl = protocol_param;
  __socket_info.socket[fd].lport = 0;
  __socket_info.socket[fd].rport = 0;
  __socket_info.socket[fd].raddr.addr = 0;
  __socket_info.socket[fd].obj = jerry_create_object();
  uint8_t mac_addr[6] = {0};
  char *p_str_buff = (char *)malloc(18);
  if (cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, mac_addr) < 0) {
    memset(mac_addr, 0, 6);
  }
  sprintf(p_str_buff, "%02X:%02X:%02X:%02X:%02X:%02X", mac_addr[0], mac_addr[1],
          mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
  jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_NETWORK_MAC,
                              p_str_buff);
  jerryxx_set_property_number(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_FD, fd);
  if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
    sprintf(p_str_buff, "STREAM");
  } else {
    sprintf(p_str_buff, "DGRAM");
  }
  jerryxx_set_property_string(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_PTCL, p_str_buff);
  jerryxx_set_property_number(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_STATE,
                              __socket_info.socket[fd].state);
  struct netif *p_netif = &(cyw43_state.netif[CYW43_ITF_STA]);
  const ip_addr_t *laddr = netif_ip_addr4(p_netif);
  __socket_info.laddr = *laddr;
  sprintf(p_str_buff, "%s", ipaddr_ntoa(laddr));
  jerryxx_set_property_string(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_LADDR, p_str_buff);
  jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_NETWORK_IP,
                              p_str_buff);
  jerryxx_set_property_number(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_LPORT,
                              __socket_info.socket[fd].lport);
  sprintf(p_str_buff, "%s", ipaddr_ntoa(&(__socket_info.socket[fd].raddr)));
  jerryxx_set_property_string(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_RADDR, p_str_buff);
  jerryxx_set_property_number(__socket_info.socket[fd].obj,
                              MSTR_NET_SOCKET_RPORT,
                              __socket_info.socket[fd].rport);
  free(p_str_buff);
  return jerry_create_number(fd);
}

JERRYXX_FUN(net_network_get) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  if (!km_is_valid_fd(fd) || !km_is_valid_fd(__socket_info.socket[fd].fd)) {
    return jerry_create_undefined();
  }
  return __socket_info.socket[fd].obj;
}

static err_t __net_socket_close(int8_t fd) {
  err_t err = ERR_OK;
  if (km_is_valid_fd(fd)) {
    __socket_info.socket[fd].fd = -1;
  } else {
    return EPERM;
  }

  if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
    if (__socket_info.socket[fd].tcp_server_pcb) {
    tcp_arg(__socket_info.socket[fd].tcp_server_pcb, NULL);
    err = __tcp_close(__socket_info.socket[fd].tcp_server_pcb);
    __socket_info.socket[fd].tcp_server_pcb = NULL;
    }
    if (__socket_info.socket[fd].tcp_pcb) {
      __tcp_close(__socket_info.socket[fd].tcp_pcb);
      __socket_info.socket[fd].tcp_pcb = NULL;
    }
  } else { /** UDP */
    if (__socket_info.socket[fd].udp_pcb) {
      udp_disconnect(__socket_info.socket[fd].udp_pcb);
      udp_remove(__socket_info.socket[fd].udp_pcb);
      __socket_info.socket[fd].udp_pcb = NULL;
    }
  }

  jerry_value_t close_js_cb = jerryxx_get_property(
      __socket_info.socket[fd].obj, MSTR_NET_SOCKET_CLOSE_CB);
  if (jerry_value_is_function(close_js_cb)) {
    jerry_value_t this_val = jerry_create_undefined();
    jerry_call_function(close_js_cb, this_val, NULL, 0);
    jerry_release_value(this_val);
  }
  jerry_release_value(__socket_info.socket[fd].obj);
  return err;
}

static err_t __net_data_receved(int8_t fd, struct tcp_pcb *tpcb,
                                struct pbuf *p) {
  err_t err = ERR_OK;
  if (p == NULL) {
    __net_socket_close(fd);
  } else {
    int8_t read_fd = km_is_valid_fd(__socket_info.socket[fd].server_fd)
                          ? __socket_info.socket[fd].server_fd
                          : fd;
    if (km_is_valid_fd(read_fd)) {
      if (p->tot_len > 0) {
        char *receiver_buffer = (char *)calloc(sizeof(char), p->tot_len + 1);
        for (struct pbuf *q = p; q != NULL; q = q->next) {
          strncat(receiver_buffer, q->payload, q->len);
        }
        if (tpcb) {
          tcp_recved(tpcb, p->tot_len);
        }
        jerry_value_t read_js_cb = jerryxx_get_property(
            __socket_info.socket[read_fd].obj, MSTR_NET_SOCKET_READ_CB);
        if (jerry_value_is_function(read_js_cb)) {
          jerry_value_t this_val = jerry_create_undefined();
          jerry_value_t data =
              jerry_create_string((const jerry_char_t *)receiver_buffer);
          jerry_value_t args_p[1] = {data};
          jerry_call_function(read_js_cb, this_val, args_p, 2);
          jerry_release_value(data);
          jerry_release_value(this_val);
        }
        jerry_release_value(read_js_cb);
        free(receiver_buffer);
      }
    } else {
      err = ERANGE;
    }
    pbuf_free(p);
  }
  return err;
}

static err_t __tcp_data_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
                                err_t err) {
  if (err == ERR_OK) {
    int8_t *fd = (int8_t *)arg;
    err = __net_data_receved(*fd, tpcb, p);
  }
  return err;
}

static void __udp_data_recv_cb(void *arg, struct udp_pcb *upcb, struct pbuf *p,
                               const struct ip4_addr *addr,
                               short unsigned int port) {
  (void)upcb;
  (void)addr;
  (void)port;
  int8_t *fd = (int8_t *)arg;
  __net_data_receved(*fd, NULL, p);
}

static err_t __net_client_connect_cb(void *arg, struct tcp_pcb *tpcb,
                                     err_t err) {
  if (err == ERR_OK) {
    int8_t *fd = (int8_t *)arg;
    if (km_is_valid_fd(*fd)) {
      jerry_value_t connect_js_cb = jerryxx_get_property(
          __socket_info.socket[*fd].obj, MSTR_NET_SOCKET_CONNECT_CB);
      if (jerry_value_is_function(connect_js_cb)) {
        jerry_value_t this_val = jerry_create_undefined();
        jerry_call_function(connect_js_cb, this_val, NULL, 0);
        jerry_release_value(this_val);
      }
      jerry_release_value(connect_js_cb);
    } else {
      err = ERANGE;
    }
  }
  return err;
}

static err_t __tcp_server_accept_cb(void *arg, struct tcp_pcb *newpcb,
                                    err_t err) {
  if (err == ERR_OK) {
    int8_t *server_fd = (int8_t *)arg;
    int8_t fd = km_get_socket_fd();
    if (km_is_valid_fd(*server_fd) && km_is_valid_fd(fd)) {
      char *p_str_buff = (char *)malloc(18);
      __socket_info.socket[fd].server_fd = *server_fd;
      __socket_info.socket[fd].tcp_server_pcb = NULL;
      __socket_info.socket[fd].state = NET_SOCKET_STATE_CONNECTED;
      __socket_info.socket[fd].ptcl = NET_SOCKET_STREAM;
      __socket_info.socket[fd].lport = __socket_info.socket[*server_fd].lport;
      __socket_info.socket[fd].rport = 0;
      __socket_info.socket[fd].raddr.addr = 0;
      __socket_info.socket[fd].obj = jerry_create_object();
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_FD, fd);
      sprintf(p_str_buff, "STREAM");
      jerryxx_set_property_string(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_PTCL, p_str_buff);
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_STATE,
                                  __socket_info.socket[fd].state);
      struct netif *p_netif = &(cyw43_state.netif[CYW43_ITF_STA]);
      const ip_addr_t *laddr = netif_ip_addr4(p_netif);
      __socket_info.laddr = *laddr;
      sprintf(p_str_buff, "%s", ipaddr_ntoa(laddr));
      jerryxx_set_property_string(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_LADDR, p_str_buff);
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_LPORT,
                                  __socket_info.socket[fd].lport);
      sprintf(p_str_buff, "%s", ipaddr_ntoa(&(__socket_info.socket[fd].raddr)));
      jerryxx_set_property_string(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_RADDR, p_str_buff);
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_RPORT,
                                  __socket_info.socket[fd].rport);
      free(p_str_buff);
      __socket_info.socket[fd].tcp_pcb = newpcb;
      tcp_arg(__socket_info.socket[fd].tcp_pcb, &(__socket_info.socket[fd].fd));
      tcp_poll(__socket_info.socket[fd].tcp_pcb, NULL, 0);
      tcp_sent(__socket_info.socket[fd].tcp_pcb, NULL);
      tcp_err(__socket_info.socket[fd].tcp_pcb, NULL);
      tcp_recv(__socket_info.socket[fd].tcp_pcb, __tcp_data_recv_cb);
      jerry_value_t acept_js_cb =
          jerryxx_get_property(__socket_info.socket[*server_fd].obj,
                               MSTR_NET_SOCKET_ACCEPT_CB);
      if (jerry_value_is_function(acept_js_cb)) {
        jerry_value_t this_val = jerry_create_undefined();
        jerry_value_t fd_val = jerry_create_number(fd);
        jerry_value_t args_p[1] = {fd_val};
        jerry_call_function(acept_js_cb, this_val, args_p, 1);
        jerry_release_value(fd_val);
        jerry_release_value(this_val);
      }
      jerry_release_value(acept_js_cb);
    } else {
      err = ECONNREFUSED;
    }
  }
  return err;
}

void __dns_found_cb(const char *name, const ip_addr_t *ipaddr, void *callback_arg) {
  (void) name;
  if (ipaddr) {
    *(ip_addr_t *)callback_arg = *ipaddr;
  } else {
    IP4_ADDR((ip_addr_t *)callback_arg, 0, 0, 0, 0); // IP is not found.
  }
  __cyw43_drv.status_flag |= KM_CYW43_STATUS_DNS_DONE;
}

JERRYXX_FUN(net_network_connect) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_STRING(1, "addr");
  JERRYXX_CHECK_ARG_NUMBER(2, "port");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(3, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  JERRYXX_GET_ARG_STRING_AS_CHAR(1, addr_str);
  uint16_t port = JERRYXX_GET_ARG_NUMBER(2);
  err_t err = ERR_OK;
  if (km_is_valid_fd(fd) && __socket_info.socket[fd].state == NET_SOCKET_STATE_CLOSED) {
#if ENABLE_CLIENT_DNS
    __cyw43_drv.status_flag &= ~KM_CYW43_STATUS_DNS_DONE;
    err = dns_gethostbyname_addrtype((const char *)addr_str, &(__socket_info.socket[fd].raddr),
                                      __dns_found_cb, &(__socket_info.socket[fd].raddr),
                                      LWIP_DNS_ADDRTYPE_IPV4);
    if (err == ERR_INPROGRESS) {
      int16_t timeout = 300; // 3 Sec
      while((__cyw43_drv.status_flag & KM_CYW43_STATUS_DNS_DONE) == 0) {
        if (timeout-- <= 0) {
          jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
          return jerry_create_error(JERRY_ERROR_COMMON,
                                  (const jerry_char_t *)"DNS response timeout.");
          }
        cyw43_arch_poll();
        km_delay(10);
      }
      if (ip4_addr_get_u32(&(__socket_info.socket[fd].raddr)) == 0) {
        jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
        return jerry_create_error(JERRY_ERROR_COMMON,
                                 (const jerry_char_t *)"DNS Error: IP is not found.");
      }
      __cyw43_drv.status_flag &= ~KM_CYW43_STATUS_DNS_DONE;
    } else if (err != ERR_OK) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
      return jerry_create_error(JERRY_ERROR_COMMON,
                                (const jerry_char_t *)"DNS Error: DNS access error.");
    }
#else
    if (ipaddr_aton((const char *)addr_str, &(__socket_info.socket[fd].raddr)) == false) {
      return jerry_create_error(JERRY_ERROR_COMMON,
                                (const jerry_char_t *)"Can't decode IP Address");
    }
#endif /* ENABLE_CLIENT_DNS */
    __socket_info.socket[fd].rport = port;
    char *p_str_buff = (char *)malloc(16);
    sprintf(p_str_buff, "%s", ipaddr_ntoa(&(__socket_info.socket[fd].raddr)));
    jerryxx_set_property_string(__socket_info.socket[fd].obj,
                                MSTR_NET_SOCKET_RADDR, p_str_buff);
    free(p_str_buff);
    jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                MSTR_NET_SOCKET_RPORT,
                                __socket_info.socket[fd].rport);
    if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
      __socket_info.socket[fd].tcp_pcb =
          tcp_new_ip_type(IP_GET_TYPE(&(__socket_info.socket[fd].raddr)));
      if (!(__socket_info.socket[fd].tcp_pcb)) {
        jerryxx_set_property_number(JERRYXX_GET_THIS,
                                    MSTR_NET_NETWORK_ERRNO, -1);
      } else {
        tcp_arg(__socket_info.socket[fd].tcp_pcb,
                &(__socket_info.socket[fd].fd));
        tcp_poll(__socket_info.socket[fd].tcp_pcb, NULL, 0);
        tcp_sent(__socket_info.socket[fd].tcp_pcb, NULL);
        tcp_err(__socket_info.socket[fd].tcp_pcb, NULL);
        tcp_recv(__socket_info.socket[fd].tcp_pcb, __tcp_data_recv_cb);
        err = tcp_connect(
            __socket_info.socket[fd].tcp_pcb, &(__socket_info.socket[fd].raddr),
            __socket_info.socket[fd].rport, __net_client_connect_cb);
      }
    } else { /** UDP */
      __socket_info.socket[fd].udp_pcb =
          udp_new_ip_type(IP_GET_TYPE(&(__socket_info.socket[fd].raddr)));
      if (!(__socket_info.socket[fd].udp_pcb)) {
        jerryxx_set_property_number(JERRYXX_GET_THIS,
                                    MSTR_NET_NETWORK_ERRNO, -1);
      } else {
        udp_recv(__socket_info.socket[fd].udp_pcb, __udp_data_recv_cb,
                 &(__socket_info.socket[fd].fd));
        err = udp_connect(__socket_info.socket[fd].udp_pcb,
                          &(__socket_info.socket[fd].raddr),
                          __socket_info.socket[fd].rport);
        __net_client_connect_cb(&(__socket_info.socket[fd].fd), NULL, ERR_OK);
      }
    }
    if (err != ERR_OK) {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, -1);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, 0);
      __socket_info.socket[fd].state = NET_SOCKET_STATE_CONNECTED;
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_STATE,
                                  __socket_info.socket[fd].state);
    }
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                -1);
  }
  if (JERRYXX_HAS_ARG(3)) {
    jerry_value_t callback = JERRYXX_GET_ARG(3);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_write) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_STRING(1, "string");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(2, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  if (km_is_valid_fd(fd) && (((__socket_info.socket[fd].ptcl == NET_SOCKET_DGRAM) &&
                          (__socket_info.socket[fd].state != NET_SOCKET_STATE_CLOSED)) ||
                         ((__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) &&
                          (__socket_info.socket[fd].state >= NET_SOCKET_STATE_CONNECTED)))) {
    jerry_size_t data_str_sz = jerry_get_string_size(args_p[1]);
    char *data_str = calloc(1, data_str_sz + 1);
    jerry_string_to_char_buffer(args_p[1], (jerry_char_t *)data_str,
                                data_str_sz);
    err_t err = ERR_OK;
    if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
      err = tcp_write(__socket_info.socket[fd].tcp_pcb, data_str,
                      strlen(data_str), TCP_WRITE_FLAG_COPY);
      if (err == ERR_OK) {
        err = tcp_output(__socket_info.socket[fd].tcp_pcb);
      }
    } else {
      struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, strlen(data_str), PBUF_POOL);
      if (p) {
        pbuf_take(p, data_str, strlen(data_str));
        err = udp_send(__socket_info.socket[fd].udp_pcb, p);
        pbuf_free(p);
      }
    }
    if (err != ERR_OK) {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, -1);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, 0);
    }
    free(data_str);
  }
  if (JERRYXX_HAS_ARG(2)) {
    jerry_value_t callback = JERRYXX_GET_ARG(2);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_close) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(1, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  err_t err = ERR_OK;
  err = __net_socket_close(fd);
  if (err == ERR_OK) {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                0);
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                -1);
  }

  if (JERRYXX_HAS_ARG(1)) {
    jerry_value_t callback = JERRYXX_GET_ARG(1);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}

#define ENABLE_TCP_SHUTDOWN 0 /* temporary setting due to the lock up issue */
JERRYXX_FUN(net_network_shutdown) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_NUMBER(1, "how");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(2, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  int8_t how = JERRYXX_GET_ARG_NUMBER(1);
  err_t err = ERR_OK;
  if (km_is_valid_fd(fd)) {
#if ENABLE_TCP_SHUTDOWN
    if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
      int shut_rx = 0;
      int shut_tx = 0;
      if (how == 0) {
        shut_rx = 1;
      } else if (how == 1) {
        shut_tx = 1;
      } else {
        shut_rx = 1;
        shut_tx = 1;
      }

      if (__socket_info.socket[fd].tcp_server_pcb) {
        err = tcp_shutdown(__socket_info.socket[fd].tcp_server_pcb, shut_rx,
                          shut_tx);
      }
      if ((err == ERR_OK) && (__socket_info.socket[fd].tcp_pcb)) {
        err = tcp_shutdown(__socket_info.socket[fd].tcp_pcb, shut_rx, shut_tx);
      }
    } else {
      /** Nothing to do for UDP */
    }
#else
    (void)how;
#endif
  } else {
    err = ERANGE;
  }
  if (err != ERR_OK) {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                -1);
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                0);
    jerry_value_t shutdown_js_cb = jerryxx_get_property(
        __socket_info.socket[fd].obj, MSTR_NET_SOCKET_SHUTDOWN_CB);
    if (jerry_value_is_function(shutdown_js_cb)) {
      jerry_value_t this_val = jerry_create_undefined();
      jerry_call_function(shutdown_js_cb, this_val, NULL, 0);
      jerry_release_value(this_val);
    }
    jerry_release_value(shutdown_js_cb);
  }
  if (JERRYXX_HAS_ARG(2)) {
    jerry_value_t callback = JERRYXX_GET_ARG(2);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_bind) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_STRING(1, "addr");
  JERRYXX_CHECK_ARG_NUMBER(2, "port");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(3, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  JERRYXX_GET_ARG_STRING_AS_CHAR(1, addr_str);
  uint16_t port = JERRYXX_GET_ARG_NUMBER(2);
  err_t err = ERR_OK;
  if (km_is_valid_fd(fd) && __socket_info.socket[fd].state == NET_SOCKET_STATE_CLOSED) {
    ip_addr_t laddr;
#if ENABLE_SERVER_DNS
    __cyw43_drv.status_flag &= ~KM_CYW43_STATUS_DNS_DONE;
    err = dns_gethostbyname_addrtype((const char *)addr_str, &(laddr),
                                      __dns_found_cb, &(laddr),
                                      LWIP_DNS_ADDRTYPE_IPV4);
    if (err == ERR_INPROGRESS) {
      int16_t timeout = 300; // 3 Sec
      while((__cyw43_drv.status_flag & KM_CYW43_STATUS_DNS_DONE) == 0) {
        if (timeout-- <= 0) {
          jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
          return jerry_create_error(JERRY_ERROR_COMMON,
                                  (const jerry_char_t *)"DNS response timeout.");
          }
        cyw43_arch_poll();
        km_delay(10);
      }
      if (ip4_addr_get_u32(&(laddr)) == 0) {
        jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
        return jerry_create_error(JERRY_ERROR_COMMON,
                                 (const jerry_char_t *)"DNS Error: IP is not found.");
      }
      __cyw43_drv.status_flag &= ~KM_CYW43_STATUS_DNS_DONE;
    } else if (err != ERR_OK) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
      return jerry_create_error(JERRY_ERROR_COMMON,
                                (const jerry_char_t *)"DNS Error: DNS access error.");
    }
#else
    if (ipaddr_aton((const char *)addr_str, &(laddr)) == false) {
      return jerry_create_error(JERRY_ERROR_COMMON,
                                (const jerry_char_t *)"Can't decode IP Address");
    }
#endif /* ENABLE_SERVER_DNS */
    __socket_info.socket[fd].lport = port;
    char *p_str_buff = (char *)malloc(16);
    sprintf(p_str_buff, "%s", ipaddr_ntoa(&(laddr)));
    jerryxx_set_property_string(__socket_info.socket[fd].obj,
                                MSTR_NET_SOCKET_LADDR, p_str_buff);
    free(p_str_buff);
    jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                MSTR_NET_SOCKET_LPORT,
                                __socket_info.socket[fd].lport);
    if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
      __socket_info.socket[fd].tcp_server_pcb =
          tcp_new_ip_type(IPADDR_TYPE_ANY);
      if (!(__socket_info.socket[fd].tcp_server_pcb)) {
        jerryxx_set_property_number(JERRYXX_GET_THIS,
                                    MSTR_NET_NETWORK_ERRNO, -1);
      } else {
        err = tcp_bind(__socket_info.socket[fd].tcp_server_pcb, NULL,
                       __socket_info.socket[fd].lport);
      }
    } else {
      err = udp_bind(__socket_info.socket[fd].udp_pcb, &(__socket_info.laddr),
                     __socket_info.socket[fd].lport);
    }
    if (err != ERR_OK) {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, -1);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, 0);
      __socket_info.socket[fd].state = NET_SOCKET_STATE_BIND;
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_STATE,
                                  __socket_info.socket[fd].state);
    }
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                -1);
  }
  if (JERRYXX_HAS_ARG(3)) {
    jerry_value_t callback = JERRYXX_GET_ARG(3);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_listen) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(1, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  err_t err = ERR_OK;
  if (km_is_valid_fd(fd) && __socket_info.socket[fd].state == NET_SOCKET_STATE_BIND) {
    if (__socket_info.socket[fd].ptcl == NET_SOCKET_STREAM) {
      __socket_info.socket[fd].tcp_server_pcb =
          tcp_listen(__socket_info.socket[fd].tcp_server_pcb);
      if (__socket_info.socket[fd].tcp_server_pcb) {
        tcp_arg(__socket_info.socket[fd].tcp_server_pcb,
                &(__socket_info.socket[fd].fd));
        tcp_accept(__socket_info.socket[fd].tcp_server_pcb,
                   __tcp_server_accept_cb);
      } else {
        err = ERR_CONN;
      }
    } else {
      /** Nothing to do for UDP */
    }
    if (err != ERR_OK) {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, -1);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS,
                                  MSTR_NET_NETWORK_ERRNO, 0);
      __socket_info.socket[fd].state = NET_SOCKET_STATE_LISTENING;
      jerryxx_set_property_number(__socket_info.socket[fd].obj,
                                  MSTR_NET_SOCKET_STATE,
                                  __socket_info.socket[fd].state);
    }
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO,
                                -1);
  }
  if (JERRYXX_HAS_ARG(1)) {
    jerry_value_t callback = JERRYXX_GET_ARG(1);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}
