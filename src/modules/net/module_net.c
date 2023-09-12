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
#include <port/net.h>
#include <string.h>

#include "err.h"
#include "jerryscript.h"
#include "jerryxx.h"
#include "system.h"
#include "net_magic_strings.h"
#include "module_tools.h" 

#define DNS_RESOLVE_TIMEOUT 10

typedef struct {
  uint8_t fd;
  jerry_value_t obj;
} socket_data_t;

socket_data_t socket_map[KALUMA_MAX_SOCKETS];

void socket_connected_implementation (const uint8_t fd) {
  if ((fd < KALUMA_MAX_SOCKETS) && (socket_map[fd].fd < KALUMA_MAX_SOCKETS)) {
    jerry_value_t callback = jerryxx_get_property(socket_map[fd].obj, MSTR_NET_SOCKET_CONNECT_CB);
    if (jerry_value_is_function(callback)) {
        jerry_value_t this_val = jerry_create_undefined();
        jerry_call_function(callback, this_val, NULL, 0);
        jerry_release_value(this_val);
    }
    jerry_release_value(callback);
  }
}

void socket_received_implementation (const uint8_t fd, const uint16_t length, const uint8_t* buffer, const ip_address_t* address, const uint16_t port) {
  if ((fd < KALUMA_MAX_SOCKETS) && (socket_map[fd].fd < KALUMA_MAX_SOCKETS)) {
    jerry_value_t callback = jerryxx_get_property(socket_map[fd].obj, MSTR_NET_SOCKET_READ_CB);
    if (jerry_value_is_function(callback)) {
      jerry_value_t this_val = jerry_create_undefined();
      jerry_value_t data = jerry_create_string((const jerry_char_t *)buffer);
      jerry_value_t args_p[1] = {data};
      jerry_call_function(callback, this_val, args_p, 1);
      jerry_release_value(data);
      jerry_release_value(this_val);
    }
    jerry_release_value(callback);
  }
}

void socket_accepted_implementation (const uint8_t fd, const uint8_t accepted) {
  if ((fd < KALUMA_MAX_SOCKETS) && (socket_map[fd].fd < KALUMA_MAX_SOCKETS) && (accepted < KALUMA_MAX_SOCKETS)) {
    socket_map[accepted].fd = accepted;
    socket_map[accepted].obj = jerry_create_object();
    jerryxx_set_property_number(socket_map[accepted].obj, MSTR_NET_SOCKET_FD, accepted);
    jerryxx_set_property_string(socket_map[accepted].obj, MSTR_NET_SOCKET_PTCL, "STREAM");
    jerryxx_set_property_string(socket_map[accepted].obj, MSTR_NET_SOCKET_STATE, "CONNECTED");
    jerryxx_set_property_string(socket_map[accepted].obj, MSTR_NET_SOCKET_LADDR, "0.0.0.0");
    jerryxx_set_property_string(socket_map[accepted].obj, MSTR_NET_SOCKET_LPORT, "0");
    jerryxx_set_property_string(socket_map[accepted].obj, MSTR_NET_SOCKET_RADDR, "0.0.0.0");
    jerryxx_set_property_string(socket_map[accepted].obj, MSTR_NET_SOCKET_RPORT, "0");
    jerry_value_t callback = jerryxx_get_property(socket_map[fd].obj, MSTR_NET_SOCKET_ACCEPT_CB);
    if (jerry_value_is_function(callback)) {
      jerry_value_t this_val = jerry_create_undefined();
      jerry_value_t fd_val = jerry_create_number(accepted);
      jerry_value_t args_p[1] = {fd_val};
      jerry_call_function(callback, this_val, args_p, 1);
      jerry_release_value(fd_val);
      jerry_release_value(this_val);
    }
    jerry_release_value(callback);
  }
}

void socket_closed_implementation (const uint8_t fd) {
  if ((fd < KALUMA_MAX_SOCKETS) && (socket_map[fd].fd < KALUMA_MAX_SOCKETS)) {
    jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_STATE, "CLOSED");
    jerry_value_t callback = jerryxx_get_property(socket_map[fd].obj, MSTR_NET_SOCKET_CLOSE_CB);
    if (jerry_value_is_function(callback)) {
      jerry_value_t this_val = jerry_create_undefined();
      jerry_call_function(callback, this_val, NULL, 0);
      jerry_release_value(this_val);
    }
    socket_map[fd].fd = KALUMA_MAX_SOCKETS;
    jerry_release_value(callback);
  } 
}

JERRYXX_FUN(net_network_ctor_fn) {
  jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_socket) {
  int8_t fd;

  JERRYXX_CHECK_ARG_STRING(0, "domain");
  JERRYXX_CHECK_ARG_STRING(1, "protocol");
  JERRYXX_GET_ARG_STRING_AS_CHAR(0, domain);
  JERRYXX_GET_ARG_STRING_AS_CHAR(1, protocol);

  if (strcmp(protocol, "STREAM") && strcmp(protocol, "DGRAM")) {
    return jerry_create_error( JERRY_ERROR_TYPE, (const jerry_char_t *)"un-supported domain or protocol.");
  } 
  else {
    char* socket_type;
    if (strcmp(protocol, "STREAM")) {
      fd = socket_stream();
      socket_type = "STREAM";
    }
    else {
      fd = socket_datagram();
      socket_type = "DGRAM";
    }
    if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) ) {
      return jerry_create_error_from_value(create_system_error(EREMOTEIO), true);
    }
    else {
      socket_map[fd].fd = fd;
      socket_map[fd].obj = jerry_create_object();
      uint8_t mac_addr[6];
      char storage[20];
      memset(mac_addr, 0, 6);

      bytes_to_string(mac_addr, 6, storage);

      jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_NETWORK_MAC, storage);
      jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_NETWORK_IP, "0.0.0.0");

      jerryxx_set_property_number(socket_map[fd].obj, MSTR_NET_SOCKET_FD, fd);
      jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_PTCL, socket_type);
      jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_STATE, "INITIALIZED");
      jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_LADDR, "0.0.0.0");
      jerryxx_set_property_number(socket_map[fd].obj, MSTR_NET_SOCKET_LPORT, 0);
      jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_RADDR, "0.0.0.0");
      jerryxx_set_property_number(socket_map[fd].obj, MSTR_NET_SOCKET_RPORT, 0);
    }
  } 
  return jerry_create_number(fd);
}

JERRYXX_FUN(net_network_get) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);
  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {
    return jerry_create_undefined();
  }
  return jerry_acquire_value(socket_map[fd].obj);
}

JERRYXX_FUN(net_network_connect) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_STRING(1, "addr");
  JERRYXX_CHECK_ARG_NUMBER(2, "port");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(3, "callback");

  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);

  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {

    JERRYXX_GET_ARG_STRING_AS_CHAR(1, addr_str);
    uint16_t port = JERRYXX_GET_ARG_NUMBER(2);
    ip_address_t remote;

    if (socket_resolve (DNS_RESOLVE_TIMEOUT, addr_str, &remote) <  0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
    }
    else {
      jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_RADDR, addr_str);
      jerryxx_set_property_number(socket_map[fd].obj, MSTR_NET_SOCKET_RPORT, port);

      if ( (socket_bind    (fd, &remote, port) < 0) ||
           (socket_connect (fd)                < 0) ) {
        jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
      }
      else {
        jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);

        if (JERRYXX_HAS_ARG(3)) {
          jerry_value_t callback = jerry_acquire_value(JERRYXX_GET_ARG(3));
          if (jerry_value_is_function(callback)) {
            jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
            jerry_value_t this_val = jerry_create_undefined();
            jerry_value_t args_p[1] = { errno };
            jerry_call_function(callback, this_val, args_p, 1);
            jerry_release_value(errno);
            jerry_release_value(this_val);
          }

          jerry_release_value(callback);
        }
      }
    }
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_write) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_STRING(1, "string");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(2, "callback");

  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);

  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {

    jerry_size_t len    = jerry_get_string_size(args_p[1]);
    uint8_t*     buffer = calloc(1, len + 1);
    jerry_string_to_char_buffer(args_p[1], (jerry_char_t *)buffer, len);

    if (socket_send (fd, len, buffer) < 0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
    } 
    else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);

      if (JERRYXX_HAS_ARG(2)) {
        jerry_value_t callback = jerry_acquire_value(JERRYXX_GET_ARG(2));
        if (jerry_value_is_function(callback)) {
          jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
          jerry_value_t this_val = jerry_create_undefined();
          jerry_value_t args_p[1] = {errno};
          jerry_call_function(callback, this_val, args_p, 1);
          jerry_release_value(errno);
          jerry_release_value(this_val);
        }
        jerry_release_value(callback);
      }
    }
    free(buffer);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_close) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(1, "callback");

  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);

  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {

    if (socket_close(fd) < 0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
    }
    else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);

      if (JERRYXX_HAS_ARG(1)) {
        jerry_value_t callback = jerry_acquire_value(JERRYXX_GET_ARG(1));
        if (jerry_value_is_function(callback)) {
          jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
          jerry_value_t this_val = jerry_create_undefined();
          jerry_value_t args_p[1] = { errno };
          jerry_call_function(callback, this_val, args_p, 1);
          jerry_release_value(errno);
          jerry_release_value(this_val);
        }
        jerry_release_value(callback);
      }

      socket_map[fd].fd = KALUMA_MAX_SOCKETS;
      jerry_release_value(socket_map[fd].obj);
    }
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_shutdown) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_NUMBER(1, "how");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(2, "callback");
  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);

  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {
    //int8_t how = JERRYXX_GET_ARG_NUMBER(1);

    //if (socket_shutdown(fd, how) < 0) {
    //  jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
    //}
    //else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);

      if (JERRYXX_HAS_ARG(2)) {
        jerry_value_t callback = jerry_acquire_value(JERRYXX_GET_ARG(2));
        if (jerry_value_is_function(callback)) {
          jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
          jerry_value_t this_val = jerry_create_undefined();
          jerry_value_t args_p[1] = { errno };
          jerry_call_function(callback, this_val, args_p, 1);
          jerry_release_value(errno);
          jerry_release_value(this_val);
        }
        jerry_release_value(callback);
      }

      socket_map[fd].fd = KALUMA_MAX_SOCKETS;
      jerry_release_value(socket_map[fd].obj);
    //}
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_network_bind) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_STRING(1, "addr");
  JERRYXX_CHECK_ARG_NUMBER(2, "port");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(3, "callback");

  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);

  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {

    JERRYXX_GET_ARG_STRING_AS_CHAR(1, addr_str);
    uint16_t port = JERRYXX_GET_ARG_NUMBER(2);
    ip_address_t remote;

    if (socket_resolve (DNS_RESOLVE_TIMEOUT, addr_str, &remote) <  0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
    }
    else {
      jerryxx_set_property_string(socket_map[fd].obj, MSTR_NET_SOCKET_RADDR, addr_str);
      jerryxx_set_property_number(socket_map[fd].obj, MSTR_NET_SOCKET_RPORT, port);

      if (socket_bind (fd, &remote, port) < 0) {
        jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
      }
      else {
        jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);

        if (JERRYXX_HAS_ARG(3)) {
          jerry_value_t callback = jerry_acquire_value(JERRYXX_GET_ARG(3));
          if (jerry_value_is_function(callback)) {
            jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
            jerry_value_t this_val = jerry_create_undefined();
            jerry_value_t args_p[1] = { errno };
            jerry_call_function(callback, this_val, args_p, 1);
            jerry_release_value(errno);
            jerry_release_value(this_val);
          }

          jerry_release_value(callback);
        }
      }
    }
  }
  return jerry_create_undefined();

}

JERRYXX_FUN(net_network_listen) {
  JERRYXX_CHECK_ARG_NUMBER(0, "fd");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(1, "callback");

  int8_t fd = JERRYXX_GET_ARG_NUMBER(0);

  if ( (fd < 0) || (fd >= KALUMA_MAX_SOCKETS) || (socket_map[fd].fd >= KALUMA_MAX_SOCKETS) ) {
    if (socket_listen (fd) < 0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, -1);
    }
    else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);

      if (JERRYXX_HAS_ARG(1)) {
        jerry_value_t callback = jerry_acquire_value(JERRYXX_GET_ARG(1));
        if (jerry_value_is_function(callback)) {
          jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_NETWORK_ERRNO, 0);
          jerry_value_t this_val = jerry_create_undefined();
          jerry_value_t args_p[1] = { errno };
          jerry_call_function(callback, this_val, args_p, 1);
          jerry_release_value(errno);
          jerry_release_value(this_val);
        }

        jerry_release_value(callback);
      }
    }
  }
  return jerry_create_undefined();
}

jerry_value_t module_net_init() {
  for (int i = 0; i < KALUMA_MAX_SOCKETS; i++) {
    socket_map[i].fd = ~0;
    socket_map[i].obj = 0;
  }

  socket_callbacks.callback_connected = socket_connected_implementation;
  socket_callbacks.callback_received  = socket_received_implementation;
  socket_callbacks.callback_accepted  = socket_accepted_implementation;
  socket_callbacks.callback_closed    = socket_closed_implementation;

  jerry_value_t net_network_ctor = jerry_create_external_function(net_network_ctor_fn);
  jerry_value_t network_prototype = jerry_create_object();
  jerryxx_set_property(net_network_ctor, "prototype", network_prototype);
  jerryxx_set_property_function(network_prototype,
                                MSTR_NET_NETWORK_SOCKET,
                                net_network_socket);
  jerryxx_set_property_function(network_prototype, MSTR_NET_NETWORK_GET,
                                net_network_get);
  jerryxx_set_property_function(network_prototype,
                                MSTR_NET_NETWORK_CONNECT,
                                net_network_connect);
  jerryxx_set_property_function(network_prototype,
                                MSTR_NET_NETWORK_WRITE,
                                net_network_write);
  jerryxx_set_property_function(network_prototype,
                                MSTR_NET_NETWORK_CLOSE,
                                net_network_close);
  jerryxx_set_property_function(network_prototype,
                                MSTR_NET_NETWORK_SHUTDOWN,
                                net_network_shutdown);
  jerryxx_set_property_function(network_prototype, MSTR_NET_NETWORK_BIND,
                                net_network_bind);
  jerryxx_set_property_function(network_prototype,
                                MSTR_NET_NETWORK_LISTEN,
                                net_network_listen);
  jerry_release_value(network_prototype);

  /* pico_cyw43 module exports */
  jerry_value_t exports = jerry_create_object();
  jerryxx_set_property(exports, MSTR_NET_SOCKET,
                       net_network_ctor);
  jerry_release_value(net_network_ctor);

  return exports;
}
