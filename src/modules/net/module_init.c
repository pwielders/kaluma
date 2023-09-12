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

jerry_value_t module_net_init() {
  /* PICO_CYW43 class */
  jerry_value_t net_ctor =
      jerry_create_external_function(net_ctor_fn);
  jerry_value_t prototype = jerry_create_object();
  jerryxx_set_property(net_ctor, "prototype", prototype);
  jerryxx_set_property_function(prototype, MSTR_NET_GETGPIO,
                                net_get_gpio);
  jerryxx_set_property_function(prototype, MSTR_NET_PUTGPIO,
                                net_put_gpio);
  jerry_release_value(prototype);

  jerry_value_t net_wifi_ctor =
      jerry_create_external_function(net_wifi_ctor_fn);
  jerry_value_t wifi_prototype = jerry_create_object();
  jerryxx_set_property(net_wifi_ctor, "prototype", wifi_prototype);
  jerryxx_set_property_function(wifi_prototype, MSTR_NET_WIFI_RESET,
                                net_wifi_reset);
  jerryxx_set_property_function(wifi_prototype, MSTR_NET_WIFI_SCAN,
                                net_wifi_scan);
  jerryxx_set_property_function(wifi_prototype, MSTR_NET_WIFI_CONNECT,
                                net_wifi_connect);
  jerryxx_set_property_function(wifi_prototype, MSTR_NET_WIFI_DISCONNECT,
                                net_wifi_disconnect);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_NET_WIFI_GET_CONNECTION,
                                net_wifi_get_connection);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_NET_WIFI_APMODE_FN,
                                net_wifi_ap_mode);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_NET_WIFI_APMODE_GET_STAS_FN,
                                net_wifi_ap_get_stas);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_NET_WIFI_APMODE_DISABLE_FN,
                                net_wifi_disable_ap_mode);
  jerry_release_value(wifi_prototype);

  jerry_value_t net_network_ctor =
      jerry_create_external_function(net_network_ctor_fn);
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
  jerryxx_set_property(exports, MSTR_NET_PICO_CYW43, net_ctor);
  jerryxx_set_property(exports, MSTR_NET_PICO_CYW43_WIFI,
                       net_wifi_ctor);
  jerryxx_set_property(exports, MSTR_NET_PICO_CYW43_NETWORK,
                       net_network_ctor);
  jerry_release_value(net_ctor);
  jerry_release_value(net_wifi_ctor);
  jerry_release_value(net_network_ctor);

  return exports;
}
