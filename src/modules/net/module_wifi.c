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

typedef struct scan_data_s {
  char ssid[33];
  uint8_t bssid[6];
  wifi_authentication auth_mode;
  int rssi;
  uint8_t channel;
  struct scan_data_s *next;
} scan_data_t;

scan_data_t*  scan_results = NULL;

void bytes_to_string(const uint8_t* input, uint8_t len, char* buffer) {
  static const char hex_array[] = "0123456789ABCDEF";

  for (uint8_t index = 0; index < len; index++) {
    buffer[(index * 3) + 0] = hex_array[input[index] >> 4];
    buffer[(index * 3) + 1] = hex_array[input[index] & 0x0F];
    buffer[(index * 3) + 2] = ':';
  }
  buffer[(len * 3) - 1 ] = '\0';
}

JERRYXX_FUN(net_ctor_fn) {
  return jerry_create_undefined();
}

void wifi_report_implementation (const char* ssid, const uint8_t bssid[6], const wifi_authentication auth, const uint8_t channel, const int strength) {
  scan_data_t* new_node = (scan_data_t *) malloc(sizeof(scan_data_t));
  if (new_node != NULL) {
    new_node->next = NULL;
    strncpy(new_node->ssid, ssid, sizeof(((scan_data_t*)0)->ssid));
    memcpy(new_node->bssid, bssid, sizeof(((scan_data_t*)0)->bssid));
    new_node->rssi = strength;
    new_node->channel = channel;
    new_node->auth_mode = auth;
    if (scan_results == NULL) {
      scan_results = new_node;
    }
    else {
      scan_data_t* current = scan_results;
      while (current->next != NULL) {
        current = current->next;
      }
      current->next = new_node;
    }
  }
}

static void initialize() {
  static bool initialized = false;
  if (initialized == false) {
    initialized = true;
    wifi_callbacks.callback_report = wifi_report_implementation;
  }
}

JERRYXX_FUN(net_wifi_ctor_fn) {
  jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
  return jerry_create_undefined();
}

JERRYXX_FUN(net_wifi_reset) {
  JERRYXX_CHECK_ARG_FUNCTION_OPT(0, "callback");
  if (wifi_reset()) {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO,
                                -1);
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO,
                                0);
  }
  if (JERRYXX_HAS_ARG(0)) {
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t reset_js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(reset_js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(reset_js_cb);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_wifi_scan) {
  JERRYXX_CHECK_ARG_FUNCTION_OPT(0, "callback");
  if (JERRYXX_HAS_ARG(0)) {  // Do nothing if callback is NULL
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t scan_js_cb = jerry_acquire_value(callback);
    int ret = wifi_scan();
    if (ret < 0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO,
                                  -1);
      jerry_value_t errno = jerryxx_get_property_number(
          JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, -1);
      jerry_value_t this_val = jerry_create_undefined();
      jerry_value_t args_p[1] = {errno};
      jerry_call_function(scan_js_cb, this_val, args_p, 1);
      jerry_release_value(errno);
      jerry_release_value(this_val);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO,
                                  0);

      uint8_t index = 0;
      scan_data_t* current = scan_results;
      while (current != NULL) {
        current = current->next;
        index++;
      }
 
      jerry_value_t scan_array = jerry_create_array(index);

      current = scan_results;
      index = 0;
      char  buffer[33];
      const char* selected;

      while (current) {
        jerry_value_t obj = jerry_create_object();

        jerryxx_set_property_string(obj, MSTR_NET_SCANINFO_SSID, current->ssid);

        bytes_to_string(current->bssid, 6, buffer);
        jerryxx_set_property_string(obj, MSTR_NET_SCANINFO_BSSID, buffer);

        if ((current->auth_mode & (CYW43_WIFI_AUTH_WPA | CYW43_WIFI_AUTH_WPA2)) == (CYW43_WIFI_AUTH_WPA | CYW43_WIFI_AUTH_WPA2)) {
          selected = "WPA2_WPA_PSK";
        } else if (current->auth_mode & CYW43_WIFI_AUTH_WPA2) {
          selected = "WPA2_PSK";
        } else if (current->auth_mode & CYW43_WIFI_AUTH_WPA) {
          selected = "WPA_PSK";
        } else if (current->auth_mode & CYW43_WIFI_AUTH_WEP_PSK) {
          selected = "WEP_PSK";
        } else if (current->auth_mode == CYW43_WIFI_AUTH_OPEN) {
          selected = "OPEN";
        } else {
          selecetd = "-"; // Unknown
        }
        jerryxx_set_property_string(obj, MSTR_NET_SCANINFO_SECURITY, selected);
        jerryxx_set_property_number(obj, MSTR_NET_SCANINFO_RSSI, current->rssi);
        jerryxx_set_property_number(obj, MSTR_NET_SCANINFO_CHANNEL, current->channel);
        jerry_value_t ret = jerry_set_property_by_index(scan_array, index++, obj);
        jerry_release_value(ret);
        jerry_release_value(obj);
        scan_data_t* remove = current;
        current = current->next;
        free(remove);
      }
      jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
      jerry_value_t this_val = jerry_create_undefined();
      jerry_value_t args_p[2] = {errno, scan_array};
      jerry_call_function(scan_js_cb, this_val, args_p, 2);
      jerry_release_value(errno);
      jerry_release_value(this_val);
      jerry_release_value(scan_js_cb);
      jerry_release_value(scan_array);
    }
    scan_results = NULL;
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_wifi_connect) {
  jerry_value_t result;

  JERRYXX_CHECK_ARG(0, "connectInfo");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(1, "callback");
  jerry_value_t connect_info = JERRYXX_GET_ARG(0);
  jerry_value_t ssid = jerryxx_get_property(connect_info, MSTR_NET_SCANINFO_SSID);

  if (!jerry_value_is_string(ssid)) {
    jerry_release_value(ssid);
    result = jerry_create_error(JERRY_ERROR_TYPE, (const jerry_char_t *)"SSID error");
  }
  else {
    char* buffer = NULL;
    char* pw_str = NULL;
    jerry_size_t ssid_len = std::min(jerryxx_get_ascii_string_size(ssid), 32);
    jerry_value_t pw = jerryxx_get_property(connect_info, MSTR_NET_PASSWORD);

    if (!jerry_value_is_string(pw)) {
      buffer = (char*) malloc(ssid_len + 1);
    }
    else {
      jerry_size_t pw_len = jerryxx_get_ascii_string_size(pw);
      buffer = (char*) malloc(ssid_len + 1 + pw_len + 1);
      pw_str = buffer[ssid_len + 1];
      jerryxx_string_to_ascii_char_buffer(pw, pw_str, pw_len);
      pw_str[pw_len] = '\0';
    }
    jerryxx_string_to_ascii_char_buffer(ssid, buffer, ssid_len); 
    buffer[ssid_len] = '\0';

    jerry_release_value(ssid);
    jerry_release_value(pw);

    int connect_ret = wifi_connect_timeout_ms(buffer, pw_str, -1, CONNECT_TIMEOUT);
    free(buffer);

    if (connect_ret) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, -1);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
      jerry_value_t connect_js_cb = jerryxx_get_property(JERRYXX_GET_THIS, MSTR_NET_WIFI_CONNECT_CB);
      jerry_value_t assoc_js_cb = jerryxx_get_property(JERRYXX_GET_THIS, MSTR_NET_WIFI_ASSOC_CB);
      jerry_value_t this_val = jerry_create_undefined();
      if (jerry_value_is_function(assoc_js_cb)) {
        jerry_call_function(assoc_js_cb, this_val, NULL, 0);
      }
      if (jerry_value_is_function(connect_js_cb)) {
        jerry_call_function(connect_js_cb, this_val, NULL, 0);
      }
      jerry_release_value(connect_js_cb);
      jerry_release_value(this_val);
      jerry_release_value(assoc_js_cb);
    }
    if (JERRYXX_HAS_ARG(1)) {
      jerry_value_t callback = JERRYXX_GET_ARG(1);
      jerry_value_t connect_js_cb = jerry_acquire_value(callback);
      jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
      jerry_value_t this_val = jerry_create_undefined();
      jerry_value_t args_p[1] = {errno};
      jerry_call_function(connect_js_cb, this_val, args_p, 1);
      jerry_release_value(errno);
      jerry_release_value(this_val);
      jerry_release_value(connect_js_cb);
    }
    result = jerry_create_undefined();
  }
  return result;
}

JERRYXX_FUN(net_wifi_disconnect) {
  JERRYXX_CHECK_ARG_FUNCTION_OPT(0, "callback");
  int disconnect_ret = wifi_disconnect();
  if (disconnect_ret == 0) {
    jerry_value_t disconnect_js_cb = jerryxx_get_property(JERRYXX_GET_THIS, MSTR_NET_WIFI_DISCONNECT_CB);
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
    if (jerry_value_is_function(disconnect_js_cb)) {
      jerry_value_t this_val = jerry_create_undefined();
      jerry_call_function(disconnect_js_cb, this_val, NULL, 0);
      jerry_release_value(this_val);
    }
    jerry_release_value(disconnect_js_cb);
  } 
  else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, -1);
  }
  if (JERRYXX_HAS_ARG(0)) {
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }
  return jerry_create_undefined();
}

JERRYXX_FUN(net_wifi_get_connection) {
  JERRYXX_CHECK_ARG_FUNCTION_OPT(0, "callback");
  jerry_value_t obj = jerry_create_object();
  const char* ssid = NULL;
  const uint8_t* bssid = NULL;
  wifi_status(&ssid, &bssid);
  if (ssid == NULL) {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, -1);
  }
  else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
    jerryxx_set_property_string(obj, MSTR_NET_SCANINFO_SSID, ssid);
    if (bssid != NULL) {
      char buffer[18];
      bytes_to_string(bssid, 6, buffer);
      jerryxx_set_property_string(obj, MSTR_NET_SCANINFO_BSSID, "");
    }
  }

  if (JERRYXX_HAS_ARG(0)) {
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t get_connect_js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    if (ssid != NULL) {
      jerry_value_t args_p[2] = {errno, obj};
      jerry_call_function(get_connect_js_cb, this_val, args_p, 2);
    } else {
      jerry_value_t args_p[1] = {errno};
      jerry_call_function(get_connect_js_cb, this_val, args_p, 1);
    }
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(get_connect_js_cb);
  }
  jerry_release_value(obj);
  return jerry_create_undefined();
}

/*
  AP Mode
*/

JERRYXX_FUN(net_wifi_ap_mode) {
  JERRYXX_CHECK_ARG(0, "apInfo");
  JERRYXX_CHECK_ARG_FUNCTION_OPT(1, "callback");
  jerry_value_t ap_info = JERRYXX_GET_ARG(0);
  jerry_size_t len;
  uint8_t *pw_str = NULL;
  uint8_t *str_buffer = NULL;
  ip4_addr_t gw, mask;

  // validate SSID
  jerry_value_t ssid = jerryxx_get_property(ap_info, MSTR_NET_WIFI_APMODE_SSID);
  if (jerry_value_is_string(ssid)) {
    len = jerryxx_get_ascii_string_size(ssid);
    if (len > 32) {
      len = 32;
    }
    jerryxx_string_to_ascii_char_buffer(
        ssid, (uint8_t *)__cyw43_drv.current_ssid, len);
    __cyw43_drv.current_ssid[len] = '\0';
  } else {
    jerry_release_value(ssid);
    return jerry_create_error(JERRY_ERROR_TYPE, (const jerry_char_t *)"SSID error");
  }
  jerry_release_value(ssid);

  // validate password
  jerry_value_t password = jerryxx_get_property(ap_info, MSTR_NET_WIFI_APMODE_PASSWORD);
  if (jerry_value_is_string(password)) {
    len = jerryxx_get_ascii_string_size(password);
    if (len < 8) {
      jerry_release_value(password);
      return jerry_create_error(JERRY_ERROR_COMMON, (const jerry_char_t *)"PASSWORD need to have at least 8 characters");
    }
    pw_str = (uint8_t *)malloc(len + 1);
    jerryxx_string_to_ascii_char_buffer(password, pw_str, len);
    pw_str[len] = '\0';
  }
  jerry_release_value(password);

  // validate Gateway
  jerry_value_t gateway = jerryxx_get_property(ap_info, MSTR_NET_WIFI_APMODE_GATEWAY);
  if (jerry_value_is_string(gateway)) {
    len = jerryxx_get_ascii_string_size(gateway);
    str_buffer = (uint8_t *)malloc(len + 1);
    jerryxx_string_to_ascii_char_buffer(gateway, str_buffer, len);
    str_buffer[len] = '\0';
    if (ipaddr_aton((const char *)str_buffer, &(gw)) == false) {
      free(pw_str);
      free(str_buffer);
      jerry_release_value(gateway);
      return jerry_create_error(JERRY_ERROR_COMMON,
                                (const jerry_char_t *)"Can't decode Gateway IP Address");
    }
    jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_WIFI_APMODE_GATEWAY,
                                (char *)str_buffer);
  } else {
    IP4_ADDR(&gw, 192, 168, 4, 1);
    jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_WIFI_APMODE_GATEWAY,
                                "192.168.4.1");
  }
  free(str_buffer);
  jerry_release_value(gateway);

  // validate subnet mask
  jerry_value_t subnet_mask = jerryxx_get_property(ap_info, MSTR_NET_WIFI_APMODE_SUBNET_MASK);
  if (jerry_value_is_string(subnet_mask)) {
    len = jerryxx_get_ascii_string_size(subnet_mask);
    str_buffer = (uint8_t *)malloc(len + 1);
    jerryxx_string_to_ascii_char_buffer(subnet_mask, str_buffer, len);
    str_buffer[len] = '\0';
    if (ipaddr_aton((const char *)str_buffer, &(mask)) == false) {
      free(pw_str);
      free(str_buffer);
      jerry_release_value(subnet_mask);
      return jerry_create_error(JERRY_ERROR_COMMON,
                                (const jerry_char_t *)"Can't decode Subnet Mask");
    }
    jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_WIFI_APMODE_SUBNET_MASK,
                                (char *)str_buffer);
  } else {
    IP4_ADDR(&mask, 255, 255, 255, 0);
    jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_NET_WIFI_APMODE_SUBNET_MASK,
                                "255.255.255.0");
  }
  free(str_buffer);
  jerry_release_value(subnet_mask);

  // init driver
  if (__cyw43_init()) {
    return jerry_create_error_from_value(create_system_error(EAGAIN), true);
  }

  cyw43_arch_enable_ap_mode((char *) __cyw43_drv.current_ssid, (char *) pw_str, CYW43_AUTH_WPA2_AES_PSK);
  free(pw_str);
  // start DHCP server
	dhcp_server_init(&dhcp_server, &gw, &mask);

  // call callback
  if (JERRYXX_HAS_ARG(1)) {
    jerry_value_t callback = JERRYXX_GET_ARG(1);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_NET_WIFI_ERRNO, 0);
    jerry_value_t this_val = jerry_create_undefined();
    jerry_value_t args_p[1] = {errno};
    jerry_call_function(js_cb, this_val, args_p, 1);
    jerry_release_value(errno);
    jerry_release_value(this_val);
    jerry_release_value(js_cb);
  }

  return jerry_create_undefined();
}

JERRYXX_FUN(net_wifi_disable_ap_mode) {
  // verify if AP_mode is enabled
  int wifi_ap_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_AP);
  if (wifi_ap_status != CYW43_LINK_UP) {
    return jerry_create_error(JERRY_ERROR_COMMON,
                              (const jerry_char_t *)"WiFi AP_mode is not enabled.");
  }

  // deinit DHCP server
  dhcp_server_deinit(&dhcp_server);
  cyw43_arch_deinit();
  /* Reset and power up the WL chip */
  cyw43_hal_pin_low(CYW43_PIN_WL_REG_ON);
  cyw43_delay_ms(20);
  cyw43_hal_pin_high(CYW43_PIN_WL_REG_ON);
  cyw43_delay_ms(50);
  __cyw43_drv.status_flag = KM_CYW43_STATUS_DISABLED;
  // init the WiFi chip
  if (__cyw43_init()) {
    return jerry_create_error_from_value(create_system_error(EAGAIN), true);
  }
  return jerry_create_undefined();
}

// Function to get the MAC address of connected clients
JERRYXX_FUN(net_wifi_ap_get_stas) {
  // verify if AP_mode is enabled
  int wifi_ap_status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_AP);
  if (wifi_ap_status != CYW43_LINK_UP) {
    return jerry_create_error(JERRY_ERROR_COMMON,
                              (const jerry_char_t *)"WiFi AP_mode is not enabled.");
  }

  int num_stas, max_stas, MAC_len = 18;
  // get max stas
  cyw43_wifi_ap_get_max_stas(&cyw43_state, &max_stas);
  // declare
  uint8_t *macs = (uint8_t*)malloc(num_stas * 6);
  jerry_value_t MAC_array = jerry_create_array (num_stas);
  //uint8_t macs[32 * 6];
  cyw43_wifi_ap_get_stas(&cyw43_state, &num_stas, macs);
  char **mac_strs = (char **)malloc(num_stas * sizeof(char *));
  for (int i = 0; i < num_stas; i++) {
    mac_strs[i] = (char *)malloc(MAC_len * sizeof(char));
    sprintf(mac_strs[i], "%02x:%02x:%02x:%02x:%02x:%02x", macs[i*6], macs[i*6+1], macs[i*6+2], macs[i*6+3], macs[i*6+4], macs[i*6+5]);
    // add to the array
    jerry_value_t prop = jerry_create_string((const jerry_char_t *)mac_strs[i]);
    jerry_release_value(jerry_set_property_by_index(MAC_array, i, prop));
    jerry_release_value(prop);
  }
  // deallocate memory
  free(macs);
  // return the list of macs
  return MAC_array;
}

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
