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
#include <port/wifi.h>
#include <string.h>
#include <ctype.h>

#include "err.h"
#include "jerryscript.h"
#include "jerryxx.h"
#include "system.h"
#include "wifi_magic_strings.h"
#include "../net/module_tools.h"

#define WIFI_CONNECT_TIMEOUT    20
#define WIFI_SCAN_TIMEOUT       10

typedef struct wifi_info_s {
  char ssid[33];
  uint8_t bssid[6];
} wifi_info_t;

typedef struct scan_data_s {
  wifi_info_t info;
  wifi_authentication auth_mode;
  int rssi;
  uint8_t channel;
  struct scan_data_s *next;
} scan_data_t;

scan_data_t*  scan_results = NULL;

static int min(const int left, const int right) {
    return (left >= right ? right : left);
}

static void wifi_report_implementation (const char* ssid, const uint8_t bssid[6], const wifi_authentication auth, const uint8_t channel, const int strength) {
  scan_data_t* new_node = (scan_data_t *) malloc(sizeof(scan_data_t));
  if (new_node != NULL) {
    new_node->next = NULL;
    strncpy(new_node->info.ssid, ssid, sizeof(((scan_data_t*)0)->info.ssid)-1);
    memcpy(new_node->info.bssid, bssid, sizeof(((scan_data_t*)0)->info.bssid));
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

static void wifi_link_implementation (const char* ssid, const uint8_t bssid[6], const bool connected) {
  if (connected == false) {
    printf("Connected to %s.\n\r", ssid);
  }
  else {
    printf("Disconnected from  %s.\n\r", ssid);
  }
}

JERRYXX_FUN(net_wifi_ctor_fn) {
  jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
  return jerry_create_undefined();
}

JERRYXX_FUN(net_wifi_reset) {
  JERRYXX_CHECK_ARG_FUNCTION_OPT(0, "callback");
  if (wifi_reset()) {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO,
                                -1);
  } else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO,
                                0);
  }
  if (JERRYXX_HAS_ARG(0)) {
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t reset_js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(
        JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
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
    int ret = wifi_scan(WIFI_SCAN_TIMEOUT);
    if (ret < 0) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO,
                                  -1);
      jerry_value_t errno = jerryxx_get_property_number(
          JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, -1);
      jerry_value_t this_val = jerry_create_undefined();
      jerry_value_t args_p[1] = {errno};
      jerry_call_function(scan_js_cb, this_val, args_p, 1);
      jerry_release_value(errno);
      jerry_release_value(this_val);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO,
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
      char* selected;

      while (current) {
        jerry_value_t obj = jerry_create_object();

        jerryxx_set_property_string(obj, MSTR_WIFI_SCANINFO_SSID, current->info.ssid);

        bytes_to_string(current->info.bssid, 6, buffer);
        jerryxx_set_property_string(obj, MSTR_WIFI_SCANINFO_BSSID, buffer);

        if ((current->auth_mode & (WIFI_AUTH_WPA | WIFI_AUTH_WPA2)) == (WIFI_AUTH_WPA | WIFI_AUTH_WPA2)) {
          selected = "WPA2_WPA_PSK";
        } else if (current->auth_mode & WIFI_AUTH_WPA2) {
          selected = "WPA2_PSK";
        } else if (current->auth_mode & WIFI_AUTH_WPA) {
          selected = "WPA_PSK";
        } else if (current->auth_mode & WIFI_AUTH_WEP_PSK) {
          selected = "WEP_PSK";
        } else if (current->auth_mode == WIFI_AUTH_OPEN) {
          selected = "OPEN";
        } else {
          selected = "-"; // Unknown
        }
        jerryxx_set_property_string(obj, MSTR_WIFI_SCANINFO_SECURITY, selected);
        jerryxx_set_property_number(obj, MSTR_WIFI_SCANINFO_RSSI, current->rssi);
        jerryxx_set_property_number(obj, MSTR_WIFI_SCANINFO_CHANNEL, current->channel);
        jerry_value_t ret = jerry_set_property_by_index(scan_array, index++, obj);
        jerry_release_value(ret);
        jerry_release_value(obj);
        scan_data_t* remove = current;
        current = current->next;
        free(remove);
      }
      jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
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
  jerry_value_t ssid = jerryxx_get_property(connect_info, MSTR_WIFI_SCANINFO_SSID);
  jerry_value_t bssid = jerryxx_get_property(connect_info, MSTR_WIFI_SCANINFO_BSSID);

  if (!jerry_value_is_string(ssid) && !jerry_value_is_string(bssid)) {
    result = jerry_create_error(JERRY_ERROR_TYPE, (const jerry_char_t *)"no SSID/BSSID error");
  }
  else {
    char* buffer = NULL;
    char* pw_str = NULL;
    uint8_t raw_bssid[6];
    jerry_size_t ssid_len = 0;

    if (!jerry_value_is_string(bssid)) {
      memset(raw_bssid, 0, sizeof(raw_bssid));
    }
    else {
      char storage[20];
      jerryxx_string_to_ascii_char_buffer(bssid, (jerry_char_t*) storage, sizeof(storage));
      string_to_bytes(storage, raw_bssid, sizeof(raw_bssid));
    }

    if (jerry_value_is_string(ssid)) {
      ssid_len = min(jerryxx_get_ascii_string_size(ssid), 32);
    }

    jerry_value_t pw = jerryxx_get_property(connect_info, MSTR_WIFI_PASSWORD);

    if (!jerry_value_is_string(pw)) {
      buffer = (char*) malloc(ssid_len + 1);
    }
    else {
      jerry_size_t pw_len = jerryxx_get_ascii_string_size(pw);
      buffer = (char*) malloc(ssid_len + 1 + pw_len + 1);
      pw_str = &(buffer[ssid_len + 1]);
      jerryxx_string_to_ascii_char_buffer(pw, (jerry_char_t*) pw_str, pw_len);
      pw_str[pw_len] = '\0';
    }
    if (ssid_len > 0) {
      jerryxx_string_to_ascii_char_buffer(ssid, (jerry_char_t*) buffer, ssid_len); 
    }
    buffer[ssid_len] = '\0';

    jerry_release_value(bssid);
    jerry_release_value(ssid);
    jerry_release_value(pw);

    int connect_ret = wifi_connect(WIFI_CONNECT_TIMEOUT, buffer, raw_bssid, WIFI_AUTH_UNKNOWN, pw_str);

    // Lets wait till we are connected or for a time-out..


    free(buffer);

    if (connect_ret) {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, -1);
    } else {
      jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
      jerry_value_t connect_js_cb = jerryxx_get_property(JERRYXX_GET_THIS, MSTR_WIFI_CONNECT_CB);
      jerry_value_t assoc_js_cb = jerryxx_get_property(JERRYXX_GET_THIS, MSTR_WIFI_ASSOC_CB);
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
        JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
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
    jerry_value_t disconnect_js_cb = jerryxx_get_property(JERRYXX_GET_THIS, MSTR_WIFI_DISCONNECT_CB);
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
    if (jerry_value_is_function(disconnect_js_cb)) {
      jerry_value_t this_val = jerry_create_undefined();
      jerry_call_function(disconnect_js_cb, this_val, NULL, 0);
      jerry_release_value(this_val);
    }
    jerry_release_value(disconnect_js_cb);
  } 
  else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, -1);
  }
  if (JERRYXX_HAS_ARG(0)) {
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
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
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, -1);
  }
  else {
    jerryxx_set_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
    jerryxx_set_property_string(obj, MSTR_WIFI_SCANINFO_SSID, (char*) ssid);
    if (bssid != NULL) {
      char buffer[18];
      bytes_to_string(bssid, 6, buffer);
      jerryxx_set_property_string(obj, MSTR_WIFI_SCANINFO_BSSID, "");
    }
  }

  if (JERRYXX_HAS_ARG(0)) {
    jerry_value_t callback = JERRYXX_GET_ARG(0);
    jerry_value_t get_connect_js_cb = jerry_acquire_value(callback);
    jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
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
  jerry_value_t result;
  jerry_value_t ap_info = JERRYXX_GET_ARG(0);

  // validate SSID
  jerry_value_t ssid = jerryxx_get_property(ap_info, MSTR_WIFI_APMODE_SSID);
  if (!jerry_value_is_string(ssid)) {
    result = jerry_create_error(JERRY_ERROR_TYPE, (const jerry_char_t *)"SSID error");
  }
  else {
    jerry_size_t len;
    uint8_t* pw_str = NULL;
    char* str_buffer = NULL;
    ip_address_t gw, mask;

    len = min(jerryxx_get_ascii_string_size(ssid), 32);

    // validate password
    jerry_value_t password = jerryxx_get_property(ap_info, MSTR_WIFI_APMODE_PASSWORD);
    if (!jerry_value_is_string(password)) {
      str_buffer = (char *)malloc(len + 1);
    }
    else {
      jerry_size_t pw_len = jerryxx_get_ascii_string_size(password);
      str_buffer = (char *)malloc(len + 1 + pw_len + 1);
      pw_str = (uint8_t*) &(str_buffer[len + 1]);
      jerryxx_string_to_ascii_char_buffer(password, pw_str, pw_len);
      pw_str[pw_len] = '\0';
    }
    jerry_release_value(password);

    jerryxx_string_to_ascii_char_buffer(ssid, (uint8_t *)str_buffer, len);
    str_buffer[len] = '\0';
    jerry_release_value(ssid);

    // validate Gateway
    jerry_value_t gateway = jerryxx_get_property(ap_info, MSTR_WIFI_APMODE_GATEWAY);
    if (jerry_value_is_string(gateway)) {
      len = jerryxx_get_ascii_string_size(gateway);
      char storage[16];
      jerryxx_string_to_ascii_char_buffer(gateway, (uint8_t*) storage, sizeof(storage));
      storage[sizeof(storage)-1] = '\0';
      if (string_to_ip_address(storage, &gw) == false) {
        result = jerry_create_error(JERRY_ERROR_COMMON, (const jerry_char_t *)"Can't decode Gateway IP Address");
      }
      else {
        jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_WIFI_APMODE_GATEWAY, storage);
      }
    } 
    else {
      gw.ipv4.addr = 0xC0A80401;
      SET_IPV4(gw);
      jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_WIFI_APMODE_GATEWAY, "192.168.4.1");
    }
    jerry_release_value(gateway);

    // validate subnet mask
    jerry_value_t subnet_mask = jerryxx_get_property(ap_info, MSTR_WIFI_APMODE_SUBNET_MASK);
    if (jerry_value_is_string(subnet_mask)) {
      len = jerryxx_get_ascii_string_size(subnet_mask);
      char storage[16];
      jerryxx_string_to_ascii_char_buffer(subnet_mask, (uint8_t*) storage, sizeof(storage));
      storage[sizeof(storage)-1] = '\0';
      if (string_to_ip_address(storage, &mask) == false) {
        result = jerry_create_error(JERRY_ERROR_COMMON, (const jerry_char_t *)"Can't decode Subnet Mask");
      }
      else {
        jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_WIFI_APMODE_SUBNET_MASK, storage);
      }
    } 
    else {
      mask.ipv4.addr = 0xFFFFFF00;
      SET_IPV4(mask);
      jerryxx_set_property_string(JERRYXX_GET_THIS, MSTR_WIFI_APMODE_SUBNET_MASK, "255.255.255.0");
    }
    jerry_release_value(subnet_mask);

    if (wifi_access_point(str_buffer, (char*) pw_str, &gw, &mask) != 0) {
      result = jerry_create_undefined();
    }
    else {
      result = jerry_create_undefined();

      if (JERRYXX_HAS_ARG(1)) {
        // call callback
        jerry_value_t callback = JERRYXX_GET_ARG(1);
        jerry_value_t js_cb = jerry_acquire_value(callback);
        jerry_value_t errno = jerryxx_get_property_number(JERRYXX_GET_THIS, MSTR_WIFI_ERRNO, 0);
        jerry_value_t this_val = jerry_create_undefined();
        jerry_value_t args_p[1] = {errno};
        jerry_call_function(js_cb, this_val, args_p, 1);
        jerry_release_value(errno);
        jerry_release_value(this_val);
        jerry_release_value(js_cb);
      }
    }
    free(str_buffer);
    jerry_release_value(ssid);
  }

  return result;
}

JERRYXX_FUN(net_wifi_disable_ap_mode) {

  wifi_access_point(NULL, NULL, NULL, NULL);
  return jerry_create_undefined();
}

// Function to get the MAC address of connected clients
JERRYXX_FUN(net_wifi_ap_get_stas) {
  const char* ssid;
  const uint8_t* bssid;

  wifi_status(&ssid, &bssid);
  jerry_value_t MAC_array = jerry_create_array (1);
  for (int i = 0; i < 1; i++) {
    char macAddress[20];
    
    bytes_to_string(bssid, 6, macAddress);

    // add to the array
    jerry_value_t prop = jerry_create_string((const jerry_char_t *)macAddress);
    jerry_release_value(jerry_set_property_by_index(MAC_array, i, prop));
    jerry_release_value(prop);
  }

  // return the list of macs
  return MAC_array;
}

jerry_value_t module_wifi_init() {
  wifi_callbacks.callback_report = wifi_report_implementation;
  wifi_callbacks.callback_link = wifi_link_implementation;

  /* net wifi class */
  jerry_value_t net_wifi_ctor =
      jerry_create_external_function(net_wifi_ctor_fn);
  jerry_value_t wifi_prototype = jerry_create_object();
  jerryxx_set_property(net_wifi_ctor, "prototype", wifi_prototype);
  jerryxx_set_property_function(wifi_prototype, MSTR_WIFI_RESET,
                                net_wifi_reset);
  jerryxx_set_property_function(wifi_prototype, MSTR_WIFI_SCAN,
                                net_wifi_scan);
  jerryxx_set_property_function(wifi_prototype, MSTR_WIFI_CONNECT,
                                net_wifi_connect);
  jerryxx_set_property_function(wifi_prototype, MSTR_WIFI_DISCONNECT,
                                net_wifi_disconnect);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_WIFI_GET_CONNECTION,
                                net_wifi_get_connection);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_WIFI_APMODE_FN,
                                net_wifi_ap_mode);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_WIFI_APMODE_GET_STAS_FN,
                                net_wifi_ap_get_stas);
  jerryxx_set_property_function(wifi_prototype,
                                MSTR_WIFI_APMODE_DISABLE_FN,
                                net_wifi_disable_ap_mode);
  // jerryxx_set_property_function(wifi_prototype, MSTR_GETGPIO,
  //                              net_get_gpio);
  // jerryxx_set_property_function(wifi_prototype, MSTR_PUTGPIO,
  //                              net_put_gpio);
  jerry_release_value(wifi_prototype);

  /* pico_cyw43 module exports */
  jerry_value_t exports = jerry_create_object();
  jerryxx_set_property(exports, MSTR_WIFI, net_wifi_ctor);
  jerry_release_value(net_wifi_ctor);

  return exports;
}
