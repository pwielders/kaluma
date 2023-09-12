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

#ifndef __NET_MAGIC_STRINGS_H
#define __NET_MAGIC_STRINGS_H

#define MSTR_NET_NET "net"
#define MSTR_NET_WIFI "wifi"

#define MSTR_NET_NETWORK_ERRNO "errno"
#define MSTR_NET_NETWORK_MAC "mac"
#define MSTR_NET_NETWORK_IP "ip"
#define MSTR_NET_NETWORK_SOCKET "socket"
#define MSTR_NET_NETWORK_GET "get"
#define MSTR_NET_NETWORK_CONNECT "connect"
#define MSTR_NET_NETWORK_WRITE "write"
#define MSTR_NET_NETWORK_CLOSE "close"
#define MSTR_NET_NETWORK_SHUTDOWN "shutdown"
#define MSTR_NET_NETWORK_BIND "bind"
#define MSTR_NET_NETWORK_LISTEN "listen"

#define MSTR_NET_SOCKET_FD "fd"
#define MSTR_NET_SOCKET_PTCL "ptcl"
#define MSTR_NET_SOCKET_STATE "state"
#define MSTR_NET_SOCKET_LADDR "laddr"
#define MSTR_NET_SOCKET_LPORT "lport"
#define MSTR_NET_SOCKET_RADDR "raddr"
#define MSTR_NET_SOCKET_RPORT "rport"
#define MSTR_NET_SOCKET_CONNECT_CB "connect_cb"
#define MSTR_NET_SOCKET_CLOSE_CB "close_cb"
#define MSTR_NET_SOCKET_READ_CB "read_cb"
#define MSTR_NET_SOCKET_ACCEPT_CB "accept_cb"
#define MSTR_NET_SOCKET_SHUTDOWN_CB "shutdown_cb"

#define MSTR_NET_WIFI_ERRNO "errno"
#define MSTR_NET_WIFI_ASSOC_CB "assoc_cb"
#define MSTR_NET_WIFI_CONNECT_CB "connect_cb"
#define MSTR_NET_WIFI_DISCONNECT_CB "disconnect_cb"
#define MSTR_NET_WIFI_RESET "reset"
#define MSTR_NET_WIFI_SCAN "scan"
#define MSTR_NET_WIFI_CONNECT "connect"
#define MSTR_NET_WIFI_DISCONNECT "disconnect"
#define MSTR_NET_WIFI_GET_CONNECTION "get_connection"

#define MSTR_NET_WIFI_SCANINFO_BSSID "bssid"
#define MSTR_NET_WIFI_SCANINFO_SSID "ssid"
#define MSTR_NET_WIFI_SCANINFO_SECURITY "security"
#define MSTR_NET_WIFI_SCANINFO_RSSI "rssi"
#define MSTR_NET_WIFI_SCANINFO_CHANNEL "channel"

/* AP_mode strings */
#define MSTR_NET_WIFI_APMODE_FN "ap_mode"
#define MSTR_NET_WIFI_APMODE_DISABLE_FN "disable_ap_mode"

#define MSTR_NET_WIFI_APMODE_SSID "ssid"
#define MSTR_NET_WIFI_APMODE_PASSWORD "password"
#define MSTR_NET_WIFI_APMODE_GATEWAY "gateway"
#define MSTR_NET_WIFI_APMODE_SUBNET_MASK "subnet_mask"
#define MSTR_NET_WIFI_APMODE_GET_STAS_FN "get_clients"

#define MSTR_NET_WIFI_PASSWORD "password"
#
#endif /* __NET_MAGIC_STRINGS_H */

#if 0

#define MSTR_NET_PICO_CYW43 "PicoCYW43"
#define MSTR_NET_GETGPIO "getGpio"
#define MSTR_NET_PUTGPIO "putGpio"

#define MSTR_NET_PICO_CYW43_WIFI "PicoCYW43WIFI"
#define MSTR_NET_PICO_CYW43_NETWORK "PicoCYW43Network"
#endif 
