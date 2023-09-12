#pragma once

#include <stdlib.h>

void bytes_to_string(const uint8_t* input, uint8_t len, char* buffer);
uint8_t string_to_bytes(const char* text, uint8_t* input, const uint8_t len);
uint8_t string_to_ipv4_address(const char* text, ipv4_address_t* address);
uint8_t string_to_ip_address(const char* text, ip_address_t* address);
