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
#include <ctype.h>

void bytes_to_string(const uint8_t* input, uint8_t len, char* buffer) {
  static const char hex_array[] = "0123456789ABCDEF";
  for (uint8_t index = 0; index < len; index++) {
    buffer[(index * 3) + 0] = hex_array[input[index] >> 4];
    buffer[(index * 3) + 1] = hex_array[input[index] & 0x0F];
    buffer[(index * 3) + 2] = ':';
  }
  buffer[(len * 3) - 1 ] = '\0';
}

static uint8_t convert(const char element) {
  if (isdigit(element)) {
    return (element - '0');
  }
  else if (isxdigit(element)) {
    return (toupper(element) - 'A' + 10);
  }
  return (0xFF);
}

uint8_t string_to_bytes(const char* text, uint8_t* input, const uint8_t len) {
  uint8_t index  = 0;
  uint8_t loaded = 0;
  while ((text[index] != '\0') && (text[index+1] != '\0') && (loaded < len)) {
    input[loaded++] = (convert(text[index]) << 4) | convert(text[index + 1]);
    index += ( ((text[index+2] == '\0') || (isxdigit((uint8_t) text[index+2]))) ? 2 : 3 );
  }
  return (loaded);
}

uint8_t string_to_ipv4_address(const char* text, ipv4_address_t* address)
{
  const char* location = text;
  uint32_t value = 0;
  uint8_t  dot = 8;
    
  while (isdigit((uint8_t) *location)) {
    uint8_t base = 10;

    /* Determine the base, 0x=hex (16), 0=octal (8), 1-9=decimal (10). */
    if (*location == '0') {
      ++location;
      if (toupper(*location) != 'X') {
        base = 8;
      }
      else {
        base = 16;
        ++location;
      }
    }
    
    /* Determine the actual value */ 
    for(;;) {
      uint8_t digit = (uint8_t) *location;
      uint8_t entry = (isdigit(digit) ? (digit - '0') : (isxdigit(digit) ? (digit - (islower(digit) ? 'a' : 'A') + 10) : 0xFF));
      
      if (entry >= base) {
      	break;
      }
      else {
        uint32_t old = value;
        value = (value * base) + entry;
        
        if (old > value) {
          // Oops the number does not fit 32 bits..
          break;
        }
        ++location;
      }
    }
 
    /* Seems we can not handle it anymore, lets see if we hit a delimiter */    
    if (*location == '.') {
      /* Check if the segmentations still fits...
       * Internet formats:
       *  a.b.c.d (a/b/c/d 8 bits)
       *  a.b.c   (a/b 8 bits, c 16 bits)
       *  a.b     (a 8 bits, b 24 bits)
       */
       if (value < (1 << dot)) {
         dot += 8;
         ++location;
       }  
    }
  }
  if ((dot > 8) && ((*location == '\0') || (*location == ':') ||(isspace((uint8_t) *location)))) { 
    address->addr = value;
    return (*location - *text);
  }
  return (0);
}

uint8_t string_to_ip_address(const char* text, ip_address_t* address)
{
  if ( (text != NULL) && (address != NULL)) {
    uint8_t index = 0;
    while ((text[index] != 0) && (text[index] != ':') && (text[index] != '.')) {
      ++index;
    }

    if (text[index] == ':') {
      /* it is detected as an IPv6 address */
      /* to be implemented!!! */
      // SET_IPV6(*addr);
      // return string_to_ipv6_address(text, &(address->ipv6));
    }
    else if (text[index] == '.') {
      /* it is detected as an IPv4 address */
      SET_IPV4(*addr);
      return string_to_ipv4_address(text, &(address->ipv4));
    }
  }
  return 0;
}
