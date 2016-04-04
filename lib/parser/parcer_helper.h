//
// Created by root on 05.04.16.
//

#ifndef SYNFLOODPROTECT_PARCER_HELPER_H
#define SYNFLOODPROTECT_PARCER_HELPER_H

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h> // in6_addr
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop
#include <sys/types.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <strings.h>
//#include <fstream>
//#include <iostream>
//#include <boost/asio.hpp>

#include "packet_parser.h"

#define TCP_FIN_FLAG_SHIFT 1
#define TCP_SYN_FLAG_SHIFT 2
#define TCP_RST_FLAG_SHIFT 3
#define TCP_PSH_FLAG_SHIFT 4
#define TCP_ACK_FLAG_SHIFT 5
#define TCP_URG_FLAG_SHIFT 6

std::string get_printable_protocol_name(unsigned int protocol);
std::string print_tcp_flags(uint8_t flag_value);
std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer);
int extract_bit_value(uint8_t num, int bit);
int check_bit_value(uint8_t num, int bit);
int fastnetmon_print_parsed_pkt(char* buff, u_int buff_len, const struct pfring_pkthdr* h);
char* etheraddr2string(const u_char* ep, char* buf);

#endif //SYNFLOODPROTECT_PARCER_HELPER_H
