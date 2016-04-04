//
// Created by root on 29.03.16.
//

#ifndef SYNFLOODPROTECT_PARCER_H
#define SYNFLOODPROTECT_PARCER_H

#include <sys/types.h>
#include <netinet/in.h> // in6_addr

#include <utility> // std::pair
#include <stdint.h> // uint32_t
#include <sys/time.h> // struct timeval
#include <netinet/in.h> // struct in6_addr

#include <string>
#include <map>
#include <vector>

#include "packet_parser.h"

bool parse_raw_packet_to_packet_header(u_char *buffer, int len, pfring_pkthdr &packet_header);

#endif //SYNFLOODPROTECT_PARCER_H
