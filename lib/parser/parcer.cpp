//
// Created by root on 29.03.16.
//

#include <sys/types.h> // For support uint32_t, uint16_t
//#include <sys/time.h> // gettimeofday
//#include <stdint.h>
//#include <stdlib.h>
//#include <netinet/in.h> // in6_addr
//#include <net/ethernet.h>
//#include <string.h> // memcpy
//#include <stdio.h>
//#include <arpa/inet.h> // inet_ntop
//#include <sys/types.h>
//#include <stdint.h>
//#include <arpa/inet.h>
//#include <stdlib.h> // atoi
//#include <netinet/in.h>
//#include <sys/ioctl.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <unistd.h>
//#include <netdb.h>
//#include <net/if.h>
//#include <sys/socket.h>
//#include <fstream>
//#include <iostream>
//#include <boost/asio.hpp>


#include "parcer.h"
//#include "packet_parser.h"
//#include "parcer_helper.h"

bool parse_raw_packet_to_packet_header(u_char *buffer, int len, pfring_pkthdr &packet_header)
{
    packet_header.len = (u_int32_t) len;
    packet_header.caplen = (u_int32_t) len;
    parse_pkt(buffer, &packet_header, 4);

    if (packet_header.extended_hdr.parsed_pkt.ip_version != 4)
        return false;

    return true;
}
