//
// Created by root on 29.03.16.
//

#include <sys/types.h> // For support uint32_t, uint16_t
#include "parcer.h"

bool parse_raw_packet_to_packet_header(u_char *buffer, int len, pfring_pkthdr &packet_header)
{
    packet_header.len =    (u_int32_t) len;
    packet_header.caplen = (u_int32_t) len;
    parse_pkt(buffer, &packet_header, 4);

    if (packet_header.extended_hdr.parsed_pkt.ip_version != 4)
        return false;

    return true;
}
