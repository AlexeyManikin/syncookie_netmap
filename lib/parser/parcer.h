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

#include "fastnetmon_packet_parser.h"

enum direction { INCOMING = 0, OUTGOING, INTERNAL, OTHER };

// simplified packet struct for lightweight save into memory
class simple_packet {
public:
    simple_packet()
            : sample_ratio(1), src_ip(0), dst_ip(0), source_port(0), destination_port(0), protocol(0),
              length(0), flags(0), number_of_packets(1), ip_fragmented(false), ip_protocol_version(4), ttl(0),
              packet_payload_pointer(NULL), packet_payload_length(0), packet_direction(OTHER) {

        ts.tv_usec = 0;
        ts.tv_sec = 0;
    }
    uint32_t sample_ratio;
    /* IPv4 */
    uint32_t src_ip;
    uint32_t dst_ip;
    /* IPv6 */
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
    uint8_t ip_protocol_version; /* IPv4 or IPv6 */
    uint8_t ttl;
    uint16_t source_port;
    uint16_t destination_port;
    unsigned int protocol;
    uint64_t length;
    uint64_t number_of_packets; /* for netflow */
    uint8_t flags; /* tcp flags */
    bool ip_fragmented; /* If IP packet fragmented */
    struct timeval ts;
    void* packet_payload_pointer;
    int packet_payload_length;
    // We store packet direction here because direction calculation is very difficult task for cpu
    direction packet_direction;
};

int extract_bit_value(uint8_t num, int bit);
std::string get_printable_protocol_name(unsigned int protocol);
std::string print_tcp_flags(uint8_t flag_value);
std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer);
bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet& packet);

#endif //SYNFLOODPROTECT_PARCER_H
