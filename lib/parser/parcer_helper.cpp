//
// Created by root on 05.04.16.
//

#include <sys/types.h> // For support uint32_t, uint16_t
#include <stdint.h>
#include <netinet/in.h> // in6_addr
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop

#include <fstream>
#include <iostream>
#include <boost/asio.hpp>

#include "parcer_helper.h"
#include "packet_parser.h"

std::string get_printable_protocol_name(unsigned int protocol)
{
    std::string proto_name;

    switch (protocol) {
        case IPPROTO_TCP:
            proto_name = "tcp";
            break;
        case IPPROTO_UDP:
            proto_name = "udp";
            break;
        case IPPROTO_ICMP:
            proto_name = "icmp";
            break;
        default:
            proto_name = "unknown";
            break;
    }

    return proto_name;
}

std::string print_tcp_flags(uint8_t flag_value)
{
    if (flag_value == 0) {
        return "-";
    }

    std::vector<std::string> all_flags;

    if (extract_bit_value(flag_value, TCP_FIN_FLAG_SHIFT)) {
        all_flags.push_back("fin");
    }

    if (extract_bit_value(flag_value, TCP_SYN_FLAG_SHIFT)) {
        all_flags.push_back("syn");
    }

    if (extract_bit_value(flag_value, TCP_RST_FLAG_SHIFT)) {
        all_flags.push_back("rst");
    }

    if (extract_bit_value(flag_value, TCP_PSH_FLAG_SHIFT)) {
        all_flags.push_back("psh");
    }

    if (extract_bit_value(flag_value, TCP_ACK_FLAG_SHIFT)) {
        all_flags.push_back("ack");
    }

    if (extract_bit_value(flag_value, TCP_URG_FLAG_SHIFT)) {
        all_flags.push_back("urg");
    }

    std::ostringstream flags_as_string;

    if (all_flags.empty()) {
        return "-";
    }

    // concatenate all vector elements with comma
    std::copy(all_flags.begin(), all_flags.end() - 1, std::ostream_iterator<std::string>(flags_as_string, ","));

    // add last element
    flags_as_string << all_flags.back();

    return flags_as_string.str();
}

std::string convert_ip_as_uint_to_string(uint32_t ip_as_integer)
{
    struct in_addr ip_addr;
    ip_addr.s_addr = ip_as_integer;
    return (std::string)inet_ntoa(ip_addr);
}

// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit)
{
    if (bit > 0 && bit <= 8) {
        return ((num >> (bit - 1)) & 1);
    } else {
        return 0;
    }
}

// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int check_bit_value(uint8_t num, int bit)
{
    if (bit > 0 && bit <= 8) {
        return ((num >> (bit - 1)) & num);
    } else {
        return 0;
    }
}

char* etheraddr2string(const u_char* ep, char* buf) {
    char* hex = (char* ) "0123456789ABCDEF";
    u_int i, j;
    char* cp;

    cp = buf;
    if ((j = *ep >> 4) != 0)
        *cp++ = hex[j];
    else
        *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];

    for (i = 5; (int)--i >= 0;) {
        *cp++ = ':';
        if ((j = *ep >> 4) != 0)
            *cp++ = hex[j];
        else
            *cp++ = '0';

        *cp++ = hex[*ep++ & 0xf];
    }

    *cp = '\0';
    return (buf);
}

char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
    char* cp, *retStr;
    u_int byte;
    int n;

    cp = &buf[bufLen];
    *--cp = '\0';

    n = 4;
    do {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0) {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0) *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    retStr = (char*)(cp + 1);

    return (retStr);
}


char* intoa(unsigned int addr) {
    static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];
    return (_intoa(addr, buf, sizeof(buf)));
}

char* proto2str(u_short proto) {
    static char protoName[8];

    switch (proto) {
        case IPPROTO_TCP:
            return ((char*) "TCP");
        case IPPROTO_UDP:
            return ((char*) "UDP");
        case IPPROTO_ICMP:
            return ((char*) "ICMP");
        case IPPROTO_GRE:
            return ((char*) "GRE");
        default:
            snprintf(protoName, sizeof(protoName), "%d", proto);
            return (protoName);
    }
}

int print_parsed_pkt(char *buff, u_int buff_len, const struct pfring_pkthdr *h)
{
    char buf1[32], buf2[32];
    int buff_used = 0;

    buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[%s -> %s] ",
                          etheraddr2string((const u_char*) h->extended_hdr.parsed_pkt.smac, buf1),
                          etheraddr2string((const u_char*) h->extended_hdr.parsed_pkt.dmac, buf2));

    if (h->extended_hdr.parsed_pkt.offset.vlan_offset)
        buff_used +=
                snprintf(&buff[buff_used], buff_len - buff_used, "[vlan %u] ", h->extended_hdr.parsed_pkt.vlan_id);

    if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ||
        h->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6*/) {

        if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/) {
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[IPv4][%s:%d ",
                                  intoa(h->extended_hdr.parsed_pkt.ipv4_src),
                                  h->extended_hdr.parsed_pkt.l4_src_port);
            buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "-> %s:%d] ",
                                  intoa(h->extended_hdr.parsed_pkt.ipv4_dst),
                                  h->extended_hdr.parsed_pkt.l4_dst_port);
        }

        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[l3_proto=%s]",
                              proto2str((u_short) h->extended_hdr.parsed_pkt.l3_proto));


        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[ip_fragmented: %d]",
                              h->extended_hdr.parsed_pkt.ip_fragmented);

        buff_used += snprintf(&buff[buff_used], buff_len - buff_used,
                              "[tos=%d][tcp_seq_num=%u]",
                              h->extended_hdr.parsed_pkt.ipv4_tos,
                              h->extended_hdr.parsed_pkt.tcp.seq_num);

    } else {
        buff_used += snprintf(&buff[buff_used], buff_len - buff_used, "[eth_type=0x%04X]",
                              h->extended_hdr.parsed_pkt.eth_type);
    }

    buff_used +=
            snprintf(&buff[buff_used], buff_len - buff_used, " [caplen=%d][len=%d]["
                             "eth_offset=%d][l3_offset=%d][l4_offset=%d]["
                             "payload_offset=%d]\n",
                     h->caplen, h->len,
                     h->extended_hdr.parsed_pkt.offset.eth_offset, h->extended_hdr.parsed_pkt.offset.l3_offset,
                     h->extended_hdr.parsed_pkt.offset.l4_offset, h->extended_hdr.parsed_pkt.offset.payload_offset);

    return buff_used;
}


