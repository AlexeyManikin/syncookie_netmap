#include "packet_parser.h"

/* This code is copy & paste from PF_RING user space library licensed under LGPL terms */

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h> // in6_addr
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop
#include "be_byteshift.h"
#include "parcer_helper.h"

void parce_tcp_options(char* tcp_begin, struct tcp_options *options)
{
    options->nop = 0;
    options->wscale = 0;

    struct tcphdr*  tcp = (struct tcphdr*) tcp_begin;

    uint8_t* opt = (uint8_t*)(tcp_begin + sizeof(struct tcphdr));
    uint8_t* end_options = (uint8_t*)(tcp_begin + tcp->doff * 4);

    while (*opt != TCPOPT_EOL || (void* ) opt <= (void* ) end_options) {
        tcp_option_t* _opt = (tcp_option_t*)opt;
        if (_opt->kind == TCPOPT_NOP) {
            ++opt;
            options->nop++;
            continue;
        }

        if (_opt->kind == TCPOPT_MSS) {
            options->mss = ntohs((uint16_t)*(opt + sizeof(opt)));
        }

        if (_opt->kind == TCPOPT_WINDOW) {
            options->wscale = *(opt + 2);
        }

        if (_opt->kind == TCPOPT_SACK_PERM) {
            options->wscale = 1;
        }

        if (_opt->kind == TCPOPT_TIMESTAMP) {
            options->timestamp_send = get_unaligned_be32(opt + 2);
            options->timestamp_reserved = get_unaligned_be32(opt + 6);
        }

        opt += _opt->size;
    }
}

int parse_pkt(unsigned char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */)
{
    struct ethhdr* eh = (struct ethhdr*)pkt;
    u_int32_t displ = 0, ip_len;
    u_int16_t analyzed = 0, fragment_offset = 0;

    memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest, sizeof(eh->h_dest));
    memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

    hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
    hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;
    hdr->extended_hdr.parsed_pkt.offset.vlan_offset = 0;
    hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */


    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset
                                                    + displ + sizeof(struct ethhdr);
    analyzed = 2;
    if (level < 3) return analyzed;
    if (hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */) {

        struct iphdr* ip;

        hdr->extended_hdr.parsed_pkt.ip_version = 4;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr))
            return analyzed;

        ip = (struct iphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

        hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
        hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
        hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
        hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
        fragment_offset = ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
        ip_len = ip->ihl * 4;
        hdr->extended_hdr.parsed_pkt.ip_total_size = ntohs(ip->tot_len);

        // Parse fragmentation info:
        // Very good examples about IPv4 flags: http://lwn.net/Articles/136319/
        hdr->extended_hdr.parsed_pkt.ip_fragmented = 0;
        hdr->extended_hdr.parsed_pkt.ip_ttl = ip->ttl;

        int fast_frag_off = ntohs(ip->frag_off);
        int fast_offset = (fast_frag_off & IP_OFFSET);

        if (fast_frag_off & IP_MF) {
            hdr->extended_hdr.parsed_pkt.ip_fragmented = 1;
        }

        if (fast_offset != 0) {
            hdr->extended_hdr.parsed_pkt.ip_fragmented = 1;
        }
    } else {
        hdr->extended_hdr.parsed_pkt.l3_proto = 0;
        return analyzed;
    }

    hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len;
    analyzed = 3;
    if (level < 4 || fragment_offset) return analyzed;

    if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_ICMP) {
        struct icmphdr* icmp;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct icmphdr))
            return analyzed;

        icmp = (struct icmphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.icmp.code = icmp->code;
        hdr->extended_hdr.parsed_pkt.icmp.type = icmp->type;

        analyzed = 4;

    } else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
        struct tcphdr* tcp;

        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr))
            return analyzed;

        tcp = (struct tcphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source);
        hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
        hdr->extended_hdr.parsed_pkt.offset.payload_offset =
                                                    hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);

        hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
        hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
        hdr->extended_hdr.parsed_pkt.tcp.flags =
        (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) + (tcp->rst * TH_RST_MULTIPLIER) +
        (tcp->psh * TH_PUSH_MULTIPLIER) + (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

        if (hdr->extended_hdr.parsed_pkt.tcp.flags == 2 || hdr->extended_hdr.parsed_pkt.tcp.flags == 16 ) {
            char* tcp_begin = (char *) &pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset];

            hdr->extended_hdr.parsed_pkt.tcp.options.nop = 0;
            hdr->extended_hdr.parsed_pkt.tcp.options.wscale = 0;

            uint8_t* opt = (uint8_t*)(tcp_begin + sizeof(struct tcphdr));

            u_int16_t counter = 0;
            while (*opt != TCPOPT_EOL) {
                if (counter++ > 20) {
                    break;
                }

                tcp_option_t* _opt = (tcp_option_t*)opt;
                if (_opt->kind == TCPOPT_NOP) {
                    ++opt;
                    hdr->extended_hdr.parsed_pkt.tcp.options.nop++;
                    continue;
                } else if (_opt->kind == TCPOPT_MSS) {
                    struct optmss* mss_struct = (struct optmss*) &(opt[2]);
                    hdr->extended_hdr.parsed_pkt.tcp.options.mss = ntohs(mss_struct->mss);
                } else if (_opt->kind == TCPOPT_WINDOW) {
                    hdr->extended_hdr.parsed_pkt.tcp.options.wscale = *(opt + 2);
                } else if (_opt->kind == TCPOPT_SACK_PERM) {
                    hdr->extended_hdr.parsed_pkt.tcp.options.saksp = 1;
                } else if (_opt->kind == TCPOPT_TIMESTAMP) {
                    struct opttimes* time_struct = (struct opttimes*) &(opt[2]);
                    hdr->extended_hdr.parsed_pkt.tcp.options.timestamp_send     = ntohl(time_struct->timestamp_send);
                    hdr->extended_hdr.parsed_pkt.tcp.options.timestamp_reserved = ntohl(time_struct->timestamp_reserved);
                }
                opt += _opt->size;
            }
        }
        analyzed = 4;
    } else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
        struct udphdr* udp;
        if (hdr->caplen < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr))
            return analyzed;

        udp = (struct udphdr*)(&pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

        hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source),
        hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
        hdr->extended_hdr.parsed_pkt.offset.payload_offset =
        hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);
        analyzed = 4;

        if (level < 5) return analyzed;
    } else {
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
        hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;
    }

    return analyzed;
}



