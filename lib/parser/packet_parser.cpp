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

// TCP flags
#define TH_FIN_MULTIPLIER   0x01
#define TH_SYN_MULTIPLIER   0x02
#define TH_RST_MULTIPLIER   0x04
#define TH_PUSH_MULTIPLIER  0x08
#define TH_ACK_MULTIPLIER   0x10
#define TH_URG_MULTIPLIER   0x20

#define __LITTLE_ENDIAN_BITFIELD /* FIX */

struct tcphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u_int16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    u_int16_t doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#else
    //#error "Adjust your <asm/byteorder.h> defines"
#endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct udphdr {
    u_int16_t source;
    u_int16_t dest;
    u_int16_t len;
    u_int16_t check;
};


struct opttimes {
    u_int32_t timestamp_send;
    u_int32_t timestamp_reserved;
};

struct optmss {
    uint16_t mss;
};


#define __LITTLE_ENDIAN_BITFIELD /* FIX */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    u_int8_t ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    u_int8_t version : 4, ihl : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
#define IP_CE 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_MSS              2       /* Segment size negotiating */
#define TCPOPT_WINDOW           3       /* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define TCPOPT_MD5SIG           19      /* MD5 Signature (RFC2385) */
#define TCPOPT_FASTOPEN         34      /* Fast open (RFC7413) */
#define TCPOPT_EXP              254     /* Experimental */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_MD5SIG         18
#define TCPOLEN_FASTOPEN_BASE  2
#define TCPOLEN_EXP_FASTOPEN_BASE  4

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED          12
#define TCPOLEN_WSCALE_ALIGNED          4
#define TCPOLEN_SACKPERM_ALIGNED        4
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_BASE_ALIGNED       4
#define TCPOLEN_SACK_PERBLOCK           8
#define TCPOLEN_MD5SIG_ALIGNED          20
#define TCPOLEN_MSS_ALIGNED             4

#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */

#define NO_TUNNEL_ID 0xFFFFFFFF

#define NEXTHDR_HOP 0
#define NEXTHDR_TCP 6
#define NEXTHDR_UDP 17
#define NEXTHDR_IPV6 41
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_ESP 50
#define NEXTHDR_AUTH 51
#define NEXTHDR_ICMP 58
#define NEXTHDR_NONE 59
#define NEXTHDR_DEST 60
#define NEXTHDR_MOBILITY 135


int parse_pkt(unsigned char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */)
{
    struct ethhdr* eh = (struct ethhdr*)pkt;
    u_int32_t displ = 0, ip_len;
    u_int16_t analyzed = 0, fragment_offset = 0;

    memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest,   sizeof(eh->h_dest));
    memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

    hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
    hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;
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
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset
                                                             + (tcp->doff * 4);

        hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
        hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
        hdr->extended_hdr.parsed_pkt.tcp.flags =  (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER)
                                                  + (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER)
                                                  + (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

        if (hdr->extended_hdr.parsed_pkt.tcp.flags == 2 /*SYN*/
            || hdr->extended_hdr.parsed_pkt.tcp.flags == 16 /*ASK*/)
        {
            char* tcp_begin = (char *) &pkt[hdr->extended_hdr.parsed_pkt.offset.l4_offset];

            hdr->extended_hdr.parsed_pkt.tcp.options.nop    = 0;
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
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset
                                                             + sizeof(struct udphdr);
        analyzed = 4;

        if (level < 5) return analyzed;
    } else {
        hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
        hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;
    }

    return analyzed;
}



