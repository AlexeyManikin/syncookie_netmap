//
// Created by root on 05.04.16.
//

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <boost/thread.hpp>

// Boost libs
#include <lib/parser/packet_parser.h>
//#include <netinet/ip.h>

#include "tcp.h"

// thanx to http://seclists.org/lists/bugtraq/1999/Mar/0057.html
struct tcp_pseudo /*the tcp pseudo header*/
{
    __u32 src_addr;
    __u32 dst_addr;
    __u8  zero;
    __u8  proto;
    __u16 length;
} pseudohead;

u_int16_t tcp_checksum(unsigned short *addr, unsigned int count)
{
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     */
    register long sum = 0;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += * addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if( count > 0 )
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (u_int16_t) ~sum;
}

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

u_int16_t get_tcp_checksum(struct iphdr* myip, struct tcphdr* mytcp)
{
    u_int16_t total_len = ntohs((uint16_t) myip->tot_len);

    int tcpopt_len = mytcp->doff*4 - 20;
    int tcpdatalen = total_len - (mytcp->doff*4) - (myip->ihl*4);

    pseudohead.src_addr=myip->saddr;
    pseudohead.dst_addr=myip->daddr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(struct tcphdr) + tcpopt_len + tcpdatalen);

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + tcpopt_len + tcpdatalen;
    unsigned short tcp[totaltcp_len];
    memset(tcp, 0, totaltcp_len);

    std::memcpy((unsigned char *) tcp, &pseudohead,
                sizeof(struct tcp_pseudo));
    std::memcpy((unsigned char *) tcp+sizeof(struct tcp_pseudo),
                (unsigned char *)mytcp,
                sizeof(struct tcphdr));
    std::memcpy((unsigned char *) tcp+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr),
                (unsigned char *) myip+(myip->ihl*4)+(sizeof(struct tcphdr)),
                (size_t) tcpopt_len);
    std::memcpy((unsigned char *) tcp+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr)+tcpopt_len,
                (unsigned char *) mytcp+(mytcp->doff*4),
                (size_t) tcpdatalen);

    return tcp_checksum(tcp, (unsigned int) totaltcp_len);
}

void initialize_tcphdr(struct tcphdr *tcp, u_int16_t sport, u_int16_t dport, uint32_t ack_seq, uint32_t seq)
{
    tcp->source = ntohs((uint16_t) sport);
    tcp->dest   = ntohs((uint16_t) dport);
    tcp->seq = ntohl(seq);
    tcp->ack_seq = ntohl(ack_seq + 1);

    tcp->res1 = 0;
    tcp->doff = 11;
    tcp->fin = 0;
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;

    tcp->syn = 0;
    tcp->ack = 0;

    tcp->window = ntohs(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;
}

