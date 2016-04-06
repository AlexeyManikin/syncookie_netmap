//
// Created by root on 05.04.16.
//

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <boost/thread.hpp>

// Boost libs
#include <lib/parser/packet_parser.h>
#include <netinet/ip.h>

#include "ip.h"

void initialize_ehhdr(u_int8_t* src_mac, u_int8_t* dst_mac, struct ether_header *eh)
{
    bcopy(src_mac, eh->ether_shost, 6);
    bcopy(dst_mac, eh->ether_dhost, 6);
    eh->ether_type = htons(ETHERTYPE_IP);
}


/* Compute the checksum of the given ip header. */
static  uint16_t checksum(const void *data, uint16_t len, uint32_t sum)
{
    const uint8_t *addr = (uint8_t *)data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    return (uint16_t) sum;
}

static  u_int16_t wrapsum(u_int32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons((uint16_t) sum));
}

void initialize_iphdr(uint32_t src, uint32_t dst, int l4size, struct iphdr *ip, u_int8_t ipproto)
{
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = IPTOS_LOWDELAY;
    ip->tot_len = ntohs(l4size - sizeof(struct ether_header));
    ip->id = 0;
    ip->frag_off = htons(IP_DF);
    ip->ttl      = 126;
    ip->protocol = ipproto;
    ip->saddr = htonl(src);
    ip->daddr = htonl(dst);
    ip->check = wrapsum(checksum(ip, sizeof(*ip), 0));
}

