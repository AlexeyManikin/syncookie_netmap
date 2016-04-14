#ifndef SYNFLOODPROTECT_PACKET_PARSER_H
#define SYNFLOODPROTECT_PACKET_PARSER_H

#include <sys/types.h>
#include <netinet/in.h> // in6_addr

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop

#define ETH_ALEN 6


// Fake fields
#define ipv4_tos ip_tos
#define ipv4_src ip_src.v4
#define ipv4_dst ip_dst.v4

/*
  Note that as offsets *can* be negative,
  please do not change them to unsigned
*/
struct pkt_offset {
    int16_t eth_offset; /*
                           This offset *must* be added to all offsets below
                           ONLY if you are inside the kernel (e.g. when you
                           code a pf_ring plugin). Ignore it in user-space.
                         */
    int16_t l3_offset;
    int16_t l4_offset;
    int16_t payload_offset;
};

typedef union {
    u_int32_t v4; /* IPv4 src/dst IP addresses */
} ip_addr;


typedef struct {
    uint8_t kind;
    uint8_t size;
} tcp_option_t;

struct  tcp_options {
    u_int8_t          nop;
    __u16             mss;
    unsigned char     wscale;
    uint8_t           saksp;
    __u32             saks;
    __u32             timestamp_reserved;
    __u32             timestamp_send;
};

struct pkt_parsing_info {
    /* Core fields (also used by NetFlow) */
    u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN];    /* MAC src/dst addresses */
    u_int16_t eth_type;                         /* Ethernet type */
    u_int8_t ip_version;
    u_int8_t l3_proto, ip_tos;                  /* Layer 3 protocol/TOS */
    u_int8_t ip_fragmented;                     /* Layer 3 fragmentation flag */
    u_int16_t ip_total_size;                    /* Total size of IP packet */
    u_int8_t ip_ttl;                            /* TTL flag */
    ip_addr ip_src, ip_dst;                     /* IPv4 src/dst IP addresses */
    u_int16_t l4_src_port, l4_dst_port;         /* Layer 4 src/dst ports */

    struct {
        u_int8_t flags; /* TCP flags (0 if not available) */
        u_int32_t seq_num, ack_num; /* TCP sequence number */
        struct tcp_options options;
    } tcp;

    struct {
        u_int8_t type;        /* message type */
        u_int8_t code;        /* type sub-code */
    } icmp;

    struct pkt_offset offset; /* Offsets of L3/L4/payload elements */
};

struct pfring_extended_pkthdr {
    u_int64_t timestamp_ns; /* Packet timestamp at ns precision. Note that if your NIC supports
                               hardware timestamp, this is the place to read timestamp from */

#define PKT_FLAGS_CHECKSUM_OFFLOAD 1 << 0 /* IP/TCP checksum offload enabled */
#define PKT_FLAGS_CHECKSUM_OK 1 << 1 /* Valid checksum (with IP/TCP checksum offload enabled) */
#define PKT_FLAGS_IP_MORE_FRAG 1 << 2 /* IP More fragments flag set */
#define PKT_FLAGS_IP_FRAG_OFFSET 1 << 3 /* IP fragment offset set (not 0) */
#define PKT_FLAGS_VLAN_HWACCEL 1 << 4 /* VLAN stripped by hw */
    struct pkt_parsing_info parsed_pkt; /* packet parsing info */
};


/* NOTE: Keep 'struct pfring_pkthdr' in sync with 'struct pcap_pkthdr' */
struct pfring_pkthdr {
    u_int32_t caplen;   /* length of portion present */
    u_int32_t len;      /* length of whole packet (off wire) */
    struct pfring_extended_pkthdr extended_hdr; /* PF_RING extended header */
};

struct icmphdr
{
    u_int8_t type;        /* message type */
    u_int8_t code;        /* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t    id;
            u_int16_t    sequence;
        } echo;            /* echo datagram */
        u_int32_t    gateway;    /* gateway address */
        struct
        {
            u_int16_t    __unused;
            u_int16_t    mtu;
        } frag;            /* path mtu discovery */
    } un;
};

#define ICMP_ECHOREPLY          0    /* Echo Reply            */
#define ICMP_DEST_UNREACH       3    /* Destination Unreachable    */
#define ICMP_SOURCE_QUENCH      4    /* Source Quench        */
#define ICMP_REDIRECT           5    /* Redirect (change route)    */
#define ICMP_ECHO               8    /* Echo Request            */
#define ICMP_TIME_EXCEEDED      11    /* Time Exceeded        */
#define ICMP_PARAMETERPROB      12    /* Parameter Problem        */
#define ICMP_TIMESTAMP          13    /* Timestamp Request        */
#define ICMP_TIMESTAMPREPLY     14    /* Timestamp Reply        */
#define ICMP_INFO_REQUEST       15    /* Information Request        */
#define ICMP_INFO_REPLY         16    /* Information Reply        */
#define ICMP_ADDRESS            17    /* Address Mask Request        */
#define ICMP_ADDRESSREPLY       18    /* Address Mask Reply        */
#define NR_ICMP_TYPES           18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH        0    /* Network Unreachable        */
#define ICMP_HOST_UNREACH       1    /* Host Unreachable        */
#define ICMP_PROT_UNREACH       2    /* Protocol Unreachable        */
#define ICMP_PORT_UNREACH       3    /* Port Unreachable        */
#define ICMP_FRAG_NEEDED        4    /* Fragmentation Needed/DF set    */
#define ICMP_SR_FAILED          5    /* Source Route failed        */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13    /* Packet filtered */
#define ICMP_PREC_VIOLATION     14    /* Precedence violation */
#define ICMP_PREC_CUTOFF        15    /* Precedence cut off */
#define NR_ICMP_UNREACH         15    /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET          0    /* Redirect Net            */
#define ICMP_REDIR_HOST         1    /* Redirect Host        */
#define ICMP_REDIR_NETTOS       2    /* Redirect Net for TOS        */
#define ICMP_REDIR_HOSTTOS      3    /* Redirect Host for TOS    */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL            0    /* TTL count exceeded        */
#define ICMP_EXC_FRAGTIME       1    /* Fragment Reass time exceeded    */



#ifdef __cplusplus
extern "C" {
#endif

// Prototypes
int parse_pkt(unsigned char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */);

#ifdef __cplusplus
}
#endif

#endif
