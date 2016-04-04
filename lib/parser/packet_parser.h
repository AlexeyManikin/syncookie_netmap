#ifndef SYNFLOODPROTECT_PACKET_PARSER_H
#define SYNFLOODPROTECT_PACKET_PARSER_H

#include <sys/types.h>
#include <netinet/in.h> // in6_addr

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h> // in6_addr
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h> // in6_addr
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop


#define ETH_ALEN 6

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
    int16_t vlan_offset;
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
    u_int16_t vlan_id;                          /* VLAN Id or NO_VLAN */
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

// Fake fields
#define ipv4_tos ip_tos
#define ipv4_src ip_src.v4
#define ipv4_dst ip_dst.v4

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

#ifdef __cplusplus
extern "C" {
#endif

// Prototypes
int parse_pkt(unsigned char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */);

#ifdef __cplusplus
}
#endif

#endif
