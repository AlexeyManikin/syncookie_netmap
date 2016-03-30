#ifndef PFRING_PACKET_PARSER_H
#define PFRING_PACKET_PARSER_H

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

#if defined(__APPLE__)
// For Mac OS X here we can find definition of "struct timeval"
#include <sys/time.h>
#endif

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
    struct in6_addr v6; /* IPv6 src/dst IP addresses (Network byte order) */
    u_int32_t v4; /* IPv4 src/dst IP addresses */
} ip_addr;

/* GPRS Tunneling Protocol */
typedef struct {
    u_int32_t tunnel_id; /* GTP/GRE tunnelId or NO_TUNNEL_ID for no filtering */
    u_int8_t tunneled_proto;
    ip_addr tunneled_ip_src, tunneled_ip_dst;
    u_int16_t tunneled_l4_src_port, tunneled_l4_dst_port;
} tunnel_info;

typedef struct {
  uint8_t kind;
  uint8_t size;
} tcp_option_t;

struct  tcp_options {
    /*      PAWS/RTTM data  */
    long    ts_recent_stamp;/* Time we stored ts_recent (for aging) */
    u_int8_t  nop;
    __u32     ts_recent;      /* Time stamp to echo next              */
    __u32     rcv_tsval;      /* Time stamp value                     */
    __u32     rcv_tsecr;      /* Time stamp echo reply                */
    __u16     saw_tstamp : 1, /* Saw TIMESTAMP on last packet         */
              tstamp_ok : 1,  /* TIMESTAMP seen on SYN packet         */
              dsack : 1,      /* D-SACK is scheduled                  */
              wscale_ok : 1,  /* Wscale seen on SYN packet            */
              sack_ok : 4,    /* SACK seen on SYN packet              */
              snd_wscale : 4, /* Window scaling received from sender  */
              rcv_wscale : 4; /* Window scaling to send to receiver   */
    __u8      num_sacks;      /* Number of SACK blocks                */
    __u16     user_mss;       /* mss requested by user in ioctl       */
};


struct pkt_parsing_info {
    /* Core fields (also used by NetFlow) */
    u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN]; /* MAC src/dst addresses */
    u_int16_t eth_type; /* Ethernet type */
    u_int16_t vlan_id; /* VLAN Id or NO_VLAN */
    u_int8_t ip_version;
    u_int8_t l3_proto, ip_tos; /* Layer 3 protocol/TOS */
    u_int8_t ip_fragmented; /* Layer 3 fragmentation flag */
    u_int16_t ip_total_size; /* Total size of IP packet */ 
    u_int8_t ip_ttl; /* TTL flag */
    ip_addr ip_src, ip_dst; /* IPv4 src/dst IP addresses */
    u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
    struct {
        u_int8_t flags; /* TCP flags (0 if not available) */
        u_int32_t seq_num, ack_num; /* TCP sequence number */
        struct tcp_options options;
    } tcp;

    struct {
        u_int8_t type;		/* message type */
        u_int8_t code;		/* type sub-code */
    } icmp;

    tunnel_info tunnel;
    u_int16_t last_matched_plugin_id; /* If > 0 identifies a plugin to that matched the packet */
    u_int16_t last_matched_rule_id; /* If > 0 identifies a rule that matched the packet */
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
    u_int32_t flags;
    /* --- short header ends here --- */
    u_int8_t rx_direction; /* 1=RX: packet received by the NIC, 0=TX: packet transmitted by the NIC
                              */
    int32_t if_index; /* index of the interface on which the packet has been received.
                         It can be also used to report other information */
    u_int32_t pkt_hash; /* Hash based on the packet header */
    struct {
        int bounce_interface; /* Interface Id where this packet will bounce after processing
                                 if its values is other than UNKNOWN_INTERFACE */
        struct sk_buff* reserved; /* Kernel only pointer */
    } tx;
    u_int16_t parsed_header_len; /* Extra parsing data before packet */

    /* NOTE: leave it as last field of the memset on parse_pkt() will fail */
    struct pkt_parsing_info parsed_pkt; /* packet parsing info */
};


/* NOTE: Keep 'struct pfring_pkthdr' in sync with 'struct pcap_pkthdr' */
struct pfring_pkthdr {
    /* pcap header */
    struct timeval ts; /* time stamp */
    u_int32_t caplen; /* length of portion present */
    u_int32_t len; /* length of whole packet (off wire) */
    struct pfring_extended_pkthdr extended_hdr; /* PF_RING extended header */
};

struct icmphdr
{
    u_int8_t type;		/* message type */
    u_int8_t code;		/* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t	id;
            u_int16_t	sequence;
        } echo;			/* echo datagram */
        u_int32_t	gateway;	/* gateway address */
        struct
        {
            u_int16_t	__unused;
            u_int16_t	mtu;
        } frag;			/* path mtu discovery */
    } un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#ifdef __cplusplus
extern "C" {
#endif

// Prototypes
int fastnetmon_parse_pkt(unsigned char* pkt,
                         struct pfring_pkthdr* hdr,
                         u_int8_t level /* L2..L4, 5 (tunnel) */,
                         u_int8_t add_timestamp /* 0,1 */,
                         u_int8_t add_hash /* 0,1 */);
char* etheraddr2string(const u_char* ep, char* buf);
int fastnetmon_print_parsed_pkt(char* buff, u_int buff_len, const struct pfring_pkthdr* h) ;

#ifdef __cplusplus
}
#endif

#endif
