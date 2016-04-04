#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>

#include <sys/types.h>

// For config map operations
#include <string>
#include <map>
#include <iostream>

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <utility>
#include <sstream>

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/regex.hpp>

// Boost libs
#include <boost/algorithm/string.hpp>
#include <lib/parser/packet_parser.h>
#include <netinet/ip.h>
#include "lib/parser/parcer_helper.h"

#define NETMAP_WITH_LIBS
#include "net/netmap_user.h"
#include "lib/logger/logger.h"
#include "lib/parser/packet_parser.h"
#include "lib/parser/parcer.h"
#include "lib/syncookie/synproxy.h"

#define WAIT_NIC_TIME 4

#define TCP_SYN_FLAG_SHIFT 2
#define TCP_ACK_FLAG_SHIFT 5

// Get log4cpp logger from main program
extern log4cpp::Category& logger;
static int do_not_abort = 1;


static void sigint_h(int sig)
{
    (void)sig;    /* UNUSED */
    logger.error("Receive signal %i", sig);
    do_not_abort = 0;
    signal(SIGINT, SIG_DFL);
}

inline void forward_packet(struct netmap_ring *rx_ring, unsigned int cur)
{
    rx_ring->slot[cur].flags |= NS_FORWARD;
    rx_ring->flags |= NR_FORWARD;
}

void logging_packet_info(struct pfring_pkthdr packet_header)
{
    char buf_src[32], buf_dst[32];
    logger.debug("Received packed len %i, protocol %s\nsource ip %s, dst ip %s\nflags %s, dp %i, sp %i, sednum %u, acknum %u\nmac src %s mac dst %s",
                 packet_header.len, get_printable_protocol_name(packet_header.extended_hdr.parsed_pkt.l3_proto).c_str(),
                 convert_ip_as_uint_to_string(
                         htonl(packet_header.extended_hdr.parsed_pkt.ip_src.v4)).c_str(),
                 convert_ip_as_uint_to_string(
                         htonl(packet_header.extended_hdr.parsed_pkt.ip_dst.v4)).c_str(),
                 print_tcp_flags((uint8_t)packet_header.extended_hdr.parsed_pkt.tcp.flags).c_str(),
                 packet_header.extended_hdr.parsed_pkt.l4_dst_port,
                 packet_header.extended_hdr.parsed_pkt.l4_src_port,
                 (uint32_t) packet_header.extended_hdr.parsed_pkt.tcp.seq_num,
                 (uint32_t) packet_header.extended_hdr.parsed_pkt.tcp.ack_num,
                 etheraddr2string((const u_char*) packet_header.extended_hdr.parsed_pkt.smac, buf_src),
                 etheraddr2string((const u_char*) packet_header.extended_hdr.parsed_pkt.smac, buf_dst));
}

struct pfring_pkthdr get_pached_info(u_char *buf, int len)
{
    struct pfring_pkthdr packet_header;
    std::memset(&packet_header, 0, sizeof(packet_header));
    parse_raw_packet_to_packet_header(buf, len, packet_header);
    return packet_header;
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

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        std::memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        std::memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        std::memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}


static void initialize_iphdr(uint32_t src, uint32_t dst, int l4size, struct iphdr *ip, u_int8_t ipproto)
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
#error "Adjust your <asm/byteorder.h> defines"
#endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

// thanx to http://seclists.org/lists/bugtraq/1999/Mar/0057.html
struct tcp_pseudo /*the tcp pseudo header*/
{
    __u32 src_addr;
    __u32 dst_addr;
    __u8 zero;
    __u8 proto;
    __u16 length;
} pseudohead;

u_int16_t tcp_checksum(unsigned short *addr, unsigned int count) {
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

    return ~sum;
}

u_int16_t get_tcp_checksum(struct iphdr* myip, struct tcphdr* mytcp)
{
    u_int16_t total_len = ntohs(myip->tot_len);

    int tcpopt_len = mytcp->doff*4 - 20;
    int tcpdatalen = total_len - (mytcp->doff*4) - (myip->ihl*4);

    pseudohead.src_addr=myip->saddr;
    pseudohead.dst_addr=myip->daddr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(struct tcphdr) + tcpopt_len + tcpdatalen);

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + tcpopt_len + tcpdatalen;
    unsigned short * tcp = new unsigned short[totaltcp_len];


    memcpy((unsigned char *) tcp,
           &pseudohead,
           sizeof(struct tcp_pseudo));
    memcpy((unsigned char *) tcp+sizeof(struct tcp_pseudo),
           (unsigned char *)mytcp,
           sizeof(struct tcphdr));
    memcpy((unsigned char *) tcp+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr),
           (unsigned char *) myip+(myip->ihl*4)+(sizeof(struct tcphdr)),
           tcpopt_len);
    memcpy((unsigned char *) tcp+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr)+tcpopt_len,
           (unsigned char *) mytcp+(mytcp->doff*4),
           tcpdatalen);

/*      printf("pseud length: %d\n",pseudohead.length);
        printf("tcp hdr length: %d\n",mytcp->doff*4);
        printf("tcp hdr struct length: %d\n",sizeof(struct tcphdr));
        printf("tcp opt length: %d\n",tcpopt_len);
        printf("tcp total+psuedo length: %d\n",totaltcp_len);

        fflush(stdout);

        printf("tcp data len: %d, data start %u\n", tcpdatalen,mytcp + (mytcp->doff*4));
*/


    return tcp_checksum(tcp, totaltcp_len);

}

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

struct opttimes {
    u_int32_t timestamp_send;
    u_int32_t timestamp_reserved;
};

struct sunt8 {
    u_int8_t val;
};

struct sunt16 {
    u_int16_t val;
    u_int16_t val2;
};

struct schar {
    unsigned char val;
    unsigned char val2;
};

static void generate_tcp_options(char* buf, uint16_t mss, u_int32_t timesend, u_int32_t timereserved,
                                  unsigned char wscale, uint8_t sperm)
{
    tcp_option_t* tcp_option = (tcp_option_t*) buf;
    tcp_option->kind = TCPOPT_MSS;
    tcp_option->size = 4;

    struct sunt16* s16 = (struct sunt16*) &(buf[2]);
    s16->val = ntohs(mss);

    if (sperm) {
        tcp_option = (tcp_option_t*) (buf + 4);
        tcp_option->kind = TCPOPT_SACK_PERM;
        tcp_option->size = 2;
    } else {
        tcp_option = (tcp_option_t*) (buf + 4);
        tcp_option->kind = TCPOPT_NOP;
        tcp_option->size = TCPOPT_NOP;
    }

    tcp_option = (tcp_option_t*) (buf + 6);
    tcp_option->kind = TCPOPT_TIMESTAMP;
    tcp_option->size = 10;

    struct opttimes* time_struct = (struct opttimes*) &(buf[8]);
    time_struct->timestamp_send     = ntohl(timesend);
    time_struct->timestamp_reserved = ntohl(timereserved);

    tcp_option = (tcp_option_t*) (buf + 16);
    tcp_option->kind = TCPOPT_WINDOW;
    tcp_option->size = 3;

    struct schar* s8 = (struct schar*) &(buf[18]);
    s8->val = wscale;
}

static void initialize_tcphdr(struct tcphdr *tcp, u_int16_t sport, u_int16_t dport, uint32_t ack_seq, uint32_t seq)
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

static void initialize_ehhdr(u_int8_t* src_mac, u_int8_t* dst_mac, struct ether_header *eh)
{
    bcopy(src_mac, eh->ether_shost, 6);
    bcopy(dst_mac, eh->ether_dhost, 6);
    eh->ether_type = htons(ETHERTYPE_IP);
}

u_int16_t tcp_check_sum(u_int16_t *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)  {
        cksum += *buffer++;
        size  -= sizeof(u_int16_t);
    }
    if(size)
        cksum += *(u_int16_t*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (u_int16_t)(~cksum);
}

uint32_t generate_syncookie_seq(uint16_t mss, unsigned char wscale, uint8_t sperm, u_int32_t ip,
                                uint32_t timestamp)
{
    uint32_t return_val = 0;
    unsigned char *pointer = (unsigned char *) &return_val;
    unsigned char *ip_pointer = (unsigned char *) &ip;
    struct sunt16* s16 = (struct sunt16*) &return_val;
    s16->val = mss;
    s16->val2 = wscale;

    if (sperm) {
        s16->val2 |= 1<<8;
    } else {
        s16->val2 &= ~(1<<8);
    }

    ip = ip<<25;
    return_val |= ip;

    return_val ^= timestamp;
    return return_val;
}

struct cookie_param {
    uint16_t mss;
    unsigned char wscale;
    uint8_t sperm;
};

bool check_syncookie(uint32_t ack_seq, u_int32_t ip, uint32_t timestamp)
{
    ack_seq = ack_seq - 1;
    ack_seq ^= timestamp;
    u_int32_t ip_mask = 127;

    if (ack_seq & ip_mask != ip & ip_mask) {
        return false;
    }

    return true;
}

void get_syncookie_seq(uint32_t ack_seq, u_int32_t ip, uint32_t timestamp, cookie_param* param)
{
    ack_seq = ack_seq - 1;

    ack_seq ^= timestamp;
    u_int32_t ip_mask = 127;

    if (ack_seq & ip_mask != ip & ip_mask) {
        return;
    }

    uint16_t mss;
    unsigned char wscale = 0;
    uint8_t sperm;

    struct sunt16* s16 = (struct sunt16*) &ack_seq;
    if ( s16->val2 & (0X0000 | 1<<8)) {
        sperm = 1;
    } else {
        sperm = 0;
    }

    u_int16_t mask = s16->val2 & 0X00FF;
    wscale = (char) s16->val2 & 0X00FF;

    param->mss = mss;
    param->wscale = wscale;
    param->sperm = sperm;
}

void send_syn_to_host_response(struct netmap_ring *rx_ring, struct pfring_pkthdr *packet_header)
{
    register unsigned int rx_cur;
    char *rx_buf;

    rx_cur   = rx_ring->cur;

    unsigned char* pointer;
    unsigned int size = sizeof(ether_header) + 20 + sizeof(tcphdr)  + 24; /* tcp options */

    pointer = (unsigned char *) std::malloc(size);
    std::memset(pointer, 0, size);

    initialize_ehhdr(packet_header->extended_hdr.parsed_pkt.smac,
                     packet_header->extended_hdr.parsed_pkt.dmac,
                     (struct ether_header *) pointer);

    iphdr* ip;
    ip = (struct iphdr*) &pointer[sizeof(struct ethhdr)];

    initialize_iphdr(packet_header->extended_hdr.parsed_pkt.ip_src.v4,
                     packet_header->extended_hdr.parsed_pkt.ip_dst.v4,
                     size, ip, IPPROTO_TCP);

//
//
//    cookie_param params;
//    get_syncookie_seq(packet_header->extended_hdr.parsed_pkt.tcp.ack_num,
//                      packet_header->extended_hdr.parsed_pkt.ip_src.v4,
//                      packet_header->extended_hdr.parsed_pkt.tcp.options.timestamp_reserved,
//                      &params);


    tcphdr* tcp;
    tcp = (struct tcphdr*) &pointer[sizeof(struct ethhdr) + 20];

    initialize_tcphdr(tcp, packet_header->extended_hdr.parsed_pkt.l4_src_port,
                      packet_header->extended_hdr.parsed_pkt.l4_dst_port,
                      -1,
                      packet_header->extended_hdr.parsed_pkt.tcp.seq_num);

//    generate_tcp_options((char *)(pointer + sizeof(struct ethhdr) + 20 + sizeof(struct tcphdr)),
//                         params.mss, packet_header->extended_hdr.parsed_pkt.tcp.options.timestamp_send,
//                         0, params.wscale, params.sperm);

    tcp->syn = 1;

    tcp->check = get_tcp_checksum(ip, tcp);

    rx_buf = NETMAP_BUF(rx_ring, rx_ring->slot[rx_cur].buf_idx);
    bzero(rx_buf, size);
    nm_pkt_copy(pointer, rx_buf, size);

    logger.debug("\nACK - proxy syn");
    logging_packet_info(get_pached_info((u_char *)rx_buf, size));

    rx_ring->slot[rx_cur].len = (uint16_t) size;
    rx_ring->slot[rx_cur].flags |= NS_BUF_CHANGED;
    rx_ring->slot[rx_cur].flags |= NS_FORWARD;
    rx_ring->flags |= NR_FORWARD;

    free(pointer);
}

bool send_syncookie_response(char *rx_buf, int len, struct netmap_ring *tx_ring, struct pfring_pkthdr *packet_header)
{
    register unsigned int tx_avail, tx_cur;
    char *tx_buf;

    tx_cur   = tx_ring->cur;
    tx_avail = nm_ring_space(tx_ring);

    char *print;
    print = (char *) malloc(999);


    fastnetmon_print_parsed_pkt(print, 999, packet_header);
    logger.debug("%s", print);

    if (tx_avail > 0) {
        unsigned char* pointer;
        unsigned int size = sizeof(ether_header) + 20 + sizeof(tcphdr) + 24; /* tcp options */

        pointer = (unsigned char *) malloc(size);
        std::memset(pointer, 0, size);

        initialize_ehhdr(packet_header->extended_hdr.parsed_pkt.dmac,
                         packet_header->extended_hdr.parsed_pkt.smac,
                         (struct ether_header *) pointer);

        iphdr* ip;
        ip = (struct iphdr*) &pointer[sizeof(struct ethhdr)];

        initialize_iphdr(packet_header->extended_hdr.parsed_pkt.ip_dst.v4,
                         packet_header->extended_hdr.parsed_pkt.ip_src.v4,
                         size, ip, IPPROTO_TCP);

        tcphdr* tcp;
        tcp = (struct tcphdr*) &pointer[sizeof(struct ethhdr) + 20];

        initialize_tcphdr(tcp, packet_header->extended_hdr.parsed_pkt.l4_dst_port,
                          packet_header->extended_hdr.parsed_pkt.l4_src_port,
                          packet_header->extended_hdr.parsed_pkt.tcp.seq_num,
                          1206
                          /*generate_syncookie_seq(packet_header->extended_hdr.parsed_pkt.tcp.options.mss,
                                                 packet_header->extended_hdr.parsed_pkt.tcp.options.wscale,
                                                 packet_header->extended_hdr.parsed_pkt.tcp.options.saksp,
                                                 packet_header->extended_hdr.parsed_pkt.ip_dst.v4,
                                                 packet_header->extended_hdr.parsed_pkt.tcp.options.timestamp_send)*/);

        tcp->syn = 1;
        tcp->ack = 1;

        generate_tcp_options((char *)(pointer + sizeof(struct ethhdr) + 20 + sizeof(struct tcphdr)),
                             1460, /*packet_header->extended_hdr.parsed_pkt.tcp.options.timestamp_send*/ 1206,
                             packet_header->extended_hdr.parsed_pkt.tcp.options.timestamp_send,
                             7, packet_header->extended_hdr.parsed_pkt.tcp.options.saksp);

        tcp->check = get_tcp_checksum(ip, tcp);

        tx_buf = NETMAP_BUF(tx_ring, tx_ring->slot[tx_cur].buf_idx);
        bzero(tx_buf, size);
        nm_pkt_copy(pointer, tx_buf, size);

//        logger.debug("\n SYN SYN/ACK");
//        logging_packet_info(get_pached_info(pointer, size));

        tx_ring->slot[tx_cur].len = (uint16_t) size;
        tx_ring->slot[tx_cur].flags |= NS_BUF_CHANGED;
        tx_ring->head = tx_ring->cur = nm_ring_next(tx_ring, tx_cur);

        free(pointer);
    } else {
        logger.warn("tx not availible");
    }
}

bool send_echo_response(char *rx_buf, int len, struct netmap_ring *tx_ring, struct pfring_pkthdr *packet_header)
{
    register unsigned int tx_avail, tx_cur;
    char *tx_buf;

    tx_cur   = tx_ring->cur;
    tx_avail = nm_ring_space(tx_ring);

    if (tx_avail > 0) {

        unsigned char* pointer;
        unsigned int min_size = sizeof(ether_header) + 20 + sizeof(icmphdr);
        unsigned int size = len;
        unsigned int size_data = size - min_size;

        pointer = (unsigned char *) malloc(size);
        std::memset(pointer, 0, size);

        initialize_ehhdr(packet_header->extended_hdr.parsed_pkt.dmac,
                         packet_header->extended_hdr.parsed_pkt.smac,
                         (struct ether_header *) pointer);

        iphdr* ip;
        ip = (struct iphdr*) &pointer[sizeof(struct ethhdr)];

        initialize_iphdr(packet_header->extended_hdr.parsed_pkt.ip_dst.v4,
                         packet_header->extended_hdr.parsed_pkt.ip_src.v4,
                         size, ip, IPPROTO_ICMP);

        struct icmphdr* responce_icmp;
        responce_icmp = (struct icmphdr*) &pointer[sizeof(struct ethhdr) + 20];

        struct icmphdr* request_icmp;
        request_icmp = (struct icmphdr*)(&rx_buf[packet_header->extended_hdr.parsed_pkt.offset.l4_offset]);

        responce_icmp->type        = 0;
        responce_icmp->code     = 0;
        responce_icmp->checksum = 0;
        responce_icmp->un.echo.id = request_icmp->un.echo.id;
        responce_icmp->un.echo.sequence = request_icmp->un.echo.sequence + 1;
        std::memcpy((void *) &pointer[min_size], (void *) &rx_buf[min_size],  size_data);
        responce_icmp->checksum = ip_checksum(responce_icmp, sizeof(icmphdr)+size_data);

        tx_buf = NETMAP_BUF(tx_ring, tx_ring->slot[tx_cur].buf_idx);
        bzero(tx_buf, size);
        nm_pkt_copy(pointer, tx_buf, size);

        tx_ring->slot[tx_cur].len = (uint16_t) size;
        tx_ring->slot[tx_cur].flags |= NS_BUF_CHANGED;
        tx_ring->head = tx_ring->cur = nm_ring_next(tx_ring, tx_cur);

        free(pointer);
    } else {
        logger.warn("tx not availible");
    }
}

static void rx_nic_thread(struct nm_desc *netmap_description, unsigned int thread_id)
{
    struct pollfd fds;
    struct netmap_ring *rx_ring = NULL;
    struct netmap_ring *tx_ring = NULL;
    register unsigned int rx_cur, tx_cur, rx_len;
    unsigned int tx_avail;
    char *rx_buf, *tx_buf;

    struct netmap_if* nifp = netmap_description->nifp;

    fds.fd     = netmap_description->fd;
    fds.events = POLLIN;

    while (do_not_abort) {

        int poll_result = poll(&fds, 1, 1000);
        if (poll_result == 0)
            continue;

        if (poll_result < 0) {
            logger.error("poll() return <0 value theread %i", thread_id);
            exit(3);
        }

        for (int i = netmap_description->first_rx_ring; i <= netmap_description->last_rx_ring; i++) {
            rx_ring = NETMAP_RXRING(nifp, i);

            while (!nm_ring_empty(rx_ring)) {
                rx_cur = rx_ring->cur;
                rx_buf = NETMAP_BUF(rx_ring, rx_ring->slot[rx_cur].buf_idx);
                rx_len = rx_ring->slot[rx_cur].len;

                struct pfring_pkthdr packet_header;
                std::memset(&packet_header, 0, sizeof(packet_header));
                u_int8_t flags = 0;

                if (!parse_raw_packet_to_packet_header((u_char *) rx_buf, rx_len, packet_header)) {
                    forward_packet(rx_ring, rx_cur);
                } else {
                    tx_ring = NETMAP_TXRING(nifp, i);

                    if (packet_header.extended_hdr.parsed_pkt.l3_proto == IPPROTO_ICMP
                        || packet_header.extended_hdr.parsed_pkt.l4_dst_port == 7) {

                        if (packet_header.extended_hdr.parsed_pkt.icmp.type == 8) {
                            send_echo_response(rx_buf, rx_len, tx_ring, &packet_header);
                        } else if (packet_header.extended_hdr.parsed_pkt.icmp.type == 0) {
                            forward_packet(rx_ring, rx_cur);
                        }
                    } else if (packet_header.extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
                        flags = packet_header.extended_hdr.parsed_pkt.tcp.flags;

                        if (flags == 2 /*TCP_SYN_FLAG*/) {
                            send_syncookie_response(rx_buf, rx_len, tx_ring, &packet_header);
                        } else if (flags == 16 /*TCP_ACK_FLAG*/) {
//                            if (check_syncookie(packet_header.extended_hdr.parsed_pkt.tcp.ack_num,
//                                                packet_header.extended_hdr.parsed_pkt.l4_src_port,
//                                                packet_header.extended_hdr.parsed_pkt.tcp.options.timestamp_reserved))
                            if (packet_header.extended_hdr.parsed_pkt.l4_dst_port == 22) {
                                if (packet_header.extended_hdr.parsed_pkt.tcp.ack_num == 1207
                                    && packet_header.extended_hdr.parsed_pkt.tcp.options.timestamp_reserved == 1206) {
                                    send_syn_to_host_response(rx_ring, &packet_header);
                                } else {
                                    forward_packet(rx_ring, rx_cur);
                                }
                            } else {
                                forward_packet(rx_ring, rx_cur);
                            }
                        } else {
                            forward_packet(rx_ring, rx_cur);
                        }

                    } else {
                        forward_packet(rx_ring, rx_cur);
                    }
                }

                rx_ring->head = rx_ring->cur = nm_ring_next(rx_ring, rx_cur);
            }
        }
    }
}

void create_main_work_pool(std::string interface_for_listening)
{
    struct nm_desc* netmap_descriptor;

    struct nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));

    // Magic from pkt-gen.c
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    std::string interface = "";
    std::string system_interface_name = "";

    system_interface_name = interface_for_listening;
    interface = "netmap:" + interface_for_listening;

    logger.warn("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off",
                system_interface_name.c_str());

    netmap_descriptor = nm_open(interface.c_str(), &base_nmd, 0, NULL);

    if (netmap_descriptor == NULL) {
        logger.error("Can't open netmap device %s", interface.c_str());
        exit(1);
    }

    logger.info("We have %d tx and %d rx rings", netmap_descriptor->req.nr_tx_rings,
                                                 netmap_descriptor->req.nr_rx_rings);

    logger.info("Wait %d seconds for NIC reset", WAIT_NIC_TIME);
    sleep(WAIT_NIC_TIME);

    boost::thread_group packet_nic_rx_thread_group;

    // Обрабатываем сигналы завершения для закрытия netmap
    signal(SIGINT, sigint_h);
    signal(SIGTERM, sigint_h);

    for (uint16_t i = 0; i < netmap_descriptor->req.nr_rx_rings; i++) {

        struct nm_desc params_descriptor = *netmap_descriptor;
        params_descriptor.self = &params_descriptor;

        uint64_t nmd_flags = 0;
        if (params_descriptor.req.nr_flags != NR_REG_ALL_NIC) {
            logger.error("Main descriptor of interface %s should be with NR_REG_ALL_NIC flag", interface.c_str());
        }

        params_descriptor.req.nr_flags = NR_REG_ONE_NIC;
        params_descriptor.req.nr_ringid = i;

        struct nm_desc* one_nic_ring_netmap_descriptor = nm_open(interface.c_str(), NULL,
                                                                 nmd_flags | NM_OPEN_NO_MMAP | NM_OPEN_IFNAME,
                                                                 &params_descriptor);

        if (one_nic_ring_netmap_descriptor == NULL) {
            logger.error("Can't open netmap descriptor of interface %s for netmap per hardware queue thread",
                         interface.c_str());
            exit(1);
        }

        logger.info("My first rx ring is %d and last ring id is %d I'm thread %d",
                    one_nic_ring_netmap_descriptor->first_rx_ring, one_nic_ring_netmap_descriptor->last_rx_ring, i);

        logger.info("My first tx ring is %d and last ring id is %d I'm thread %d",
                    one_nic_ring_netmap_descriptor->first_tx_ring, one_nic_ring_netmap_descriptor->last_tx_ring, i);

        packet_nic_rx_thread_group.add_thread(new boost::thread(rx_nic_thread, one_nic_ring_netmap_descriptor, i));
    }

    packet_nic_rx_thread_group.join_all();
    nm_close(netmap_descriptor);
    logger.error("Close all nm description, programme done");
}



int main(int argc, char *argv[])
{
    init_logging();
    logger << log4cpp::Priority::DEBUG << "Run program";

    const char* interface;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s [interface]\n", argv[0]);
        exit(1);
    }

    interface = argv[1];
    std::string std_interface(interface);
    logger << log4cpp::Priority::INFO << "netmap will sniff interface: " << std_interface;

    create_main_work_pool(std_interface);

    return 0;
}

