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
#include <boost/atomic/atomic.hpp>

// Boost libs
#include <boost/algorithm/string.hpp>
#include <lib/parser/packet_parser.h>
#include <netinet/ip.h>
#include "lib/parser/parcer_helper.h"
#include "lib/protocol_helpers/tcp.h"
#include "lib/protocol_helpers/ip.h"
#include "lib/protocol_helpers/icmp.h"

#define NETMAP_WITH_LIBS
#include "net/netmap_user.h"
#include "lib/logger/logger.h"
#include "lib/parser/packet_parser.h"
#include "lib/parser/parcer.h"
#include "lib/syncookie/synproxy.h"

#define WAIT_NIC_TIME 2

#define TCP_SYN_FLAG_SHIFT 2
#define TCP_ACK_FLAG_SHIFT 5

// Get log4cpp logger from main program
extern log4cpp::Category& logger;
static int do_not_abort = 1;

boost::atomic<__u32> tcp_time_stamp;
boost::atomic<__u32> tcp_cookie_time;

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


bool send_syncookie_response(char *rx_buf, int len, struct netmap_ring *tx_ring, struct pfring_pkthdr *packet_header,
                             struct pollfd* fd_out)
{
    register unsigned int tx_avail, tx_cur;
    char *tx_buf;

    tx_cur   = tx_ring->cur;
    tx_avail = nm_ring_space(tx_ring);

    if (tx_avail > 0) {
        unsigned char* pointer;
        unsigned int size = sizeof(ether_header) + 20 + sizeof(tcphdr) + 24; /* tcp options */

        pointer = (unsigned char *) std::malloc(size);
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

        __u32 tcp_time_stamp = tcp_time_stamp.load(memory_order_acquire);
        __u32 tcp_cookie_time = tcp_cookie_time.load(memory_order_acquire);

        initialize_tcphdr(tcp, packet_header->extended_hdr.parsed_pkt.l4_dst_port,
                          packet_header->extended_hdr.parsed_pkt.l4_src_port,
                          packet_header->extended_hdr.parsed_pkt.tcp.seq_num,
                          __cookie_v4_init_sequence(packet_header->extended_hdr.parsed_pkt.ip_src.v4,
                                                    packet_header->extended_hdr.parsed_pkt.ip_dst.v4,
                                                    (__be16) packet_header->extended_hdr.parsed_pkt.l4_src_port,
                                                    (__be16) packet_header->extended_hdr.parsed_pkt.l4_dst_port,
                                                    packet_header->extended_hdr.parsed_pkt.tcp.seq_num,
                                                    packet_header->extended_hdr.parsed_pkt.tcp.options.mss,
                                                    tcp_cookie_time));

        tcp->syn = 1;
        tcp->ack = 1;

        generate_tcp_options((char *)(pointer + sizeof(struct ethhdr) + 20 + sizeof(struct tcphdr)),
                             get_mss(&packet_header->extended_hdr.parsed_pkt.tcp.options.mss),
                             synproxy_init_timestamp_cookie(/*packet_header->extended_hdr.parsed_pkt.tcp.options.wscale*/ 7,
                                                            packet_header->extended_hdr.parsed_pkt.tcp.options.saksp,
                                                            0, tcp_time_stamp),
                             packet_header->extended_hdr.parsed_pkt.tcp.options.timestamp_send,
                             7,
                             packet_header->extended_hdr.parsed_pkt.tcp.options.saksp);

        tcp->check = get_tcp_checksum(ip, tcp);

        tx_buf = NETMAP_BUF(tx_ring, tx_ring->slot[tx_cur].buf_idx);
        bzero(tx_buf, size);
        nm_pkt_copy(pointer, tx_buf, size);

        tx_ring->slot[tx_cur].len = (uint16_t) size;
        tx_ring->slot[tx_cur].flags |= NS_BUF_CHANGED;
        tx_ring->head = tx_ring->cur = nm_ring_next(tx_ring, tx_cur);

        ioctl(fd_out->fd, NIOCTXSYNC, NULL);
        std::free(pointer);

        return true;
    } else {
        ioctl(fd_out->fd, NIOCTXSYNC, NULL);
        //logger.warn("tx not availible");
    }
    return false;
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
        unsigned int size = (unsigned int) len;
        unsigned int size_data = size - min_size;

        pointer = (unsigned char *) std::malloc(size);
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

        responce_icmp->type     = 0;
        responce_icmp->code     = 0;
        responce_icmp->checksum = 0;
        responce_icmp->un.echo.id = request_icmp->un.echo.id;
        responce_icmp->un.echo.sequence = request_icmp->un.echo.sequence + 1;
        std::memcpy((void *) &pointer[min_size], (void *) &rx_buf[min_size],  size_data);
        responce_icmp->checksum = icmp_checksum(responce_icmp, sizeof(icmphdr) + size_data);

        tx_buf = NETMAP_BUF(tx_ring, tx_ring->slot[tx_cur].buf_idx);
        bzero(tx_buf, size);
        nm_pkt_copy(pointer, tx_buf, size);

        tx_ring->slot[tx_cur].len = (uint16_t) size;
        tx_ring->slot[tx_cur].flags |= NS_BUF_CHANGED;
        tx_ring->head = tx_ring->cur = nm_ring_next(tx_ring, tx_cur);

        free(pointer);
    } else {
        //logger.warn("tx not availible");
    }
}

static void update_time_value()
{
    while (do_not_abort) {
        FILE *file;
        file = fopen("/proc/beget_uptime", "r");
        __u32 tcp_cookie_time = 0;
        __u64 jiffies = 0;
        if (fscanf (file, "%llu %lu", &jiffies, (long *)&tcp_cookie_time)) {
            fclose(file);

            tcp_time_stamp.store((__u32) jiffies & 0X00000000ffffffff, memory_order_release);
            tcp_cookie_time.store(tcp_cookie_time, memory_order_release);
        } else {
            fclose(file);
            logger.error("time value not updated");
        }
        boost::this_thread::sleep(boost::posix_time::milliseconds(300));
    }
}

static void rx_nic_thread(struct nm_desc *netmap_description, unsigned int thread_id)
{
    struct pollfd fd_in, fd_out;
    struct netmap_ring *rx_ring = NULL;
    struct netmap_ring *tx_ring = NULL;
    register unsigned int rx_cur, tx_cur, rx_len;
    unsigned int tx_avail;
    char *rx_buf, *tx_buf;

    struct netmap_if* nifp = netmap_description->nifp;

    fd_in.fd     = netmap_description->fd;
    fd_in.events = POLLIN;

    fd_out.fd     = netmap_description->fd;
    fd_out.events = POLLOUT;

    while (do_not_abort) {

        int poll_result = poll(&fd_in, 1, 1000);
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
                    tx_ring->num_slots;

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
                            //logger.warn("syn");
                            //if (packet_header.extended_hdr.parsed_pkt.tcp.options.mss != 0) {
                                //logger.warn("mss != 0 ");
                                send_syncookie_response(rx_buf, rx_len, tx_ring, &packet_header, &fd_out);
                            //} else {
                                // DROP PACKET
                            //}
//                        } else if (flags == 16 /*TCP_ACK_FLAG*/) {
//                            if (check_syncookie(packet_header.extended_hdr.parsed_pkt.tcp.ack_num,
//                                                packet_header.extended_hdr.parsed_pkt.l4_src_port,
//                                                packet_header.extended_hdr.parsed_pkt.tcp.options.timestamp_reserved))
//                            if (packet_header.extended_hdr.parsed_pkt.l4_dst_port == 22) {
//                                if (packet_header.extended_hdr.parsed_pkt.tcp.ack_num == 1207
//                                    && packet_header.extended_hdr.parsed_pkt.tcp.options.timestamp_reserved == 1206) {
//                                    send_syn_to_host_response(rx_ring, &packet_header);
//                                } else {
//                                    forward_packet(rx_ring, rx_cur);
//                                }
//                            } else {
//                                forward_packet(rx_ring, rx_cur);
//                            }
                        } else {
                            forward_packet(rx_ring, rx_cur);
                        }
                    } else if (packet_header.extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
                        // UPD NEED DROP
                        forward_packet(rx_ring, rx_cur);
                    } else {
                        // other arp
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

    packet_nic_rx_thread_group.add_thread(new boost::thread(update_time_value));
    boost::thread::yield();

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

