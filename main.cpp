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


#define NETMAP_WITH_LIBS
#include "net/netmap_user.h"
#include "lib/logger/logger.h"
#include "lib/parser/fastnetmon_packet_parser.h"
#include "lib/parser/parcer.h"

#define WAIT_NIC_TIME 4

// Get log4cpp logger from main program
extern log4cpp::Category& logger;
static int do_not_abort = 1;


static void sigint_h(int sig)
{
	(void)sig;	/* UNUSED */
	logger.error("Receive signal %i", sig);
	do_not_abort = 0;
	signal(SIGINT, SIG_DFL);
}

static void rx_nic_thread(struct nm_desc *netmap_description, unsigned int thread_id)
{
	struct pollfd fds;
	struct netmap_ring *rx_ring = NULL;
	unsigned int cur, len;
	char *buf;

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
				cur = rx_ring->cur;
                buf = NETMAP_BUF(rx_ring, rx_ring->slot[cur].buf_idx);
                len = rx_ring->slot[cur].len;

				struct pfring_pkthdr packet_header;
				memset(&packet_header, 0, sizeof(packet_header));
				u_int8_t flags = 0;

				if (!parse_raw_packet_to_packet_header((u_char *) buf, len, packet_header)) {
					rx_ring->slot[cur].flags |= NS_FORWARD;
					rx_ring->flags |= NR_FORWARD;
				} else {
					// Copy flags from PF_RING header to our pseudo header
					if (packet_header.extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
						flags = packet_header.extended_hdr.parsed_pkt.tcp.flags;
					}

					rx_ring->slot[cur].flags |= NS_FORWARD;
					rx_ring->flags |= NR_FORWARD;
				}

				logger.debug("Received packed len %i, protocol %s, dst ip %s, source ip %s, flags %s, dp %i, sp %i",
							 len, get_printable_protocol_name(packet_header.extended_hdr.parsed_pkt.l3_proto).c_str(),
							 convert_ip_as_uint_to_string(
									 htonl(packet_header.extended_hdr.parsed_pkt.ip_dst.v4)).c_str(),
							 convert_ip_as_uint_to_string(
									 htonl(packet_header.extended_hdr.parsed_pkt.ip_src.v4)).c_str(),
							 print_tcp_flags((uint8_t)flags).c_str(),
							 packet_header.extended_hdr.parsed_pkt.l4_dst_port,
							 packet_header.extended_hdr.parsed_pkt.l4_src_port);

                rx_ring->head = rx_ring->cur = nm_ring_next(rx_ring, cur);
            }
        }
	}
}

static void rx_host_thread(struct nm_desc *netmap_description, unsigned int thread_id)
{
	struct pollfd fds;
	struct netmap_ring *rx_ring = NULL;
	unsigned int cur;

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
				cur = rx_ring->cur;
				rx_ring->slot[cur].flags |= NS_FORWARD;
				rx_ring->flags |= NR_FORWARD;
				rx_ring->head = rx_ring->cur = nm_ring_next(rx_ring, cur);
			}
		}
	}
}

void create_main_work_pool(std::string interface_for_listening)
{
	struct nm_desc* netmap_descriptor;
	struct nm_desc* netmap_descriptor_host;

	struct nmreq base_nmd;
	bzero(&base_nmd, sizeof(base_nmd));

	// Magic from pkt-gen.c
	base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
	base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

	std::string interface = "";
	std::string interface_host = "";
	std::string system_interface_name = "";

    system_interface_name = interface_for_listening;
    interface = "netmap:" + interface_for_listening;
    interface_host = interface + "^";

	logger.warn("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off",
	            system_interface_name.c_str());


    // Открывать надо именно в этой последовательности, иначе приложеним может зависнуть\
    // на некоторых сетевых картах с драйвером igb
	netmap_descriptor_host = nm_open(interface_host.c_str(), &base_nmd, 0, NULL);
	netmap_descriptor = nm_open(interface.c_str(), &base_nmd, NM_OPEN_NO_MMAP, netmap_descriptor_host);

	if (netmap_descriptor == NULL) {
		logger.error("Can't open netmap device %s", interface.c_str());
		exit(1);
	}

    if (netmap_descriptor_host == NULL) {
        logger.error("Can't open netmap host device %s", interface_host.c_str());
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
			logger.error("Main descriptor of interface %s should be with NR_REG_ALL_NIC flag", interface_host.c_str());
		}

		params_descriptor.req.nr_flags = NR_REG_ONE_NIC;
		params_descriptor.req.nr_ringid = i;

		struct nm_desc* one_nic_ring_netmap_descriptor = nm_open(interface.c_str(), NULL,
                                                  nmd_flags | NM_OPEN_NO_MMAP | NM_OPEN_IFNAME, &params_descriptor);

		if (one_nic_ring_netmap_descriptor == NULL) {
			logger.error("Can't open netmap descriptor of interface %s for netmap per hardware queue thread",
                         interface_host.c_str());
			exit(1);
		}

		logger.info("My first rx ring is %d and last ring id is %d I'm thread %d",
					one_nic_ring_netmap_descriptor->first_rx_ring, one_nic_ring_netmap_descriptor->last_rx_ring, i);

		logger.info("My first tx ring is %d and last ring id is %d I'm thread %d",
					one_nic_ring_netmap_descriptor->first_tx_ring, one_nic_ring_netmap_descriptor->last_tx_ring, i);

        packet_nic_rx_thread_group.add_thread(new boost::thread(rx_nic_thread, one_nic_ring_netmap_descriptor, i));
	}

	{
		logger.info("My first rx ring is %d and last ring id is %d I'm thread %d",
					netmap_descriptor_host->first_rx_ring, netmap_descriptor_host->last_rx_ring, -1);

		logger.info("My first tx ring is %d and last ring id is %d I'm thread %d",
					netmap_descriptor_host->first_tx_ring, netmap_descriptor_host->last_tx_ring, -1);

		packet_nic_rx_thread_group.add_thread(new boost::thread(rx_host_thread, netmap_descriptor_host, -1));
	}

	packet_nic_rx_thread_group.join_all();
    nm_close(netmap_descriptor);
    nm_close(netmap_descriptor_host);
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

