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

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;


static int filter_packet(char *buf, int len)
{
    return 1;
//	// Allow ARP
//	if (len >= 14 &&
//	    *((uint16_t *) (buf + 12)) == 0x0608)
//    {
//        logger.info("arp");
//		return 1;
//	}
//
//	// Allow ICMP
//	if (len >= 34 &&
//	    *((uint16_t *) (buf + 12)) == 0x0008 &&
//	    *((uint8_t *)  (buf + 23)) == 0x1)
//    {
//        logger.info("icmp");
//		return 1;
//	}
//
//    logger.info("other");
//    return 1;
//
////	// Drop anything else
////	return 0;
}

static void rx_nic_theread(struct nm_desc *netmap_description, unsigned int therad_id)
{
	struct pollfd fds;
	struct netmap_ring *rx_ring = NULL;
	unsigned int cur, len;
	char *buf;

    struct netmap_if* nifp = netmap_description->nifp;

    fds.fd     = netmap_description->fd;
    fds.events = POLLIN;

	while (1) {
		int poll_result = poll(&fds, 1, 1000);
        if (poll_result == 0) {
            continue;
        }

		if (poll_result < 0) {
			logger.error("poll() theread %i", therad_id);
			exit(3);
		}

        for (int i = netmap_description->first_rx_ring; i <= netmap_description->last_rx_ring; i++) {
            rx_ring = NETMAP_RXRING(nifp, i);

			while (!nm_ring_empty(rx_ring)) {
				cur = rx_ring->cur;
                buf = NETMAP_BUF(rx_ring, rx_ring->slot[cur].buf_idx);
                len = rx_ring->slot[cur].len;

				simple_packet packet;
				if (!parse_raw_packet_to_simple_packet((u_char*)buf, len, packet)) {
					rx_ring->slot[cur].flags |= NS_FORWARD;
					rx_ring->flags |= NR_FORWARD;
				} else {
					rx_ring->slot[cur].flags |= NS_FORWARD;
					rx_ring->flags |= NR_FORWARD;
				}

				logger.debug("recirved packed len %i, protocol %s, dst ip %s, source ip %s, flags %s, dp %i, sp %i", len,
							 get_printable_protocol_name(packet.protocol).c_str(),
							 convert_ip_as_uint_to_string(packet.dst_ip).c_str(),
							 convert_ip_as_uint_to_string(packet.src_ip).c_str(),
							 print_tcp_flags(packet.flags).c_str(),
							 packet.destination_port, packet.source_port);

                rx_ring->head = rx_ring->cur = nm_ring_next(rx_ring, cur);
            }
        }
	}
}


static void rx_host_theread(struct nm_desc *netmap_description, unsigned int therad_id)
{
	struct pollfd fds;
	struct netmap_ring *rx_ring = NULL;
	unsigned int cur, len;
	char *buf;

	struct netmap_if* nifp = netmap_description->nifp;

	fds.fd     = netmap_description->fd;
	fds.events = POLLIN;

	while (1) {
		int poll_result = poll(&fds, 1, 1000);
		if (poll_result == 0) {
			continue;
		}

		if (poll_result < 0) {
			logger.error("poll() theread %i", therad_id);
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

//static void rx_host_theread(struct nm_desc *host_nm_description, unsigned int therad_id)
//{
//	struct pollfd fds;
//	struct netmap_ring *rx_host_ring;
//	uint32_t pps, cur;
//
//	pps = 0;
//
//    fds.fd     = host_nm_description->fd;
//    fds.events = POLLIN;
//
//    struct netmap_if* nifp = host_nm_description->nifp;
//
//	while (1) {
//		int poll_result = poll(&fds, 1, 2500);
//
//        if (poll_result == 0) {
//            continue;
//        }
//
//		if (poll_result < 0) {
//			logger.error("poll() host rx theread %i", therad_id);
//			exit(3);
//		}
//
//		for (int i = host_nm_description->first_rx_ring; i <= host_nm_description->last_rx_ring; i++) {
//			rx_host_ring = NETMAP_RXRING(nifp, i);
//
//			while (!nm_ring_empty(rx_host_ring)) {
//				cur = rx_host_ring->cur;
//				pps++;
//				rx_host_ring->slot[cur].flags |= NS_FORWARD;
//                rx_host_ring->flags |= NR_FORWARD;
//				rx_host_ring->head = rx_host_ring->cur = nm_ring_next(rx_host_ring, cur);
//			}
//		}
//	}
//}


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

	// If we haven't netmap: prefix in interface name we will append it
	if (interface_for_listening.find("netmap:") == std::string::npos) {
		system_interface_name = interface_for_listening;
		interface = "netmap:" + interface_for_listening;
		interface_host = interface + "^";
	} else {
		// We should skip netmap prefix
		system_interface_name = boost::replace_all_copy(interface_for_listening, "netmap:", "");
		interface = interface_for_listening;
		interface_host = interface + "^";
	}

	logger.warn("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off", system_interface_name.c_str());

	logger.info("nm_open(%s)", interface.c_str());

	netmap_descriptor_host = nm_open(interface_host.c_str(), &base_nmd, 0, NULL);
	netmap_descriptor = nm_open(interface.c_str(), &base_nmd, NM_OPEN_NO_MMAP, netmap_descriptor_host);

	if (netmap_descriptor == NULL) {
		logger.error("Can't open netmap device %s", interface.c_str());
		exit(1);
	}

	logger.info("Mapped %dKB memory at %p", netmap_descriptor->req.nr_memsize >> 10, netmap_descriptor->mem);
	logger.info("We have %d tx and %d rx rings", netmap_descriptor->req.nr_tx_rings,
				                                 netmap_descriptor->req.nr_rx_rings);

	unsigned int wait_link = 4;
	logger.info("Wait %d seconds for NIC reset", wait_link);
	sleep(wait_link);

	boost::thread_group packet_nic_rx_thread_group;

	for (int i = 0; i < netmap_descriptor->req.nr_rx_rings; i++) {

		struct nm_desc nmd = *netmap_descriptor;

        // This operation is VERY important!
		nmd.self = &nmd;

		uint64_t nmd_flags = 0;
		if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
			logger.error("Ooops, main descriptor should be with NR_REG_ALL_NIC flag");
		}

		nmd.req.nr_flags = NR_REG_ONE_NIC;
		nmd.req.nr_ringid = i;

		struct nm_desc* one_nic_ring_nm = nm_open(interface.c_str(), NULL,
                                                  nmd_flags | NM_OPEN_NO_MMAP | NM_OPEN_IFNAME, &nmd);

		if (one_nic_ring_nm == NULL) {
			logger.error("Can't open netmap descriptor for netmap per hardware queue thread");
			exit(1);
		}

		logger.info("My first rx ring is %d and last ring id is %d I'm thread %d",
					one_nic_ring_nm->first_rx_ring, one_nic_ring_nm->last_rx_ring, i);

		logger.info("My first tx ring is %d and last ring id is %d I'm thread %d",
					one_nic_ring_nm->first_tx_ring, one_nic_ring_nm->last_tx_ring, i);

        packet_nic_rx_thread_group.add_thread(new boost::thread(rx_nic_theread, one_nic_ring_nm, i));
	}

	{
		logger.info("My first rx ring is %d and last ring id is %d I'm thread %d",
					netmap_descriptor_host->first_rx_ring, netmap_descriptor_host->last_rx_ring, -1);

		logger.info("My first tx ring is %d and last ring id is %d I'm thread %d",
					netmap_descriptor_host->first_tx_ring, netmap_descriptor_host->last_tx_ring, -1);

		packet_nic_rx_thread_group.add_thread(new boost::thread(rx_host_theread, netmap_descriptor_host, -1));
	}

//	struct nm_desc nmd = *netmap_descriptor;
//
//	// This operation is VERY important!
//	nmd.self = &nmd;
//
//	uint64_t nmd_flags = 0;
//	if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
//		logger.error("Ooops, main descriptor should be with NR_REG_ALL_NIC flag");
//	}
//
//	nmd.req.nr_flags = NR_REG_SW;
//	nmd.req.nr_ringid = netmap_descriptor->req.nr_rx_rings;
//
//	struct nm_desc* one_host_rx_ring_nm = nm_open(interface.c_str(), NULL,
//												  nmd_flags | NM_OPEN_NO_MMAP | NM_OPEN_IFNAME, &nmd);
//
//	if (one_host_rx_ring_nm == NULL) {
//		logger.error("Can't open netmap descriptor for netmap per hardware queue thread");
//		exit(1);
//	}
//
//	logger.info("My first rx ring is %d and last ring id is %d I'm thread host",
//				one_host_rx_ring_nm->first_rx_ring, one_host_rx_ring_nm->last_rx_ring);
//
//	logger.info("My first tx ring is %d and last ring id is %d I'm thread host",
//				one_host_rx_ring_nm->first_tx_ring, one_host_rx_ring_nm->last_tx_ring);
//
//	packet_nic_rx_thread_group.add_thread(new boost::thread(rx_nic_theread, one_host_rx_ring_nm,
//                                                            one_host_rx_ring_nm->req.nr_rx_rings));
	packet_nic_rx_thread_group.join_all();
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

