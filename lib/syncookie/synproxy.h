////
//// Created by root on 29.03.16.
////
//
#ifndef SYNFLOODPROTECT_SYNPROXY_H_H
#define SYNFLOODPROTECT_SYNPROXY_H_H

#include <sys/types.h> // For support uint32_t, uint16_t
#include <sys/time.h> // gettimeofday
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h> // in6_addr
#include <net/ethernet.h>
#include <string.h> // memcpy
#include <stdio.h>
#include <arpa/inet.h> // inet_ntop
#include <sys/types.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <fstream>
#include <iostream>
#include <boost/asio.hpp>

__u32 __cookie_v4_init_sequence(__be32	saddr, __be32 daddr, __be16	source, __be16	dest, __be32 seq, __u16 mssp);
__u32  tcp_time_stamp();
__u16 get_mss(__u16 *mssp);
__u32 tcp_cookie_time(void);
__u32 tcp_time_stamp(void);

#endif //SYNFLOODPROTECT_SYNPROXY_H_H
