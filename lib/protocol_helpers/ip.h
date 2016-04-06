//
// Created by root on 05.04.16.
//

#ifndef SYNFLOODPROTECT_IP_H_H
#define SYNFLOODPROTECT_IP_H_H

void initialize_iphdr(uint32_t src, uint32_t dst, int l4size, struct iphdr *ip, u_int8_t ipproto);
void initialize_ehhdr(u_int8_t* src_mac, u_int8_t* dst_mac, struct ether_header *eh);

#endif //SYNFLOODPROTECT_IP_H_H
