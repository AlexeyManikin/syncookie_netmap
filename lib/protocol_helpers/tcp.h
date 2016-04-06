//
// Created by root on 05.04.16.
//

#ifndef SYNFLOODPROTECT_TCP_H
#define SYNFLOODPROTECT_TCP_H

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

u_int16_t get_tcp_checksum(struct iphdr* myip, struct tcphdr* mytcp);
void initialize_tcphdr(struct tcphdr *tcp, u_int16_t sport, u_int16_t dport, uint32_t ack_seq, uint32_t seq);

#endif //SYNFLOODPROTECT_TCP_H
