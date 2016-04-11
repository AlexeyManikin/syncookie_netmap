////
//// Created by root on 29.03.16.
////
//
#ifndef SYNFLOODPROTECT_SYNPROXY_H_H
#define SYNFLOODPROTECT_SYNPROXY_H_H

/*
 *  Syncookies implementation for the Linux kernel
 *
 *  Copyright (C) 1997 Andi Kleen
 *  Based on ideas by D.J.Bernstein and Eric Schenk.
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/tcp.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <boost/algorithm/string.hpp>

#include "cryptohash.h"
#include "div64.h"
#include "sha1.c"
#include "../logger/logger.h"

#define __read_mostly __attribute__((__section__(".data..read_mostly")))
static __u32 syncookie_secret[2][16-4+SHA_DIGEST_WORDS] __read_mostly;

#define COOKIEBITS 24	/* Upper bits store count */
#define COOKIEMASK (((__u32)1 << COOKIEBITS) - 1)

#define BIT(nr)			(((unsigned long)1) << (nr))

#define TS_OPT_WSCALE_MASK	0xf
#define TS_OPT_SACK		BIT(4)
#define TS_OPT_ECN		BIT(5)
#define TSBITS	6
#define TSMASK	(((__u32)1 << TSBITS) - 1)

inline static __u32 cookie_hash(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                                __u32 count, int c)
{
    __u32* tmp;
    __u32 return_value = 0;

    //net_get_random_once(syncookie_secret, sizeof(syncookie_secret));

    std::memset(syncookie_secret, 0, sizeof(syncookie_secret));

    tmp  = (__u32 *) std::malloc(sizeof(__u32) * (16 + 5 + SHA_WORKSPACE_WORDS));

    std::memcpy(tmp + 4, syncookie_secret[c], sizeof(syncookie_secret[c]));
    tmp[0] = (__u32)saddr;
    tmp[1] = (__u32)daddr;
    tmp[2] = ((__u32)sport << 16) + (__u32)dport;
    tmp[3] = count;
    sha_transform(tmp + 16, (const char *) tmp, tmp + 16 + 5);

    return_value = tmp[17];
    std::free(tmp);

    return return_value;
}

inline static __u32 secure_tcp_syn_cookie(__be32 saddr, __be32 daddr, __be16 sport,
                                          __be16 dport, __u32 sseq, __u32 data, __u32 tcp_cookie_time)
{
    /*
     * Compute the secure sequence number.
     * The output should be:
     *   HASH(sec1,saddr,sport,daddr,dport,sec1) + sseq + (count * 2^24)
     *      + (HASH(sec2,saddr,sport,daddr,dport,count,sec2) % 2^24).
     * Where sseq is their sequence number and count increases every
     * minute by 1.
     * As an extra hack, we add a small "data" value that encodes the
     * MSS into the second hash value.
     */
    return (cookie_hash(saddr, daddr, sport, dport, 0, 0)
            + sseq + (tcp_cookie_time << COOKIEBITS)
            + ((cookie_hash(saddr, daddr, sport, dport, tcp_cookie_time, 1) + data) & COOKIEMASK)
    );
}

/*
 * MSS Values are chosen based on the 2011 paper
 * 'An Analysis of TCP Maximum Segement Sizes' by S. Alcock and R. Nelson.
 * Values ..
 *  .. lower than 536 are rare (< 0.2%)
 *  .. between 537 and 1299 account for less than < 1.5% of observed values
 *  .. in the 1300-1349 range account for about 15 to 20% of observed mss values
 *  .. exceeding 1460 are very rare (< 0.04%)
 *
 *  1460 is the single most frequently announced mss value (30 to 46% depending
 *  on monitor location).  Table must be sorted.
 */
static __u16 const msstab[] = {
        536,
        1300,
        1440,	/* 1440, 1452: PPPoE */
        1460,
};

static __u8 const msstab_array_size = 4;

inline __u16 get_mss(__u16 *mssp)
{
    __u32 mssind;
    const __u16 mss = *mssp;

    for (mssind = msstab_array_size - 1; mssind ; mssind--)
        if (mss >= msstab[mssind]) {
            break;
        }

    return msstab[mssind];
}

inline uint32_t synproxy_init_timestamp_cookie(unsigned char wscale, uint8_t sperm, uint8_t ecn, __u32 tcp_time_stamp)
{
    uint32_t tsval = tcp_time_stamp & ~0x3f;

    if (wscale) {
        tsval |= wscale;
    } else
        tsval |= 0xf;

    if (sperm)
        tsval |= 1 << 4;

    if (ecn)
        tsval |= 1 << 5;

    return tsval;
}

/*
 * Generate a syncookie.  mssp points to the mss, which is returned
 * rounded down to the value encoded in the cookie.
 */
inline __u32 __cookie_v4_init_sequence(__be32	saddr, __be32 daddr, __be16	source, __be16	dest, __be32 seq, __u16 mssp,
                                __u32 tcp_cookie_time)
{
    __u32 mssind;
    const __u16 mss = mssp;

    for (mssind = msstab_array_size - 1; mssind ; mssind--) {
        if (mss >= msstab[mssind]) {
            break;
        }
    }

    return secure_tcp_syn_cookie(ntohl(saddr), ntohl(daddr), ntohs(source), ntohs(dest), seq, mssind, tcp_cookie_time);
}


#endif //SYNFLOODPROTECT_SYNPROXY_H_H
