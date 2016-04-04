//
// Created by alexey on 04.04.16.
//

#ifndef SYNFLOODPROTECT_BE_BYTESHIFT_H
#define SYNFLOODPROTECT_BE_BYTESHIFT_H

#include <linux/types.h>

static inline __u16 __get_unaligned_be16(const __u8 *p)
{
    return p[0] << 8 | p[1];
}

static inline __u32 __get_unaligned_be32(const __u8 *p)
{
    return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline __u64 __get_unaligned_be64(const __u8 *p)
{
    return (__u64)__get_unaligned_be32(p) << 32 |
           __get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(__u16 val, __u8 *p)
{
    *p++ = val >> 8;
    *p++ = val;
}

static inline void __put_unaligned_be32(__u32 val, __u8 *p)
{
    __put_unaligned_be16(val >> 16, p);
    __put_unaligned_be16(val, p + 2);
}

static inline void __put_unaligned_be64(__u64 val, __u8 *p)
{
    __put_unaligned_be32(val >> 32, p);
    __put_unaligned_be32(val, p + 4);
}

static inline __u16 get_unaligned_be16(const void *p)
{
    return __get_unaligned_be16((const __u8 *)p);
}

static inline __u32 get_unaligned_be32(const void *p)
{
    return __get_unaligned_be32((const __u8 *)p);
}

static inline __u64 get_unaligned_be64(const void *p)
{
    return __get_unaligned_be64((const __u8 *)p);
}

static inline void put_unaligned_be16(__u16 val, void *p)
{
    __put_unaligned_be16(val, (__u8 *) p);
}

static inline void put_unaligned_be32(__u32 val, void *p)
{
    __put_unaligned_be32(val, (__u8 *) p);
}

static inline void put_unaligned_be64(__u64 val, void *p)
{
    __put_unaligned_be64(val, (__u8 *) p);
}

static inline __u16 get_unaligned_le16(const void *p)
{
    const __u8 *_p = p;
    return _p[0] | _p[1] << 8;
}

static inline void put_unaligned_le16(__u16 val, void *p)
{
    __u8 *_p = p;
    _p[0] = val;
    _p[1] = val >> 8;
}

static inline uint32_t get_unaligned32(const void *p)
{
    return (uint32_t) p;
}

static inline uint64_t get_unaligned64(const void *p)
{
    return (uint64_t) p;
}

static inline __u32 get_unaligned_le32(const void *_ptr)
{
    const __u8 *ptr = _ptr;
    return ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
}

#define get_unaligned_be32(p)     get_unaligned32(p)
#define get_unaligned_be64(p)     get_unaligned64(p)

#endif //SYNFLOODPROTECT_BE_BYTESHIFT_H
