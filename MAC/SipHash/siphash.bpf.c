/*
   SipHash reference C implementation

   Copyright (c) 2012-2022 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
//#include <stdint.h>
//#include <stdio.h>
#include <string.h>
#include <assert.h>

/* default: SipHash-2-4 */
/* pass -DcROUNDS=x and -DdROUNDS=y at compile time to use custom parameters (like 4,8)*/
#ifndef cROUNDS
#define cROUNDS 2
#endif
#ifndef dROUNDS
#define dROUNDS 4
#endif

#define UINT64_C(c)	c ## UL

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                                                        \
    (p)[0] = (uint8_t)((v));                                                   \
    (p)[1] = (uint8_t)((v) >> 8);                                              \
    (p)[2] = (uint8_t)((v) >> 16);                                             \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
    U32TO8_LE((p), (uint32_t)((v)));                                           \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                                           \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)

#ifdef DEBUG_SIPHASH
#include <stdio.h>

#define TRACE                                                                  \
    do {                                                                       \
        bpf_printk("(%3zu) v0 %016" PRIx64 "\n", inlen, v0);                       \
        bpf_printk("(%3zu) v1 %016" PRIx64 "\n", inlen, v1);                       \
        bpf_printk("(%3zu) v2 %016" PRIx64 "\n", inlen, v2);                       \
        bpf_printk("(%3zu) v3 %016" PRIx64 "\n", inlen, v3);                       \
    } while (0)
#else
#define TRACE
#endif


SEC("xdp")
int xdp_siphash_encrypt() {
    const unsigned char m[] = "Hello, eBPF! I am a string that will be authenticated by Chaskey.";
    const uint32_t mlen = sizeof(m) - 1;
    uint8_t tag[16];
    uint8_t k[16] = { 0x00, 0x11, 0x22, 0x33,
                        0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xaa, 0xbb,
                        0xcc, 0xdd, 0xee, 0xff };
    int i;
    uint32_t taglen = 16;

    //siphash(m, mlen, k, tag, taglen);

    const unsigned char *ni = (const unsigned char *)m;
    const unsigned char *kk = (const unsigned char *)k;

    assert((taglen == 8) || (taglen == 16));
    uint64_t v0 = UINT64_C(0x736f6d6570736575);
    uint64_t v1 = UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = UINT64_C(0x6c7967656e657261);
    uint64_t v3 = UINT64_C(0x7465646279746573);
    uint64_t k0 = U8TO64_LE(kk);
    uint64_t k1 = U8TO64_LE(kk + 8);
    uint64_t n;
    const unsigned char *end = ni + mlen - (mlen % sizeof(uint64_t));
    const int left = mlen & 7;
    uint64_t b = ((uint64_t)mlen) << 56;
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    if (taglen == 16)
        v1 ^= 0xee;

    for (; ni != end; ni += 8) {
        n = U8TO64_LE(ni);
        v3 ^= n;

        TRACE;
        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= n;
    }

    switch (left) {
    case 7:
        b |= ((uint64_t)ni[6]) << 48;
        /* FALLTHRU */
    case 6:
        b |= ((uint64_t)ni[5]) << 40;
        /* FALLTHRU */
    case 5:
        b |= ((uint64_t)ni[4]) << 32;
        /* FALLTHRU */
    case 4:
        b |= ((uint64_t)ni[3]) << 24;
        /* FALLTHRU */
    case 3:
        b |= ((uint64_t)ni[2]) << 16;
        /* FALLTHRU */
    case 2:
        b |= ((uint64_t)ni[1]) << 8;
        /* FALLTHRU */
    case 1:
        b |= ((uint64_t)ni[0]);
        break;
    case 0:
        break;
    }

    v3 ^= b;

    TRACE;
    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;

    if (taglen == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(tag, b);

    if (taglen == 8)
        return 0;

    v1 ^= 0xdd;

    TRACE;
    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(tag + 8, b);

    bpf_printk("Tag: ");
    for (i = 0; i < taglen; i++) {
        bpf_printk("%02d ", tag[i]);
    }
    bpf_printk("\n");

    return 0;
}

char LICENSE[] SEC("license") = "GPL";