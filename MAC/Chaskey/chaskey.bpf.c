/*
   Chaskey-12 reference C implementation

   Written in 2015 by Nicky Mouha, based on Chaskey

   To the extent possible under law, the author has dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
   
   NOTE: This implementation assumes a little-endian architecture
         that does not require aligned memory accesses.
*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
//#include <stdint.h>
//#include <stdio.h>
#include <string.h>
#include <assert.h>

#define ROTL(x,b) (uint32_t)( ((x) >> (32 - (b))) | ( (x) << (b)) )

#define ROUND \
  do { \
    v[0] += v[1]; v[1]=ROTL(v[1], 5); v[1] ^= v[0]; v[0]=ROTL(v[0],16); \
    v[2] += v[3]; v[3]=ROTL(v[3], 8); v[3] ^= v[2]; \
    v[0] += v[3]; v[3]=ROTL(v[3],13); v[3] ^= v[0]; \
    v[2] += v[1]; v[1]=ROTL(v[1], 7); v[1] ^= v[2]; v[2]=ROTL(v[2],16); \
  } while(0)
  
#define PERMUTE \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND;

const volatile uint32_t C[2] = { 0x00, 0x87 };

#define TIMESTWO(out,in) \
  do { \
    out[0] = (in[0] << 1) ^ C[in[3] >> 31]; \
    out[1] = (in[1] << 1) | (in[0] >> 31); \
    out[2] = (in[2] << 1) | (in[1] >> 31); \
    out[3] = (in[3] << 1) | (in[2] >> 31); \
  } while(0)
    
void subkeys(uint32_t k1[4], uint32_t k2[4], const uint32_t k[4]) {
  TIMESTWO(k1,k);
  TIMESTWO(k2,k1);
}

struct keys {
    uint32_t *k;
    uint32_t *k1;
    uint32_t *k2;
  };

SEC("xdp")
int xdp_chaskey_encrypt() {
  const unsigned char m[] = "Hello, eBPF! I am a string that will be authenticated by Chaskey.";
  const uint32_t mlen = sizeof(m) - 1;
  uint8_t tag[16];
  uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33,
                    0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb,
                    0xcc, 0xdd, 0xee, 0xff };
  uint32_t k1[4], k2[4];
  int i;
  uint32_t taglen = 16;

  /* key schedule */
  subkeys(k1,k2,(uint32_t*) key);

  const uint32_t *k = (const uint32_t*) key;
  
  const uint32_t *M = (uint32_t*) m;
  const uint32_t *end = M + (((mlen-1)>>4)<<2); /* pointer to last message block */

  const uint32_t *l;
  uint8_t lb[16];
  const uint32_t *lastblock;
  uint32_t v[4];
  
  uint8_t *p;

  //int count = 0;///////////////////////////////////////////
  
  assert(taglen <= 16);

  v[0] = k[0];
  v[1] = k[1];
  v[2] = k[2];
  v[3] = k[3];

  //printing state for debugging
  //bpf_printk("Initial state: \n");
  //bpf_printk("v[0]: %08x\n", v[0]);
  //bpf_printk("v[1]: %08x\n", v[1]);
  //bpf_printk("v[2]: %08x\n", v[2]);
  //bpf_printk("v[3]: %08x\n", v[3]);

  if (mlen != 0) {
    for ( ; M != end; M += 4 ) {
#ifdef DEBUG
      bpf_printk("(%3d) v[0] %08x\n", mlen, v[0]);
      bpf_printk("(%3d) v[1] %08x\n", mlen, v[1]);
      bpf_printk("(%3d) v[2] %08x\n", mlen, v[2]);
      bpf_printk("(%3d) v[3] %08x\n", mlen, v[3]);
      bpf_printk("(%3d) compress %08x %08x %08x %08x\n", mlen, m[0], m[1], m[2], m[3]);
#endif
      v[0] ^= M[0];
      v[1] ^= M[1];
      v[2] ^= M[2];
      v[3] ^= M[3];
      PERMUTE;
      //printing state for debugging
      //bpf_printk("State I %d: \n", count++);
      //bpf_printk("v[0]: %08x\n", v[0]);
      //bpf_printk("v[1]: %08x\n", v[1]);
      //bpf_printk("v[2]: %08x\n", v[2]);
      //bpf_printk("v[3]: %08x\n", v[3]);
    }
  }

  //If mlen is multiple of 16 bytes then the last block is the last block of the message, no padding required
  if ((mlen != 0) && ((mlen & 0xF) == 0)) {
    l = k1;
    lastblock = M;
  } else {
    l = k2;
    p = (uint8_t*) M;
    i = 0;
    for ( ; p != m + mlen; p++,i++) {
      lb[i] = *p;
    }
    lb[i++] = 0x01; /* padding bit */
    for ( ; i != 16; i++) {
      lb[i] = 0;
    }
    lastblock = (uint32_t*) lb;
  }

#ifdef DEBUG
  bpf_printk("(%3d) v[0] %08x\n", mlen, v[0]);
  bpf_printk("(%3d) v[1] %08x\n", mlen, v[1]);
  bpf_printk("(%3d) v[2] %08x\n", mlen, v[2]);
  bpf_printk("(%3d) v[3] %08x\n", mlen, v[3]);
  bpf_printk("(%3d) last block %08x %08x %08x %08x\n", mlen, lastblock[0], lastblock[1], lastblock[2], lastblock[3]);
#endif
  v[0] ^= lastblock[0];
  v[1] ^= lastblock[1];
  v[2] ^= lastblock[2];
  v[3] ^= lastblock[3];

  v[0] ^= l[0];
  v[1] ^= l[1];
  v[2] ^= l[2];
  v[3] ^= l[3];

  PERMUTE;
  //printing state for debugging
  //bpf_printk("State II %d: \n", count++);
  //bpf_printk("v[0]: %08x\n", v[0]);
  //bpf_printk("v[1]: %08x\n", v[1]);
  //bpf_printk("v[2]: %08x\n", v[2]);
  //bpf_printk("v[3]: %08x\n", v[3]);

#ifdef DEBUG
  bpf_printk("(%3d) v[0] %08x\n", mlen, v[0]);
  bpf_printk("(%3d) v[1] %08x\n", mlen, v[1]);
  bpf_printk("(%3d) v[2] %08x\n", mlen, v[2]);
  bpf_printk("(%3d) v[3] %08x\n", mlen, v[3]);
#endif

  v[0] ^= l[0];
  v[1] ^= l[1];
  v[2] ^= l[2];
  v[3] ^= l[3];

#ifdef DEBUG
  bpf_printk("(%3d) MAC[0] %08x\n", mlen, v[0]);
  bpf_printk("(%3d) MAC[1] %08x\n", mlen, v[1]);
  bpf_printk("(%3d) MAC[2] %08x\n", mlen, v[2]);
  bpf_printk("(%3d) MAC[3] %08x\n", mlen, v[3]);
#endif

  //memcpy(tag,v,taglen);
  //copying the state v to the tag array, considering that the tag is a vector of bytes while the state is a vector of 4 bytes
  for (i = 0; i < taglen; i++) {
    //printing for debugging
    //bpf_printk("Tag[%d]: %02x\n", i, ((uint8_t*)v)[i]);//DO NOT REMOVE, OTHERWISE LAST 8 BYTES WILL BE 0
    tag[i] = ((uint8_t*)v)[i];
  }
  
  bpf_printk("Tag: ");
  for (i = 0; i < taglen; i++) {
    bpf_printk("%02d ", tag[i]);
  }
  bpf_printk("\n");

  return 0;
}

char LICENSE[] SEC("license") = "GPL";