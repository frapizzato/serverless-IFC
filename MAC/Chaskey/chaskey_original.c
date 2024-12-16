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
#include <stdint.h>
#include <stdio.h>
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

void chaskey(uint8_t *tag, uint32_t taglen, const uint8_t *m, const uint32_t mlen, const uint32_t k[4], const uint32_t k1[4], const uint32_t k2[4]) {

  const uint32_t *M = (uint32_t*) m;
  const uint32_t *end = M + (((mlen-1)>>4)<<2); /* pointer to last message block */

  const uint32_t *l;
  uint8_t lb[16];
  const uint32_t *lastblock;
  uint32_t v[4];
  
  int i;
  uint8_t *p;

  //int count = 0;///////////////////////////////////////////
  
  assert(taglen <= 16);

  v[0] = k[0];
  v[1] = k[1];
  v[2] = k[2];
  v[3] = k[3];


  if (mlen != 0) {
    for ( ; M != end; M += 4 ) {
#ifdef DEBUG
      printf("(%3d) v[0] %08x\n", mlen, v[0]);
      printf("(%3d) v[1] %08x\n", mlen, v[1]);
      printf("(%3d) v[2] %08x\n", mlen, v[2]);
      printf("(%3d) v[3] %08x\n", mlen, v[3]);
      printf("(%3d) compress %08x %08x %08x %08x\n", mlen, m[0], m[1], m[2], m[3]);
#endif
      v[0] ^= M[0];
      v[1] ^= M[1];
      v[2] ^= M[2];
      v[3] ^= M[3];
      PERMUTE;
      //printing state for debugging
      //printf("State I %d: \n", count++);
      //printf("v[0]: %08x\n", v[0]);
      //printf("v[1]: %08x\n", v[1]);
      //printf("v[2]: %08x\n", v[2]);
      //printf("v[3]: %08x\n", v[3]);
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
  printf("(%3d) v[0] %08x\n", mlen, v[0]);
  printf("(%3d) v[1] %08x\n", mlen, v[1]);
  printf("(%3d) v[2] %08x\n", mlen, v[2]);
  printf("(%3d) v[3] %08x\n", mlen, v[3]);
  printf("(%3d) last block %08x %08x %08x %08x\n", mlen, lastblock[0], lastblock[1], lastblock[2], lastblock[3]);
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
  //printf("State II %d: \n", count++);
  //printf("v[0]: %08x\n", v[0]);
  //printf("v[1]: %08x\n", v[1]);
  //printf("v[2]: %08x\n", v[2]);
  //printf("v[3]: %08x\n", v[3]);

#ifdef DEBUG
  printf("(%3d) v[0] %08x\n", mlen, v[0]);
  printf("(%3d) v[1] %08x\n", mlen, v[1]);
  printf("(%3d) v[2] %08x\n", mlen, v[2]);
  printf("(%3d) v[3] %08x\n", mlen, v[3]);
#endif

  v[0] ^= l[0];
  v[1] ^= l[1];
  v[2] ^= l[2];
  v[3] ^= l[3];

#ifdef DEBUG
  printf("(%3d) MAC[0] %08x\n", mlen, v[0]);
  printf("(%3d) MAC[1] %08x\n", mlen, v[1]);
  printf("(%3d) MAC[2] %08x\n", mlen, v[2]);
  printf("(%3d) MAC[3] %08x\n", mlen, v[3]);
#endif

  memcpy(tag,v,taglen);

}

int main() {
  const unsigned char m[] = "Hello, eBPF! I am a string that will be authenticated by Chaskey.";
  const uint32_t mlen = sizeof(m) - 1;
  uint8_t tag[16];
  uint8_t k[16] = { 0x00, 0x11, 0x22, 0x33,
                    0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb,
                    0xcc, 0xdd, 0xee, 0xff };
  uint32_t k1[4], k2[4];
  int i;
  uint32_t taglen = 16;

  /* key schedule */
  subkeys(k1,k2,(uint32_t*) k);
    
  chaskey(tag, taglen, m, mlen, (uint32_t*) k, k1, k2);

  printf("Tag: ");
  for (i = 0; i < taglen; i++) {
    printf("%02d ", tag[i]);
  }
  printf("\n");

  return 0;
}