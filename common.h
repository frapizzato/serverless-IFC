#ifndef COMMLIBS_H
#define COMMLIBS_H

#include <bcc/proto.h>
#include <linux/pkt_cls.h> /* TC_ACT_OK, TC_ACT_SHOT, ... */
#include <uapi/linux/tcp.h> /* definition of structure tcphdr */
#include <uapi/linux/ip.h> /* definition of structure iphdr */
#include <uapi/linux/if_ether.h> /* definition of struct ethhdr */
#include <uapi/linux/bpf.h> /* definition of __sk_buff and xdp_md*/
#include <linux/sched.h> /* definition of struct task_struct */
#include <linux/ptrace.h> /* definition of struct pt_regs */
#include <net/sock.h> /* definition of struct sock */
#include <net/inet_sock.h> /* definition of struct inet_sock */

struct custom_24b {
    __u8    value[3];
};

struct label_hdr {
    __u16               init_sequence:13,
                        f_counter:3;
    __u32               id_label;
    struct custom_24b   label[6]; // 144 bits --> accessed in "groups-of-3". Is an array of 6 24-bit words
};

#define IP_TCP 6
#define ETH_HDR 14
#define LABEL_HEADER_LEN 9
#define MAX_UDP_SIZE 1480

#define LABEL_LEN 28 //36
#define LABEL_LEN_32b 7 //9 // 36B / 4 = 9 32-bit words
#define HTTP_AND_LABEL_LEN 28+26//36+26 // 36 bytes for the label and 26 bytes for minimum HTTP payload (http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes)
#define HTTP_LEN 26 // 26 bytes for minimum HTTP payload (http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes)
#define DEBUG 0

/*
**  Function to recompute TCP checksum
*/
__attribute__((__always_inline__))
static inline __u16 caltcpcsum(struct iphdr *iph, struct tcphdr *tcph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)tcph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    unsigned short tcpLen = ntohs(iph->tot_len) - (iph->ihl<<2);
    
    csum_buffer += htons(tcpLen);

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) 
    {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) 
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}

/*
** (WORKING) function to compute TCP checksum
*/
static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__attribute__((__always_inline__))
static inline void ipv4_csum(void *data_start, int data_size, __u64 *csum) {
  *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
  *csum = csum_fold_helper(*csum);
}

#endif