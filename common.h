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

struct label_hdr {
    __u64 label;
    __u64 timestamp;
};

#define IP_TCP 6
#define LABEL_HEADER_LEN 9
#define MAX_UDP_SIZE 1480


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