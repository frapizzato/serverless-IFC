#include "common.h"


#define HTTP_AND_LABEL_LEN 16+26 // 16 bytes for the label and 26 bytes for minimum HTTP payload (http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes)
#define HTTP_LEN 26 // 26 bytes for minimum HTTP payload (http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes)

// Map to push label of the incoming request at gateway, and pop them when connection exit the gateway
BPF_HASH(fifo, int, struct label_hdr, 1); 
/* BPF_QUEUE map would have been better choice but not supported in XPD - Oct' 2024 */

struct key_t {
    u8 auth_token[16];
};
// Map to store the mapping between authorization header content and labels
BPF_HASH(auth_map, struct key_t, struct label_hdr, 100);

// Map to check if a flow should be tagged or not - and if the IP is "allowed" (i.e., internal one) or not (i.e., external one)
BPF_TABLE_PINNED("hash", int, int, tags_map, 1024, "/sys/fs/bpf/tags");

/*
** INGRESS TRAFFIC (XDP):
**  - first check on packet source, if it is the GW or not
**  - IF ip.src IS internal (e.g., an OpenFaaS function) THEN:
**      - IF tagging(ip.src) THEN:
**          - could be either an HTTP message or a TCP one, but only HTTP has a LABEL. 
**          - IF tcp.payload >= sizeof(LABEL) + sizeof("HTTP ...") THEN:
**              - check if it is indeed an HTTP response or request (i.e., either "HTTP ..." or "GET..." or "POST.. " or "PUT..." or "DELETE..." or "PATCH..." or "OPTIONS..." or "HEAD...")
**              - extract the label from the packet, push it to the queue, - and enforce security policies (NOT IMPLEMENTED)
**          - ELSE: forward the packet (??) - eventually process TCP packets
*/
int handle_ingress(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct label_hdr *tag;

    if(data + sizeof(*eth) > data_end)
        return XDP_PASS;

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    if(data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    if(ip->protocol != IP_TCP)
        return XDP_PASS;

    if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    tcp = data + sizeof(*eth) + sizeof(*ip);
    
    u32 ip_header_length = ip->ihl << 2;
    u32 tcp_header_length = tcp->doff << 2;
    u32 payload_offset = sizeof(*eth) + ip_header_length + tcp_header_length;
    u32 payload_length = bpf_ntohs(ip->tot_len) - ip_header_length + tcp_header_length;
    long ret;
    int key = 0;

//  - first check on packet source, if it is the GW or not
//  - IF ip.src IS internal (e.g., an OpenFaaS function) THEN:
    int *ip_decision = tags_map.lookup(&ip->saddr);
    if(ip_decision != NULL){
//      - IF tagging(ip.src) THEN:
        if(*ip_decision == 1){
//          - could be either an HTTP message or a TCP one, but only HTTP has a LABEL. 
//          - IF tcp.payload >= sizeof(LABEL) + sizeof("HTTP ...") THEN:
            if(payload_length > HTTP_AND_LABEL_LEN){
//              - check if it is indeed an HTTP response or request (i.e., either "HTTP ..." or "GET..." or "POST.. " or "PUT..." or "DELETE..." or "PATCH..." or "OPTIONS..." or "HEAD...")
                u8 *cursor_HTTP = data + payload_offset + 16; /* skip the label */
                int buff_len_HTTP = 4;
                u8 buff_HTTP[4];
                ret = bpf_probe_read_kernel(buff_HTTP, buff_len_HTTP, cursor_HTTP);
                if(ret != 0){
                    bpf_trace_printk("[F][I] failed to read TCP's payload\n");
                    return XDP_PASS;
                }

                /* 
                    TODO: this check should be optimized with an hash map 
                */
                if(buff_HTTP[0] == 'H' && buff_HTTP[1] == 'T' && buff_HTTP[2] == 'T' && buff_HTTP[3] == 'P'){
                    bpf_trace_printk("[F][I] Found HTTP response\n");
                } else if(buff_HTTP[0] == 'P' && buff_HTTP[1] == 'O' && buff_HTTP[2] == 'S' && buff_HTTP[3] == 'T'){
                    bpf_trace_printk("[F][I] Found HTTP POST request\n");
                } else if(buff_HTTP[0] == 'G' && buff_HTTP[1] == 'E' && buff_HTTP[2] == 'T' && buff_HTTP[3] == ' '){
                    bpf_trace_printk("[F][I] Found HTTP GET request\n");
                } else if(buff_HTTP[0] == 'P' && buff_HTTP[1] == 'U' && buff_HTTP[2] == 'T' && buff_HTTP[3] == ' '){
                    bpf_trace_printk("[F][I] Found HTTP PUT request\n");
                } else if(buff_HTTP[0] == 'D' && buff_HTTP[1] == 'E' && buff_HTTP[2] == 'L' && buff_HTTP[3] == 'E'){
                    bpf_trace_printk("[F][I] Found HTTP DELETE request\n");
                } else if(buff_HTTP[0] == 'P' && buff_HTTP[1] == 'A' && buff_HTTP[2] == 'T' && buff_HTTP[3] == 'C'){
                    bpf_trace_printk("[F][I] Found HTTP PATCH request\n");
                } else if(buff_HTTP[0] == 'O' && buff_HTTP[1] == 'P' && buff_HTTP[2] == 'T' && buff_HTTP[3] == 'I'){
                    bpf_trace_printk("[F][I] Found HTTP OPTIONS request\n");
                } else if(buff_HTTP[0] == 'H' && buff_HTTP[1] == 'E' && buff_HTTP[2] == 'A' && buff_HTTP[3] == 'D'){
                    bpf_trace_printk("[F][I] Found HTTP HEAD request\n");
                } else {
                    bpf_trace_printk("[F][I] NOT an HTTP message!\n");
                    return XDP_PASS;
                }
//              - extract the label from the packet, push it to the queue, - and enforce security policies (NOT IMPLEMENTED)
                if(data + sizeof(*eth) + sizeof(*ip) + tcp_header_length + sizeof(*tag) > data_end){
                    return XDP_PASS;
                }

                tag = data + sizeof(*eth) + sizeof(*ip) + tcp_header_length;
                bpf_trace_printk("[F][I] received label: {%d, %d}\n", tag->label, tag->timestamp);

                ret = fifo.update(&key, tag);

                /*
                ** TODO: enforce security policies
                */

                struct ethhdr eth_copy;
                struct iphdr ip_copy;
                struct tcphdr tcp_copy;
                struct label_hdr tag_copy;

                __builtin_memcpy(&eth_copy, eth, sizeof(eth_copy));
                __builtin_memcpy(&ip_copy, ip, sizeof(ip_copy));
                __builtin_memcpy(&tcp_copy, tcp, sizeof(tcp_copy));
                __builtin_memcpy(&tag_copy, tag, sizeof(tag_copy));
                u8 opts[12];
                ret = bpf_xdp_load_bytes(ctx, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp), &opts[0], 12);
                if(ret){
                    return XDP_PASS;
                }

                ret = bpf_xdp_adjust_head(ctx, 16); /* move xdp_md.data to the right by 16 bytes (len of tag) */
                if(ret != 0){ 
                    bpf_trace_printk("[F][I] failed to adjust head\n");
                    return XDP_DROP;
                }

                data = (void *)(long)ctx->data;
                data_end = (void *)(long)ctx->data_end;

                if(data + sizeof(*eth) > data_end){
                    return XDP_PASS;
                }
                eth = data;

                if(data + sizeof(*eth) + sizeof(*ip) > data_end){
                    return XDP_PASS;
                }
                ip = data + sizeof(*eth);

                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end){
                    return XDP_PASS;
                }
                tcp = data + sizeof(*eth) + sizeof(*ip);

                /* modify packet len information in the header to the new one (without LABEL) */
                int tmp = ip_copy.tot_len;
                tmp -= 16<<8; /* network order */
                ip_copy.tot_len = tmp;

                __builtin_memcpy(eth, &eth_copy, sizeof(eth_copy));
                __builtin_memcpy(ip, &ip_copy, sizeof(ip_copy));
                __builtin_memcpy(tcp, &tcp_copy, sizeof(tcp_copy));
                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 12 > data_end){
                    return XDP_PASS;
                }
                ret = bpf_xdp_store_bytes(ctx, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp), &opts, 12);
                if(ret){
                    return XDP_PASS;
                }

                /* fix checksum */
                ip->check = 0;
                __u64 csum = 0;
                ipv4_csum(ip, sizeof(*ip), &csum);
                ip->check = csum;

                bpf_trace_printk("[F][I] forwarding modified packet\n");
                return XDP_PASS;
//          - ELSE: forward the packet (??) - eventually process TCP packets
            }
        }
    }
    return XDP_PASS;
}


/*
** EGRESS TRAFFIC (TCP):
**  - first check on packet destination, if it is GW or not
**  - IF ip.dst IS internal (e.g., an OpenFaaS function) THEN:
**      - IF tagging(ip.dst) THEN:
**          - could be either an HTTP message or a TCP one, but only HTTP has a LABEL. 
**          - IF tcp.payload >= sizeof("HTTP ...") THEN:
**              - check if it is indeed an HTTP response or request (i.e., either "HTTP ..." or "GET..." or "POST.. " or "PUT..." or "DELETE..." or "PATCH..." or "OPTIONS..." or "HEAD...")
**              - extract the label from the queue, enforce security policies (NOT IMPLEMENTED), and add label to the packet
**          - ELSE: forward the packet (??) - eventually process TCP packets
**      - ELSE: forward the packet (??)
*/
int handle_egress(struct __sk_buff *skb){
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct label_hdr *tag;

    if(data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    if(data + sizeof(*eth) + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    ip = data + sizeof(*eth);

    if(ip->protocol != IP_TCP)
        return TC_ACT_OK;

    if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return TC_ACT_OK;

    tcp = data + sizeof(*eth) + sizeof(*ip);

    u32 ip_header_length = ip->ihl << 2;
    u32 tcp_header_length = tcp->doff << 2;
    u32 payload_offset = sizeof(*eth) + ip_header_length + tcp_header_length;
    u32 payload_length = bpf_ntohs(ip->tot_len) - ip_header_length + tcp_header_length;
    long ret;
    int key = 0;

//  - first check on packet destination, if it is GW or not
//  - IF ip.dst IS internal (e.g., an OpenFaaS function) THEN:
    int *ip_decision = tags_map.lookup(&ip->daddr); 
    if(ip_decision != NULL){ /* pointer to value if IP exists in the map */
//      - IF tagging(ip.dst) THEN:
        if(*ip_decision == 1){
//          - could be either an HTTP message or a TCP one, but only HTTP has a LABEL. 
//          - IF tcp.payload >= sizeof("HTTP ...") THEN:
            if(payload_length > HTTP_LEN){
//              - check if it is indeed an HTTP response or request (i.e., either "HTTP ..." or "GET..." or "POST.. " or "PUT..." or "DELETE..." or "PATCH..." or "OPTIONS..." or "HEAD...")
                
                /*
                ** Since we are working with SKB, it could be that not all data is accessible trough the pointers (linear part). 
                ** Need to pull in all the non-linear data into the linear part.
                */
                if(data + payload_offset + 1 > data_end){
                    if(data_end - data < skb->len){
                        ret = bpf_skb_pull_data(skb, skb->len);
                        if(ret < 0){
                            bpf_trace_printk("[F][E] Error reading non linear part\n");
                            return TC_ACT_SHOT;
                        }
                    } else {
                        // there is no non-linear part
                        bpf_trace_printk("[F][E] Packet is too short\n");
                        return TC_ACT_OK;
                    }
                }

                /*
                ** Once this has been done, packet needs to be re-parsed (but payload_offset should be the same)
                */
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;

                u8 *cursor_HTTP = data + payload_offset;
                int buff_len_HTTP = 4;
                u8 buff_HTTP[4];
                ret = bpf_probe_read_kernel(buff_HTTP, buff_len_HTTP, cursor_HTTP);
                if(ret != 0){
                    bpf_trace_printk("[F][E] failed to read TCP's payload\n");
                    return TC_ACT_SHOT;
                }

                /* 
                    TODO: this check should be optimized with an hash map 
                */
                if(buff_HTTP[0] == 'H' && buff_HTTP[1] == 'T' && buff_HTTP[2] == 'T' && buff_HTTP[3] == 'P'){
                    bpf_trace_printk("[F][E] Found HTTP response\n");
                } else if(buff_HTTP[0] == 'P' && buff_HTTP[1] == 'O' && buff_HTTP[2] == 'S' && buff_HTTP[3] == 'T'){
                    bpf_trace_printk("[F][E] Found HTTP POST request\n");
                } else if(buff_HTTP[0] == 'G' && buff_HTTP[1] == 'E' && buff_HTTP[2] == 'T' && buff_HTTP[3] == ' '){
                    bpf_trace_printk("[F][E] Found HTTP GET request\n");
                } else if(buff_HTTP[0] == 'P' && buff_HTTP[1] == 'U' && buff_HTTP[2] == 'T' && buff_HTTP[3] == ' '){
                    bpf_trace_printk("[F][E] Found HTTP PUT request\n");
                } else if(buff_HTTP[0] == 'D' && buff_HTTP[1] == 'E' && buff_HTTP[2] == 'L' && buff_HTTP[3] == 'E'){
                    bpf_trace_printk("[F][E] Found HTTP DELETE request\n");
                } else if(buff_HTTP[0] == 'P' && buff_HTTP[1] == 'A' && buff_HTTP[2] == 'T' && buff_HTTP[3] == 'C'){
                    bpf_trace_printk("[F][E] Found HTTP PATCH request\n");
                } else if(buff_HTTP[0] == 'O' && buff_HTTP[1] == 'P' && buff_HTTP[2] == 'T' && buff_HTTP[3] == 'I'){
                    bpf_trace_printk("[F][E] Found HTTP OPTIONS request\n");
                } else if(buff_HTTP[0] == 'H' && buff_HTTP[1] == 'E' && buff_HTTP[2] == 'A' && buff_HTTP[3] == 'D'){
                    bpf_trace_printk("[F][E] Found HTTP HEAD request\n");
                } else {
                    bpf_trace_printk("[F][E] NOT an HTTP message!\n");
                    return TC_ACT_OK;
                }

//              - extract the label from the queue, enforce security policies (NOT IMPLEMENTED), and add label to the packet
                tag = fifo.lookup(&key);
                if(tag){
                    bpf_trace_printk("[F][E] popped label: {%d, %d}\n", tag->label, tag->timestamp);
                } else {
                    bpf_trace_printk("[F][E] failed to pop label from the queue\n");
                    return TC_ACT_SHOT;
                }

                // modify the packet
                struct ethhdr eth_copy;
                struct iphdr ip_copy;
                struct tcphdr tcp_copy;
                struct label_hdr tag_copy;
                long inner_ret;

                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 12 > data_end){ /* 12 is opts length */
                    return TC_ACT_OK;
                }

                inner_ret = bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(eth_copy));
                if(inner_ret){
                    return TC_ACT_SHOT;
                }
                
                inner_ret = bpf_skb_load_bytes(skb, sizeof(*eth), &ip_copy, sizeof(ip_copy));
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip), &tcp_copy, sizeof(tcp_copy));
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                u8 opts[12];
                ret = bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp), &opts[0], 12);
                if(ret){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_adjust_room(skb, 16, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO);
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                int tmp = ip_copy.tot_len;
                tmp += 16<<8;
                ip_copy.tot_len = tmp;

                /* need recasting after bpf_skb_adjust_room */
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;

                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 12 + sizeof(tag) > data_end){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0);
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth), &ip_copy, sizeof(ip_copy), 0);
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip), &tcp_copy, sizeof(tcp_copy), 0);
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp), &opts, sizeof(opts), 0);
                if(inner_ret){
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + sizeof(opts), tag, sizeof(*tag), 0);
                if(inner_ret){
                    return TC_ACT_SHOT;
                }
                
                /* fix checksum */
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;

                if(data + sizeof(*eth) > data_end){
                    return TC_ACT_OK;
                }
                eth = data;
                if(data + sizeof(*eth) + sizeof(*ip) > data_end){
                    return TC_ACT_OK;
                }
                ip = data + sizeof(*eth);
                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end){
                    return TC_ACT_OK;
                }
                tcp = data + sizeof(*eth) + sizeof(*ip);

                ip->check = 0;
                __u64 csum = 0;
                ipv4_csum(ip, sizeof(*ip), &csum);
                ip->check = csum;

                return TC_ACT_OK;                
//          - ELSE: forward the packet (??) - eventually process TCP packets
            } else {
                return TC_ACT_OK;
            }   
        }
//      - ELSE: forward the packet (??)
        else {
            return TC_ACT_OK;
        }
    }
    return TC_ACT_OK;
}
