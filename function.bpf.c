#include "common.h"


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

// Map to retrieve the label associated with the function's pod
struct string_key {
    __u8    value[63];
};        
BPF_TABLE_PINNED("hash", struct string_key, u32, pod_tags_map, 1024, "/sys/fs/bpf/pod_tags");

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
    u32 payload_length = bpf_ntohs(ip->tot_len) - ip_header_length - tcp_header_length;
    long ret;
    int key = 0;

    if(DEBUG){
        bpf_trace_printk("[F][I] total length: %d\n", data_end - data);
        bpf_trace_printk("[F][I] payload length: %d\n", payload_length);
        bpf_trace_printk("[F][I] payload offset: %d\n", payload_offset);
        bpf_trace_printk("[F][I] tcp header length: %d (sizeof TCP: %d)\n", tcp_header_length, sizeof(*tcp));
        bpf_trace_printk("[F][I] ip header length: %d (sizeof IP: %d)\n", ip_header_length, sizeof(*ip));
    }

//  check packet source, if it is the GW or not, and if it needs to be tagged
    int *ip_decision = tags_map.lookup(&ip->saddr);
    if(ip_decision != NULL){
        if(*ip_decision == 1){
//  check if it is an HTTP message
            if(payload_length > HTTP_AND_LABEL_LEN){
                u8 *cursor_HTTP = data + payload_offset;
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
                    if(DEBUG)
                        bpf_trace_printk("[F][I] NOT an HTTP message!\n");
                    return XDP_PASS;
                }
//  extract the label from the packet, push it to the local storage, - and enforce security policies (NOT IMPLEMENTED)
                //if(data + sizeof(*eth) + sizeof(*ip) + tcp_header_length > data_end){
                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 12 + sizeof(*tag) > data_end){
                    bpf_trace_printk("[F][I] Packet is too short to have tag\n");
                    return XDP_PASS;
                }

                //tag = data + sizeof(*eth) + sizeof(*ip) + tcp_header_length - sizeof(*tag);
                tag = data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 12;
                bpf_trace_printk("[F][I] received label. Id = %u, F_CNT = %u, LABELS = [", tag->id_label, tag->f_counter);
                for(int k=0; k<6; k++){
                    bpf_trace_printk("|%u%u%u|", tag->label[k].value[0], tag->label[k].value[1], tag->label[k].value[2]);
                }
                bpf_trace_printk("]}.\n");
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

                ret = bpf_xdp_adjust_head(ctx, LABEL_LEN); /* move xdp_md.data to the right by 36 bytes (len of tag) */
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
                int tmp = bpf_ntohs(ip_copy.tot_len);
                tmp -= LABEL_LEN;
                ip_copy.tot_len = bpf_htons(tmp);

                tmp = tcp_copy.doff;
                tmp -= LABEL_LEN_32b;
                tcp_copy.doff = tmp;

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

                if(DEBUG)
                    bpf_trace_printk("[F][I] forwarding modified packet\n");
                return XDP_PASS;
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

    char whoAmI[]="POD_NAME";

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
    u32 payload_length = skb->len - ip_header_length - tcp_header_length - ETH_HDR;
    long ret;
    int key = 0;
    
    if(DEBUG){
        bpf_trace_printk("[F][E] total length: %d\n", skb->len);
        bpf_trace_printk("[F][E] payload length: %d\n", payload_length);
        bpf_trace_printk("[F][E] payload offset: %d\n", payload_offset);
        bpf_trace_printk("[F][E] tcp header length: %d\n", tcp_header_length);
        bpf_trace_printk("[F][E] ip header length: %d\n", ip_header_length);
    }   

//  check on packet destination, if it is GW or not, and if it needs to be tagged
    int *ip_decision = tags_map.lookup(&ip->daddr); 
    if(ip_decision != NULL){ 
        if(*ip_decision == 1){
            if(DEBUG)
                bpf_trace_printk("[F][E] Processing internal packet that has to be tagged\n");

//  check if it is an HTTP message
            if(payload_length > HTTP_LEN){
                
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
                        //TEST
                        //bpf_trace_printk("[F][E] Packet is too short\n");
                        //return TC_ACT_OK;
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
                    if(DEBUG){
                        bpf_trace_printk("[F][E] NOT an HTTP message!\n");
                    }
                    return TC_ACT_OK;
                }

//  extract the label from the local storage, enforce security policies (NOT IMPLEMENTED), and add label to the packet
                tag = fifo.lookup(&key);
                if(tag){
                    bpf_trace_printk("[F][E] popped label. Id = %u, F_CNT = %u, LABELS = [", tag->id_label, tag->f_counter);
                    for(int k=0; k<6; k++){
                        bpf_trace_printk("|%u%u%u|", tag->label[k].value[0], tag->label[k].value[1], tag->label[k].value[2]);
                    }
                    bpf_trace_printk("]}.\n");
                } else {
                    bpf_trace_printk("[F][E] failed to pop label from the queue\n");
                    return TC_ACT_SHOT;
                }

//  modify the tag
                /*
                ** IDEA: check the function counter, write the function label on the label list, increment counter
                */
                int value_f_counter = tag->f_counter & 0x7; // consider only 3 bits
                // retrieve tags using the function name (padded to 63 bytes with 0)
                struct string_key key_pod;
                __builtin_memset(key_pod.value, 0, sizeof(key_pod.value));
                
                for(int k=0; k<sizeof(whoAmI); k++){
                    if(k < sizeof(key_pod.value))
                        key_pod.value[k] = whoAmI[k];
                }
                
                //__builtin_memcpy(key_pod.value, whoAmI, sizeof(whoAmI));
                bpf_trace_printk("[F][E] Looking for tag for the function with key:\n");
                for(int k=0; k<63; k++){
                    bpf_trace_printk("%c", key_pod.value[k]);
                }
                
                u32 *value_pod = pod_tags_map.lookup(&key_pod);

                if(value_pod){
                    bpf_trace_printk("[F][E] Found tag for the function\n");
                } else {
                    bpf_trace_printk("[F][E] Tag not found for the function\n");
                    return TC_ACT_SHOT;
                }

                u32 value_tmp = *value_pod;
                bpf_trace_printk("[F][E] Found tag for the function (%u)\n", value_tmp);
                
                u32 function_tag = (*value_pod) & 0xFFFFFF; //only care about 24 bits
                struct custom_24b function_tag_24;
                /*
                if(function_tag > 0xFFFFFF){
                    bpf_trace_printk("[F][E] function tag is too big\n");
                    return TC_ACT_SHOT;
                }
                */
                function_tag_24.value[2] = (function_tag >> 16) & 0xFF;
                function_tag_24.value[1] = (function_tag >> 8) & 0xFF;
                function_tag_24.value[0] = function_tag & 0xFF;

                

                if(value_f_counter < 6){
                    tag->label[value_f_counter] = function_tag_24;
                    tag->f_counter = value_f_counter + 1;
                } else { // TEST: what to do?
                    return TC_ACT_SHOT;
                }
                
                
                bpf_trace_printk("[F][E] updated label. Id = %u, F_CNT = %u, LABELS = [", tag->id_label, tag->f_counter);
                for(int k=0; k<6; k++){
                    bpf_trace_printk("|%u%u%u|", tag->label[k].value[0], tag->label[k].value[1], tag->label[k].value[2]);
                }
                bpf_trace_printk("]}.\n");
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
                    bpf_trace_printk("[F][E] failed to load eth\n");
                    return TC_ACT_SHOT;
                }
                
                inner_ret = bpf_skb_load_bytes(skb, sizeof(*eth), &ip_copy, sizeof(ip_copy));
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to load ip\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip), &tcp_copy, sizeof(tcp_copy));
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to load tcp\n");
                    return TC_ACT_SHOT;
                }

                u8 opts[12];
                ret = bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp), &opts[0], 12);
                if(ret){
                    bpf_trace_printk("[F][E] failed to load opts\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_adjust_room(skb, LABEL_LEN, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO);
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to adjust room\n");
                    return TC_ACT_SHOT;
                }


                int tmp = bpf_ntohs(ip_copy.tot_len);
                tmp += LABEL_LEN;
                ip_copy.tot_len = bpf_htons(tmp);

                if(DEBUG)
                    bpf_trace_printk("[F][E] Initial TCP data offset: %d\n", tcp_copy.doff);
                tmp = tcp_copy.doff;
                tmp += LABEL_LEN_32b;
                tcp_copy.doff = tmp;
                if(DEBUG)
                    bpf_trace_printk("[F][E] New TCP data offset: %d\n", tcp_copy.doff);

                /* need recasting after bpf_skb_adjust_room */
                data = (void *)(long)skb->data;
                data_end = (void *)(long)skb->data_end;

                if(data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + 12 + sizeof(tag) > data_end){
                    bpf_trace_printk("[F][E] Packet is too short\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0);
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to store eth\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth), &ip_copy, sizeof(ip_copy), 0);
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to store ip\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip), &tcp_copy, sizeof(tcp_copy), 0);
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to store tcp\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp), &opts, sizeof(opts), 0);
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to store opts\n");
                    return TC_ACT_SHOT;
                }

                inner_ret = bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + sizeof(opts), tag, sizeof(*tag), 0);
                if(inner_ret){
                    bpf_trace_printk("[F][E] failed to store tag\n");
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
        
                if(DEBUG)
                    bpf_trace_printk("[F][E] updating checksum\n");
                ip->check = 0;
                __u64 csum = 0;
                ipv4_csum(ip, sizeof(*ip), &csum);
                ip->check = csum;
                
                if(DEBUG)
                    bpf_trace_printk("[F][E] forwarding modified packet\n");
                return TC_ACT_OK;                
            } else {
                if(DEBUG)
                    bpf_trace_printk("[F][E] Packet payload not long enough to contain HTTP\n");
                return TC_ACT_OK;
            }   
        } else {
            if(DEBUG)
                bpf_trace_printk("[F][E] Packet does not need to be tagged (IP.decision %d, IP %lu)\n", *ip_decision, ip->daddr);
            return TC_ACT_OK;
        }
    }

    if(DEBUG)
        bpf_trace_printk("[F][E] Packet is external (IP.decision %d)\n", *ip_decision);
    return TC_ACT_OK;
}
