//#include <linux/bpf.h>
//#include "/home/id03141/libbpf/include/uapi/linux/bpf.h"
//#include "/usr/local/include/bpf/bpf.h"
//#include <linux/if_ether.h>
//#include <linux/if_packet.h>
//#include <linux/ip.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "hash.bpf.h"


SEC("xdp")
int keccak_xdp(struct xdp_md *ctx) {
    __u8 rateInBytes = RATE / 8;
    __u8 blockSize = 0;
    __u8 i = 0;

    // Fixed input string for hashing
    const unsigned char input[] = "Hello, eBPF! I am a string that will be hashed by Keccak. Remember that the input lenght must be higher than the rate if we want to perform the Keccak permutation in the absorbing phase.";
    short int inputByteLen = sizeof(input) - 1;
    //bpf_printk("inputByteLen: %d\n", inputByteLen);

    // Output buffer length (arbitrary, here for demo purposes)
    __u8 outputByteLen = 32;
    __u8 outputDigest[32] = {0};
    __u8 outputDigestStartIndex = 0;
    struct state_byte tempStruct = {0};
    struct state_byte *lookupVal;

    if (inputByteLen > MAX_LEN) {
        bpf_printk("Input too long\n");
        return XDP_PASS;
    }

    // Initialize state
    //for (i = 0; i < MAX_LEN; i++) {
        //tempStruct.state_byte_val = 0;
        //bpf_map_update_elem(&keccak_state_map, &i, &tempStruct, BPF_ANY);
    //}
    __u8 counter = 0;
    bpf_loop(MAX_LEN, initializing_state, &counter, 0);

    // Absorb the input into the Keccak state
    __u8 offset = 0;

    struct callback_ctx callback_ctx;
    while (inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        /*
        for (i = 0; i < blockSize; i++) {
            //bpf_printk("input[i]: %d\n", input[i]);
            __u8 index = offset + i;
            lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
            if (!lookupVal) continue;
            if (i < inputByteLen) { //This check is needed by the verifier, even if it should be implicit
                tempStruct.state_byte_val = lookupVal->state_byte_val ^ input[i];
            }
            bpf_map_update_elem(&keccak_state_map, &index, &tempStruct, BPF_ANY);
        }
        */
        counter = 0;
        callback_ctx.offset = offset;
        callback_ctx.input = input;
        callback_ctx.counter = counter;
        bpf_loop(blockSize, absorbing_input, &callback_ctx, 0);

        offset += blockSize;
        inputByteLen -= blockSize;
        
        /*
        // Print state for debugging
        for (i = 0; i < 200; i++) {
            __u8 index = i;
            lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
            //if (lookupVal) {
                //bpf_printk("BEFORE PERM byte no. %d, state_byte_val: %d\n", index, lookupVal->state_byte_val);
            //}
        }
        */

        if (blockSize == rateInBytes) {
            //bpf_printk("HERE INPUT\n");
            // Apply Keccak permutation
            int res = KeccakF1600_StatePermute();  //state is stored inside the hash map, each byte is a state_byte struct, 200 bytes in total
            blockSize = 0;
            
            /*
            // Print state for debugging
            for (i = 0; i < 200; i++) {
                __u8 index = i;
                lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
                if (lookupVal) {
                    bpf_printk("AFTER PERM byte no. %d, state_byte_val: %d\n", index, lookupVal->state_byte_val);
                }
            }
            */
        }
       
    }

    // Padding
    __u8 padIndex = offset;
    lookupVal = bpf_map_lookup_elem(&keccak_state_map, &padIndex);
    if (lookupVal) {
        tempStruct.state_byte_val = lookupVal->state_byte_val ^ DELIMITED_SUFFIX;
        bpf_map_update_elem(&keccak_state_map, &padIndex, &tempStruct, BPF_ANY);
    }

    __u8 lastIndex = rateInBytes - 1;
    lookupVal = bpf_map_lookup_elem(&keccak_state_map, &lastIndex);
    if (lookupVal) {
        tempStruct.state_byte_val = lookupVal->state_byte_val ^ 0x80;
        bpf_map_update_elem(&keccak_state_map, &lastIndex, &tempStruct, BPF_ANY);
    }

    // Output
    while (outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        for (i = outputDigestStartIndex; i < outputDigestStartIndex + blockSize; i++) {
            __u8 index = i % MAX_LEN;
            lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
            if (lookupVal) {
                outputDigest[i] = lookupVal->state_byte_val;
                //bpf_printk("i: %d\n", i);
            }
        }
        outputDigestStartIndex += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0) {
            bpf_printk("HERE OUTPUT\n");
            int res = KeccakF1600_StatePermute();  //state is stored inside the hash map, each byte is a state_byte struct, 200 bytes in total
        }
    }

    // Log the state
    bpf_printk("Keccak state:");
    __u8 value = 0;
    /*
    for (i = 0; i < 32; i++) {
        value = outputDigest[i]; 
        bpf_printk("%02x", value);
    }
    */
    value = outputDigest[0]; 
    bpf_printk("%02x", value);
    value = outputDigest[1];
    bpf_printk("%02x", value);
    value = outputDigest[2];
    bpf_printk("%02x", value);
    value = outputDigest[3];
    bpf_printk("%02x", value);
    value = outputDigest[4];
    bpf_printk("%02x", value);
    value = outputDigest[5];
    bpf_printk("%02x", value);
    value = outputDigest[6];
    bpf_printk("%02x", value);
    value = outputDigest[7];
    bpf_printk("%02x", value);
    value = outputDigest[8];
    bpf_printk("%02x", value);
    value = outputDigest[9];
    bpf_printk("%02x", value);
    value = outputDigest[10];
    bpf_printk("%02x", value);
    value = outputDigest[11];
    bpf_printk("%02x", value);
    value = outputDigest[12];
    bpf_printk("%02x", value);
    value = outputDigest[13];
    bpf_printk("%02x", value);
    value = outputDigest[14];
    bpf_printk("%02x", value);
    value = outputDigest[15];
    bpf_printk("%02x", value);
    value = outputDigest[16];
    bpf_printk("%02x", value);
    value = outputDigest[17];
    bpf_printk("%02x", value);
    value = outputDigest[18];
    bpf_printk("%02x", value);
    value = outputDigest[19];
    bpf_printk("%02x", value);
    value = outputDigest[20];
    bpf_printk("%02x", value);
    value = outputDigest[21];
    bpf_printk("%02x", value);
    value = outputDigest[22];
    bpf_printk("%02x", value);
    value = outputDigest[23];
    bpf_printk("%02x", value);
    value = outputDigest[24];
    bpf_printk("%02x", value);
    value = outputDigest[25];
    bpf_printk("%02x", value);
    value = outputDigest[26];
    bpf_printk("%02x", value);
    value = outputDigest[27];
    bpf_printk("%02x", value);
    value = outputDigest[28];
    bpf_printk("%02x", value);
    value = outputDigest[29];
    bpf_printk("%02x", value);
    value = outputDigest[30];
    bpf_printk("%02x", value);
    value = outputDigest[31];
    bpf_printk("%02x", value);
 
    return XDP_PASS;
}


char LICENSE[] SEC("license") = "GPL";