#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

#define RATE 1088  // Example rate in bits
#define CAPACITY 512  // Example capacity in bits
#define DELIMITED_SUFFIX 0x06  // Delimited suffix value
#define MAX_LEN 200  // Maximum input length in bytes

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct state_byte {
    __u8 state_byte_val;  // Use explicit type for byte values
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct state_byte));
    __uint(max_entries, MAX_LEN);
} keccak_state_map SEC(".maps");

SEC("xdp")
int keccak_xdp(struct xdp_md *ctx) {
    unsigned int rateInBytes = RATE / 8;
    unsigned int blockSize = 0;
    unsigned int i = 0;

    // Fixed input string for hashing
    const char input[] = "Hello, eBPF!";
    unsigned long long int inputByteLen = sizeof(input) - 1;

    // Output buffer length (arbitrary, here for demo purposes)
    unsigned long long int outputByteLen = 32;
    __u8 outputDigest[32] = {0};
    unsigned long long int outputDigestStartIndex = 0;
    struct state_byte tempStruct = {0};
    struct state_byte *lookupVal;

    if (inputByteLen > MAX_LEN) {
        bpf_printk("Input too long\n");
        return XDP_PASS;
    }

    // Initialize state
    for (i = 0; i < MAX_LEN; i++) {
        tempStruct.state_byte_val = 0;
        bpf_map_update_elem(&keccak_state_map, &i, &tempStruct, BPF_ANY);
    }

    // Absorb the input into the Keccak state
    __u8 offset = 0;
    while (inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for (i = 0; i < blockSize; i++) {
            __u8 index = offset + i;
            lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
            if (!lookupVal) continue;
            if (i < inputByteLen) { //This check is needed by the verifier, even if it should be implicit
                tempStruct.state_byte_val = lookupVal->state_byte_val ^ input[i];
            }
            bpf_map_update_elem(&keccak_state_map, &index, &tempStruct, BPF_ANY);
        }
        offset += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            // Apply Keccak permutation (mocked here)
            for (i = 0; i < MAX_LEN; i++) {
                tempStruct.state_byte_val = 1;
                bpf_map_update_elem(&keccak_state_map, &i, &tempStruct, BPF_ANY);
            }
        }
    }

    // Padding
    unsigned int padIndex = offset;
    lookupVal = bpf_map_lookup_elem(&keccak_state_map, &padIndex);
    if (lookupVal) {
        tempStruct.state_byte_val = lookupVal->state_byte_val ^ DELIMITED_SUFFIX;
        bpf_map_update_elem(&keccak_state_map, &padIndex, &tempStruct, BPF_ANY);
    }

    unsigned int lastIndex = rateInBytes - 1;
    lookupVal = bpf_map_lookup_elem(&keccak_state_map, &lastIndex);
    if (lookupVal) {
        tempStruct.state_byte_val = lookupVal->state_byte_val ^ 0x80;
        bpf_map_update_elem(&keccak_state_map, &lastIndex, &tempStruct, BPF_ANY);
    }

    // Output
    while (outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        for (i = outputDigestStartIndex; i < outputDigestStartIndex + blockSize; i++) {
            unsigned int index = i % MAX_LEN;
            lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
            if (lookupVal) {
                outputDigest[i] = lookupVal->state_byte_val;
            }
        }
        outputDigestStartIndex += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0) {
            for (i = 0; i < MAX_LEN; i++) {
                tempStruct.state_byte_val = 1;
                bpf_map_update_elem(&keccak_state_map, &i, &tempStruct, BPF_ANY);
            }
        }
    }

    // Log the state
    bpf_printk("Keccak state:");
    __u8 value = 0;
    for (i = 0; i < 32; i++) {
        value = outputDigest[i]; 
        //bpf_printk("%02x", value); //Not the right way of printing things
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";