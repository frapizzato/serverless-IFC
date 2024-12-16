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

struct loop_ctx {
    unsigned long long int inputByteLen;
    const char *input;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct state_byte));
    __uint(max_entries, MAX_LEN);
} keccak_state_map SEC(".maps");

static int forLoop_inputAbsorbing(struct loop_ctx *input_ctx) {
    unsigned long long int inputByteLen = input_ctx->inputByteLen;
    const char *input = input_ctx->input;
    struct state_byte tempStruct = {0};
    struct state_byte *lookupVal;
    __u8 *offset;
    __u8 *i;
    __u8 index = *offset + *i;
    lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
    if (!lookupVal) return 1;
    if (*i < inputByteLen) { //This check is needed by the verifier, even if it should be implicit
        tempStruct.state_byte_val = lookupVal->state_byte_val ^ input[*i];
        }
    bpf_map_update_elem(&keccak_state_map, &index, &tempStruct, BPF_ANY);
    *i += 1;
    return 0;
}

static int forLoop_initializingState(struct state_byte *tempStruct) {
    __u8 *i;
    tempStruct->state_byte_val = 0;
    bpf_map_update_elem(&keccak_state_map, i, &tempStruct, BPF_ANY);
    return 0;
}

SEC("xdp")
int keccak_xdp(struct xdp_md *ctx) {
    unsigned int rateInBytes = RATE / 8;
    unsigned int blockSize = 0;
    unsigned int *i;
    unsigned int j;

    // Fixed input string for hashing
    const char input[] = "Hello, eBPF!";
    unsigned long long int inputByteLen = sizeof(input) - 1;
    struct loop_ctx input_ctx = {inputByteLen, input};

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
    *i = 0;
    bpf_loop(MAX_LEN, forLoop_initializingState, &tempStruct, 0);

    // Absorb the input into the Keccak state
    __u8 *offset;
    *offset = 0;
    while (inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        *i = 0;
        bpf_loop(blockSize, forLoop_inputAbsorbing, &input_ctx, 0);
        offset += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            // Apply Keccak permutation (mocked here)
            for (j = 0; j < MAX_LEN; j++) {
                tempStruct.state_byte_val = 1;
                bpf_map_update_elem(&keccak_state_map, &j, &tempStruct, BPF_ANY);
            }
        }
    }

    // Padding
    unsigned int padIndex = *offset;
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
        for (j = outputDigestStartIndex; j < outputDigestStartIndex + blockSize; j++) {
            unsigned int index = j % MAX_LEN;
            lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
            if (lookupVal) {
                outputDigest[j] = lookupVal->state_byte_val;
            }
        }
        outputDigestStartIndex += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0) {
            for (j = 0; j < MAX_LEN; j++) {
                tempStruct.state_byte_val = 1;
                bpf_map_update_elem(&keccak_state_map, &j, &tempStruct, BPF_ANY);
            }
        }
    }

    // Log the state
    bpf_printk("Keccak state:");
    __u8 value = 0;
    for (j = 0; j < 32; j++) {
        value = outputDigest[j]; 
        //bpf_printk("%02x", value); //Not the right way of printing
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";