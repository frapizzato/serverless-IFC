// https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-readable-and-compact.c

#include "common.h"

#define RATE 1088  // Example rate in bits
#define CAPACITY 512  // Example capacity in bits
#define DELIMITED_SUFFIX 0x06  // Delimited suffix value
#define MAX_LEN 200  // Maximum input length in bytes

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct state_byte {
    uint8_t state_byte_val;
};
BPF_HASH(keccak_state_map, int, struct state_byte, MAX_LEN);


//#define KECCAKF1600_STATE_PERMUTE() \
    for (int i = 0; i < MAX_LEN; i++) { \
        keccak_state_map.update(&i, 1); /* Replace with actual transformation logic */ \
    }

int keccak_xdp(struct __sk_buff *skb) {
    unsigned int rateInBytes = RATE / 8;
    unsigned int blockSize = 0;
    int i = 0;
    int key = 0;

    // Fixed input string for hashing
    const char *input = "Hello, eBPF!";
    unsigned long long int inputByteLen = strlen(input);

    // Output buffer length (arbitrary, here for demo purposes)
    unsigned long long int outputByteLen = 32;
    uint8_t outputDigest[outputByteLen];
    unsigned long long int outputDigestStartIndex = 0;
    struct state_byte tempStruct;
    struct state_byte *lookupVal;

    if (inputByteLen > MAX_LEN) {
        bpf_trace_printk("Input too long\n");
        return XDP_PASS;
    }

    // Initialize state if it's all zeros
    tempStruct.state_byte_val = 0;
    for (i = 0; i < MAX_LEN; i++) {
        keccak_state_map.update(&i, &tempStruct);
    } 
    return XDP_PASS;/////////////////////////////

    // Absorb the input into the Keccak state
    while (inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for (i = 0; i < blockSize; i++) {
            lookupVal = keccak_state_map.lookup(&i);
            tempStruct.state_byte_val = lookupVal->state_byte_val ^ (uint8_t)input[i];
            keccak_state_map.update(&i, &tempStruct); // Absorb data
        }
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            // Apply Keccak permutation (mocked here)
            for (int i = 0; i < MAX_LEN; i++) { 
                tempStruct.state_byte_val = 1;
                keccak_state_map.update(&i, &tempStruct); /* Replace with actual transformation logic */ 
            }
            blockSize = 0;
        }
    }

    /* === Do the padding and switch to the squeezing phase === */
    lookupVal = keccak_state_map.lookup(&blockSize);
    tempStruct.state_byte_val = lookupVal->state_byte_val ^ DELIMITED_SUFFIX;
    keccak_state_map.update(&blockSize, &tempStruct);
    lookupVal = keccak_state_map.lookup(&rateInBytes-1);
    tempStruct.state_byte_val = lookupVal->state_byte_val ^ 0x80;
    keccak_state_map.update(&rateInBytes-1, &tempStruct);
    for (int i = 0; i < MAX_LEN; i++) { 
        tempStruct.state_byte_val = 1;
        keccak_state_map.update(&i, &tempStruct); /* Replace with actual transformation logic */ 
    }
    
    /* === Squeeze out all the output blocks === */
    while (outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        for (i = outputDigestStartIndex; i < outputDigestStartIndex + blockSize; i++) {
            lookupVal = keccak_state_map.lookup(&i);
            outputDigest[i] = lookupVal->state_byte_val; // Squeeze data
        }
        outputDigestStartIndex += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0) {
            for (int i = 0; i < MAX_LEN; i++) { 
                tempStruct.state_byte_val = 1;
                keccak_state_map.update(&i, &tempStruct); /* Replace with actual transformation logic */ 
            }
        }
    }

    // Retrieve state again from the map before printing
    bpf_trace_printk("Current Keccak state:\n");
    for (i = 0; i < MAX_LEN; i++) {
            bpf_trace_printk("%x", outputDigest[i]);
        }
    return XDP_PASS;
}
