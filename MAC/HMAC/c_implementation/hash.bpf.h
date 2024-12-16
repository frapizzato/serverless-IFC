#define RATE 1088  // Example rate in bits
#define CAPACITY 512  // Example capacity in bits
#define DELIMITED_SUFFIX 0x06  // Delimited suffix value
#define STATE_LEN 200  // State length in bytes
#define MAX_LEN 400  // Maximum input length in bytes

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct state_byte {
    __u8 state_byte_val;  // Use explicit type for byte values
};

struct callback_ctx {
    __u8 offset;
    const unsigned char *input;
    int counter;
};


struct struct_read_lane {
    int x;      //1st input
    int y;      //2nd input
    __u64 lane; //output
};

struct struct_write_lane {
    int x;      //1st input
    int y;      //2nd input
    __u64 value; //3rd input
};

struct struct_xor_lane {
    int x;      //1st input
    int y;      //2nd input
    __u64 value; //3rd input
};


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct struct_read_lane);
} read_lane_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct struct_write_lane);
} write_lane_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct struct_xor_lane);
} xor_lane_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u8));
    __uint(value_size, sizeof(struct state_byte));
    __uint(max_entries, STATE_LEN);
} keccak_state_map SEC(".maps");

static int initializing_state(void *ctx, __u8 *counter_addr) {
    struct state_byte tempStruct;
    tempStruct.state_byte_val = 0;
    bpf_map_update_elem(&keccak_state_map, counter_addr, &tempStruct, BPF_ANY);
    (*counter_addr)++;
    return 0;
}

static int absorbing_input(void *ctx, struct callback_ctx *callback_ctx_addr) 
{
    struct state_byte *lookupVal;
    struct state_byte tempStruct = {0};
    int inputByteLen = sizeof(callback_ctx_addr->input) - 1;
    //bpf_printk("input[i]: %d\n", input[i]);
    __u8 index = callback_ctx_addr->offset + callback_ctx_addr->counter;
    lookupVal = bpf_map_lookup_elem(&keccak_state_map, &index);
    if (lookupVal)
    {
        //This check is needed by the verifier, even if it should be implicit
        if (callback_ctx_addr->counter < inputByteLen && callback_ctx_addr->counter >= 0) { 
            tempStruct.state_byte_val = lookupVal->state_byte_val ^ callback_ctx_addr->input[callback_ctx_addr->counter];
        }
        bpf_map_update_elem(&keccak_state_map, &index, &tempStruct, BPF_ANY);
    }

    callback_ctx_addr->counter++;
    return 0;
}

/**
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
int LFSR86540(__u8 *LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        /* Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1 */
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

static __u64 ROL64(__u64 a, __u8 offset) {
    return (a << offset) ^ (a >> (64 - offset));
}

/*
static __u8 compute_key(int x, int y) {
    return (__u8)(x + 5*y);
}
*/

static int read_lane(void *ctx, struct struct_read_lane *input_struct) {
    __u64 lane = 0;
    int key = 0;
    struct state_byte *byte;
    struct struct_read_lane *read_lane_data = bpf_map_lookup_elem(&read_lane_map, &key);
    if (!read_lane_data)
        return 1;
    //int x = read_lane_data->x;
    //int y = read_lane_data->y;
    /*
    for (int b = 0; b < 8; b++) {
        __u8 key = compute_key(x, y);
        struct state_byte *byte = bpf_map_lookup_elem(&keccak_state_map, &key);
        if (byte)
            lane |= ((__u64)byte->state_byte_val) << (8 * b);
    }
    */
    key = (__u8)(read_lane_data->x + 5*read_lane_data->y);
    __u8 key_byte;

    key_byte = key + 0;
    if (key_byte >= STATE_LEN)
        return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 0);
    }

    key_byte = key + 1;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 1);
    }

    key_byte = key + 2;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 2);
    }

    key_byte = key + 3;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 3);
    }

    key_byte = key + 4;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 4);
    }

    key_byte = key + 5;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 5);
    }

    key_byte = key + 6;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 6);
    }

    key_byte = key + 7;
    if (key_byte >= STATE_LEN)
    return 1;
    byte = bpf_map_lookup_elem(&keccak_state_map, &key_byte);
    if (byte) {
        lane |= ((__u64)byte->state_byte_val) << (8 * 7);
    }

    //bpf_printk("lane read\n");
    //printing lane
    //bpf_printk("lane: %d\n", lane);
    
    read_lane_data->lane = lane;
    return 0;
}

static int write_lane(void *ctx, struct struct_write_lane *input_struct) {
    int key = 0;
    struct state_byte new_byte;
    //int x, y;
    //__u64 value;

    // Retrieve write_lane_data from the map
    struct struct_write_lane *write_lane_data = bpf_map_lookup_elem(&write_lane_map, &key);
    if (!write_lane_data)
        return 1;

    //x = write_lane_data->x;
    //y = write_lane_data->y;
    //value = write_lane_data->value;

    /*
    for (int b = 0; b < 8; b++) {
        __u8 key = compute_key(x, y);
        struct state_byte new_byte = {.state_byte_val = (value >> (8 * b)) & 0xFF};
        bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);
    }
    */
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y);
    new_byte.state_byte_val = (write_lane_data->value >> (8 * 0)) & 0xFF;
    //bpf_printk("byte: %d\n", value);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 1)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 1);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 2)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 2);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 3)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 3);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 4)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 4);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 5)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 5);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 6)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 6);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);

    new_byte.state_byte_val = (write_lane_data->value >> (8 * 7)) & 0xFF;
    key = (__u8)(write_lane_data->x + 5*write_lane_data->y + 7);
    bpf_map_update_elem(&keccak_state_map, &key, &new_byte, BPF_ANY);
    //bpf_printk("lane written\n");

    //checking written lane using bpf_map_lookup_elem
    //struct state_byte *lookupVal;
    //key = (__u8)(x + 5*y);
    //lookupVal = bpf_map_lookup_elem(&keccak_state_map, &key);
    //if (lookupVal) {
        //bpf_printk("lane written: %d\n", lookupVal->state_byte_val);
    //}
    return 0;
}


static int xor_lane(void *ctx, struct struct_write_lane *input_struct) {  
    int key = 0;
    //__u64 lane;

    struct struct_read_lane *read_lane_data = bpf_map_lookup_elem(&read_lane_map, &key);
    if (!read_lane_data)
        return 1;

    //read_lane_data->x = input_struct->x;
    //read_lane_data->y = input_struct->y;
    //In this way we are uploading also the value field of input_struct since the struct_read_lane has the same fields, 
    //but that will be ignored
    bpf_map_update_elem(&read_lane_map, &key, input_struct, BPF_ANY); 

    bpf_loop(1, read_lane, &key, 0);

    //lane = read_lane_data->lane ^ input_struct->value;

    struct struct_write_lane *write_lane_data = bpf_map_lookup_elem(&write_lane_map, &key);
    if (!write_lane_data)
        return 1;
    //write_lane_data->x = input_struct->x;
    //write_lane_data->y = input_struct->y;
    //write_lane_data->value = read_lane_data->lane ^ input_struct->value;
    //We overwrite the value field of input_struct (since we used it already) with the value of read_lane_data->lane ^ input_struct->value
    input_struct->value = read_lane_data->lane ^ input_struct->value;
    bpf_map_update_elem(&write_lane_map, &key, input_struct, BPF_ANY);

    bpf_loop(1, write_lane, &key, 0);

    return 0;
}


int KeccakF1600_StatePermute()
{
    //unsigned int round, x, y, j, t;
    __u8 LFSRstate = 0x01;
    __u8 offset1[] = {4, 0, 1, 2, 3}; // (x + 4) % 5
    __u8 offset2[] = {1, 2, 3, 4, 0}; // (x + 1) % 5
    __u8 offset3[] = {2, 3, 4, 0, 1}; // (x + 2) % 5
    __u8 safe_index1;
    __u8 safe_index2;
    //__u64 first_lane, second_lane, third_lane, fourth_lane, fifth_lane;
    struct struct_read_lane *read_lane_data;
    struct struct_write_lane *write_lane_data;
    //struct struct_xor_lane *xor_lane_data;
    struct struct_write_lane temp_struct; //It will be used for read, write and xor lane functions since the structures are the same
    int key = 0;
    __u64 C[5], D;
    __u8 r;
    __u8 Y;
    __u64 current, temp;
    __u8 bitPosition;
    __u8 round;


    for (round = 0; round < 24; round++) {
        //bpf_printk("round: %d\n", round);
        /* === θ step === */
        /*
        for (x = 0; x < 5; x++)
            C[x] = read_lane(x, 0) ^ read_lane(x, 1) ^ read_lane(x, 2) ^ read_lane(x, 3) ^ read_lane(x, 4);
        */
        /*
        C[0] = read_lane(0, 0) ^ read_lane(0, 1) ^ read_lane(0, 2) ^ read_lane(0, 3) ^ read_lane(0, 4);
        C[1] = read_lane(1, 0) ^ read_lane(1, 1) ^ read_lane(1, 2) ^ read_lane(1, 3) ^ read_lane(1, 4);
        C[2] = read_lane(2, 0) ^ read_lane(2, 1) ^ read_lane(2, 2) ^ read_lane(2, 3) ^ read_lane(2, 4);
        C[3] = read_lane(3, 0) ^ read_lane(3, 1) ^ read_lane(3, 2) ^ read_lane(3, 3) ^ read_lane(3, 4);
        C[4] = read_lane(4, 0) ^ read_lane(4, 1) ^ read_lane(4, 2) ^ read_lane(4, 3) ^ read_lane(4, 4);
        */

        read_lane_data = bpf_map_lookup_elem(&read_lane_map, &key);
        if (!read_lane_data)
            return 1;
        read_lane_data->x = 0;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &key, 0);
        C[0] = read_lane_data->lane;
        read_lane_data->y = 1;
        bpf_loop(1, read_lane, &key, 0);
        C[0] ^= read_lane_data->lane;
        read_lane_data->y = 2;
        bpf_loop(1, read_lane, &key, 0);
        C[0] ^= read_lane_data->lane;
        read_lane_data->y = 3;
        bpf_loop(1, read_lane, &key, 0);
        C[0] ^= read_lane_data->lane;
        read_lane_data->y = 4;
        bpf_loop(1, read_lane, &key, 0);
        C[0] ^= read_lane_data->lane;
        //C[0] = first_lane ^ second_lane ^ third_lane ^ fourth_lane ^ fifth_lane;
        read_lane_data->x = 1;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &key, 0);
        C[1] = read_lane_data->lane;
        read_lane_data->y = 1;
        bpf_loop(1, read_lane, &key, 0);
        C[1] ^= read_lane_data->lane;
        read_lane_data->y = 2;
        bpf_loop(1, read_lane, &key, 0);
        C[1] ^= read_lane_data->lane;
        read_lane_data->y = 3;
        bpf_loop(1, read_lane, &key, 0);
        C[1] ^= read_lane_data->lane;
        read_lane_data->y = 4;
        bpf_loop(1, read_lane, &key, 0);
        C[1] ^= read_lane_data->lane;
        //C[1] = first_lane ^ second_lane ^ third_lane ^ fourth_lane ^ fifth_lane;
        read_lane_data->x = 2;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &key, 0);
        C[2] = read_lane_data->lane;
        read_lane_data->y = 1;
        bpf_loop(1, read_lane, &key, 0);
        C[2] ^= read_lane_data->lane;
        read_lane_data->y = 2;
        bpf_loop(1, read_lane, &key, 0);
        C[2] ^= read_lane_data->lane;
        read_lane_data->y = 3;
        bpf_loop(1, read_lane, &key, 0);
        C[2] ^= read_lane_data->lane;
        read_lane_data->y = 4;
        bpf_loop(1, read_lane, &key, 0);
        C[2] ^= read_lane_data->lane;
        //C[2] = first_lane ^ second_lane ^ third_lane ^ fourth_lane ^ fifth_lane;
        read_lane_data->x = 3;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &key, 0);
        C[3] = read_lane_data->lane;
        read_lane_data->y = 1;
        bpf_loop(1, read_lane, &key, 0);
        C[3] ^= read_lane_data->lane;
        read_lane_data->y = 2;
        bpf_loop(1, read_lane, &key, 0);
        C[3] ^= read_lane_data->lane;
        read_lane_data->y = 3;
        bpf_loop(1, read_lane, &key, 0);
        C[3] ^= read_lane_data->lane;
        read_lane_data->y = 4;
        bpf_loop(1, read_lane, &key, 0);
        C[3] ^= read_lane_data->lane;
        //C[3] = first_lane ^ second_lane ^ third_lane ^ fourth_lane ^ fifth_lane;
        read_lane_data->x = 4;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &key, 0);
        C[4] = read_lane_data->lane;
        read_lane_data->y = 1;
        bpf_loop(1, read_lane, &key, 0);
        C[4] ^= read_lane_data->lane;
        read_lane_data->y = 2;
        bpf_loop(1, read_lane, &key, 0);
        C[4] ^= read_lane_data->lane;
        read_lane_data->y = 3;
        bpf_loop(1, read_lane, &key, 0);
        C[4] ^= read_lane_data->lane;
        read_lane_data->y = 4;
        bpf_loop(1, read_lane, &key, 0);
        C[4] ^= read_lane_data->lane;
        //C[4] = first_lane ^ second_lane ^ third_lane ^ fourth_lane ^ fifth_lane;

        /*
        for (x = 0; x < 5; x++) {
            safe_index1 = offset1[x];
            safe_index2 = offset2[x];
            D = C[safe_index1] ^ ROL64(C[safe_index2], 1);
            
            for (y = 0; y < 5; y++)
                xor_lane(x, y, D);
        }
        */
        safe_index1 = offset1[0];
        safe_index2 = offset2[0];
        D = C[safe_index1] ^ ROL64(C[safe_index2], 1);
        bpf_printk("D: %u", D);

        /*
        xor_lane(0, 0, D);
        xor_lane(0, 1, D);
        xor_lane(0, 2, D);
        xor_lane(0, 3, D);
        xor_lane(0, 4, D);
        */
        //xor_lane_data = bpf_map_lookup_elem(&xor_lane_map, &key);
        //if (!xor_lane_data)
            //return 1;

        //xor_lane_data->x = 0;
        //xor_lane_data->y = 0;
        //xor_lane_data->value = D;
        temp_struct.x = 0;
        temp_struct.y = 0;
        temp_struct.value = D;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 1;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 2;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 3;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 4;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        //checking xor_lane function
        bpf_loop(1, read_lane, &read_lane_data, 0);
        bpf_printk("xor_lane(0, 4, D): %d\n", read_lane_data->lane);
        //////////////////////////////////

        safe_index1 = offset1[1];
        safe_index2 = offset2[1];
        D = C[safe_index1] ^ ROL64(C[safe_index2], 1);

        /*
        xor_lane(1, 0, D);
        xor_lane(1, 1, D);
        xor_lane(1, 2, D);
        xor_lane(1, 3, D);
        xor_lane(1, 4, D);
        */
        //xor_lane_data->x = 0;
        //xor_lane_data->y = 0;
        //xor_lane_data->value = D;
        temp_struct.x = 1;
        temp_struct.y = 0;
        temp_struct.value = D;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 1;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 2;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 3;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 4;
        bpf_loop(1, xor_lane, &temp_struct, 0);

        safe_index1 = offset1[2];
        safe_index2 = offset2[2];
        D = C[safe_index1] ^ ROL64(C[safe_index2], 1);

        /*
        xor_lane(2, 0, D);
        xor_lane(2, 1, D);
        xor_lane(2, 2, D);
        xor_lane(2, 3, D);
        xor_lane(2, 4, D);
        */
        //xor_lane_data->x = 0;
        //xor_lane_data->y = 0;
        //xor_lane_data->value = D;
        temp_struct.x = 2;
        temp_struct.y = 0;
        temp_struct.value = D;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 1;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 2;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 3;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 4;
        bpf_loop(1, xor_lane, &temp_struct, 0);

        safe_index1 = offset1[3];
        safe_index2 = offset2[3];
        D = C[safe_index1] ^ ROL64(C[safe_index2], 1);

        /*
        xor_lane(3, 0, D);
        xor_lane(3, 1, D);
        xor_lane(3, 2, D);
        xor_lane(3, 3, D);
        xor_lane(3, 4, D);
        */
        //xor_lane_data->x = 0;
        //xor_lane_data->y = 0;
        //xor_lane_data->value = D;
        temp_struct.x = 3;
        temp_struct.y = 0;
        temp_struct.value = D;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 1;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 2;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 3;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 4;
        bpf_loop(1, xor_lane, &temp_struct, 0);

        safe_index1 = offset1[4];
        safe_index2 = offset2[4];
        D = C[safe_index1] ^ ROL64(C[safe_index2], 1);

        /*
        xor_lane(4, 0, D);
        xor_lane(4, 1, D);
        xor_lane(4, 2, D);
        xor_lane(4, 3, D);
        xor_lane(4, 4, D);
        */
        //xor_lane_data->x = 0;
        //xor_lane_data->y = 0;
        //xor_lane_data->value = D;
        temp_struct.x = 4;
        temp_struct.y = 0;
        temp_struct.value = D;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 1;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 2;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 3;
        bpf_loop(1, xor_lane, &temp_struct, 0);
        temp_struct.y = 4;
        bpf_loop(1, xor_lane, &temp_struct, 0);

        //bpf_printk("theta step done\n");

        /* === ρ and π steps === */
        
        //x = 1;
        //y = 0;
        //current = read_lane(1, 0);
        read_lane_data->x = 1;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        current = read_lane_data->lane;
        /*
        for (t = 0; t < 24; t++) {
            unsigned int r = ((t + 1) * (t + 2) / 2) % 64;
            unsigned int Y = (2 * x + 3 * y) % 5;
            x = y;
            y = Y;
            temp = read_lane(x, y);
            write_lane(x, y, ROL64(current, r));
            current = temp;
        }
        */

        write_lane_data = bpf_map_lookup_elem(&write_lane_map, &key);
        if (!write_lane_data)
            return 1;

        r = ((0 + 1) * (0 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        bpf_printk("lane: %d\n", temp);
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((1 + 1) * (1 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((2 + 1) * (2 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((3 + 1) * (3 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((4 + 1) * (4 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((5 + 1) * (5 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((6 + 1) * (6 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((7 + 1) * (7 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((8 + 1) * (8 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((9 + 1) * (9 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((10 + 1) * (10 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((11 + 1) * (11 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((12 + 1) * (12 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((13 + 1) * (13 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((14 + 1) * (14 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((15 + 1) * (15 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL4(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((16 + 1) * (16 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((17 + 1) * (17 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((18 + 1) * (18 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((19 + 1) * (19 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((20 + 1) * (20 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((21 + 1) * (21 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((22 + 1) * (22 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;

        r = ((23 + 1) * (23 + 2) / 2) % 64;
        Y = (unsigned int)(2 * read_lane_data->x + 3 * read_lane_data->y) % 5;
        //x = y;
        //y = Y;
        //temp = read_lane(x, y);
        read_lane_data->x = read_lane_data->y;
        read_lane_data->y = Y;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp = read_lane_data->lane;
        //write_lane(x, y, ROL64(current, r));
        write_lane_data->x = read_lane_data->y;
        write_lane_data->y = Y;
        write_lane_data->value = ROL64(current, r);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        current = temp;


        //bpf_printk("rho and pi steps done\n");

        /* === χ step === */
        __u64 temp_plane[5];
        /*
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++)
                temp_plane[x] = read_lane(x, y);
            for (x = 0; x < 5; x++) {
                safe_index1 = offset1[x];
                safe_index2 = offset3[x];
                write_lane(x, y, temp_plane[x] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
            }
        }
        */
        /*
        temp_plane[0] = read_lane(0, 0);
        temp_plane[1] = read_lane(1, 0);
        temp_plane[2] = read_lane(2, 0);
        temp_plane[3] = read_lane(3, 0);
        temp_plane[4] = read_lane(4, 0);
        */
        read_lane_data->x = 0;
        read_lane_data->y = 0;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[0] = read_lane_data->lane;
        read_lane_data->x = 1;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[1] = read_lane_data->lane;
        read_lane_data->x = 2;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[2] = read_lane_data->lane;
        read_lane_data->x = 3;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[3] = read_lane_data->lane;
        read_lane_data->x = 4;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[4] = read_lane_data->lane;

        safe_index1 = offset1[0];
        safe_index2 = offset3[0];
        //write_lane(0, 0, temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 0;
        write_lane_data->y = 0;
        write_lane_data->value = temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[1];
        safe_index2 = offset3[1];
        //write_lane(1, 0, temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 1;
        write_lane_data->y = 0;
        write_lane_data->value = temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[2];
        safe_index2 = offset3[2];
        //write_lane(2, 0, temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 2;
        write_lane_data->y = 0;
        write_lane_data->value = temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[3];
        safe_index2 = offset3[3];
        //write_lane(3, 0, temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 3;
        write_lane_data->y = 0;
        write_lane_data->value = temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[4];
        safe_index2 = offset3[4];
        //write_lane(4, 0, temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 4;
        write_lane_data->y = 0;
        write_lane_data->value = temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);

        /*
        temp_plane[0] = read_lane(0, 1);
        temp_plane[1] = read_lane(1, 1);
        temp_plane[2] = read_lane(2, 1);
        temp_plane[3] = read_lane(3, 1);
        temp_plane[4] = read_lane(4, 1);
        */
        read_lane_data->x = 0;
        read_lane_data->y = 1;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[0] = read_lane_data->lane;
        read_lane_data->x = 1;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[1] = read_lane_data->lane;
        read_lane_data->x = 2;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[2] = read_lane_data->lane;
        read_lane_data->x = 3;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[3] = read_lane_data->lane;
        read_lane_data->x = 4;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[4] = read_lane_data->lane;

        safe_index1 = offset1[0];
        safe_index2 = offset3[0];
        //write_lane(0, 1, temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 0;
        write_lane_data->y = 1;
        write_lane_data->value = temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[1];
        safe_index2 = offset3[1];
        //write_lane(1, 1, temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 1;
        write_lane_data->y = 1;
        write_lane_data->value = temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[2];
        safe_index2 = offset3[2];
        //write_lane(2, 1, temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 2;
        write_lane_data->y = 1;
        write_lane_data->value = temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[3];
        safe_index2 = offset3[3];
        //write_lane(3, 1, temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 3;
        write_lane_data->y = 1;
        write_lane_data->value = temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[4];
        safe_index2 = offset3[4];
        //write_lane(4, 1, temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 4;
        write_lane_data->y = 1;
        write_lane_data->value = temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);

        /*
        temp_plane[0] = read_lane(0, 2);
        temp_plane[1] = read_lane(1, 2);
        temp_plane[2] = read_lane(2, 2);
        temp_plane[3] = read_lane(3, 2);
        temp_plane[4] = read_lane(4, 2);
        */
        read_lane_data->x = 0;
        read_lane_data->y = 2;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[0] = read_lane_data->lane;
        read_lane_data->x = 1;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[1] = read_lane_data->lane;
        read_lane_data->x = 2;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[2] = read_lane_data->lane;
        read_lane_data->x = 3;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[3] = read_lane_data->lane;
        read_lane_data->x = 4;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[4] = read_lane_data->lane;

        safe_index1 = offset1[0];
        safe_index2 = offset3[0];
        //write_lane(0, 2, temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 0;
        write_lane_data->y = 2;
        write_lane_data->value = temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[1];
        safe_index2 = offset3[1];
        //write_lane(1, 2, temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 1;
        write_lane_data->y = 2;
        write_lane_data->value = temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[2];
        safe_index2 = offset3[2];
        //write_lane(2, 2, temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 2;
        write_lane_data->y = 2;
        write_lane_data->value = temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[3];
        safe_index2 = offset3[3];
        //write_lane(3, 2, temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 3;
        write_lane_data->y = 2;
        write_lane_data->value = temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[4];
        safe_index2 = offset3[4];
        //write_lane(4, 2, temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 4;
        write_lane_data->y = 2;
        write_lane_data->value = temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);

        /*
        temp_plane[0] = read_lane(0, 3);
        temp_plane[1] = read_lane(1, 3);
        temp_plane[2] = read_lane(2, 3);
        temp_plane[3] = read_lane(3, 3);
        temp_plane[4] = read_lane(4, 3);
        */
        read_lane_data->x = 0;
        read_lane_data->y = 3;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[0] = read_lane_data->lane;
        read_lane_data->x = 1;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[1] = read_lane_data->lane;
        read_lane_data->x = 2;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[2] = read_lane_data->lane;
        read_lane_data->x = 3;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[3] = read_lane_data->lane;
        read_lane_data->x = 4;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[4] = read_lane_data->lane;

        safe_index1 = offset1[0];
        safe_index2 = offset3[0];
        //write_lane(0, 3, temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 0;
        write_lane_data->y = 3;
        write_lane_data->value = temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[1];
        safe_index2 = offset3[1];
        //write_lane(1, 3, temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 1;
        write_lane_data->y = 3;
        write_lane_data->value = temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[2];
        safe_index2 = offset3[2];
        //write_lane(2, 3, temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 2;
        write_lane_data->y = 3;
        write_lane_data->value = temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[3];
        safe_index2 = offset3[3];
        //write_lane(3, 3, temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 3;
        write_lane_data->y = 3;
        write_lane_data->value = temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[4];
        safe_index2 = offset3[4];
        //write_lane(4, 3, temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 4;
        write_lane_data->y = 3;
        write_lane_data->value = temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);

        /*
        temp_plane[0] = read_lane(0, 4);
        temp_plane[1] = read_lane(1, 4);
        temp_plane[2] = read_lane(2, 4);
        temp_plane[3] = read_lane(3, 4);
        temp_plane[4] = read_lane(4, 4);
        */
        read_lane_data->x = 0;
        read_lane_data->y = 4;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[0] = read_lane_data->lane;
        read_lane_data->x = 1;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[1] = read_lane_data->lane;
        read_lane_data->x = 2;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[2] = read_lane_data->lane;
        read_lane_data->x = 3;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[3] = read_lane_data->lane;
        read_lane_data->x = 4;
        bpf_loop(1, read_lane, &read_lane_data, 0);
        temp_plane[4] = read_lane_data->lane;

        safe_index1 = offset1[0];
        safe_index2 = offset3[0];
        //write_lane(0, 4, temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 0;
        write_lane_data->y = 4;
        write_lane_data->value = temp_plane[0] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[1];
        safe_index2 = offset3[1];
        //write_lane(1, 4, temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 1;
        write_lane_data->y = 4;
        write_lane_data->value = temp_plane[1] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[2];
        safe_index2 = offset3[2];
        //write_lane(2, 4, temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 2;
        write_lane_data->y = 4;
        write_lane_data->value = temp_plane[2] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[3];
        safe_index2 = offset3[3];
        //write_lane(3, 4, temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 3;
        write_lane_data->y = 4;
        write_lane_data->value = temp_plane[3] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);
        safe_index1 = offset1[4];
        safe_index2 = offset3[4];
        //write_lane(4, 4, temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]));
        write_lane_data->x = 4;
        write_lane_data->y = 4;
        write_lane_data->value = temp_plane[4] ^ ((~temp_plane[safe_index1]) & temp_plane[safe_index2]);
        bpf_loop(1, write_lane, &write_lane_data, 0);


        //bpf_printk("chi step done\n");

        /* === ι step === */
        /*
        for (j = 0; j < 7; j++) {
            unsigned int bitPosition = (1 << j) - 1;
            if (LFSR86540(&LFSRstate))
                xor_lane(0, 0, ((__u64)1 << bitPosition));
        }
        */
        key = 0;

        bitPosition = (1 << 0) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }
        bitPosition = (1 << 1) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }
        bitPosition = (1 << 2) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }
        bitPosition = (1 << 3) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }
        bitPosition = (1 << 4) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }
        bitPosition = (1 << 5) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }
        bitPosition = (1 << 6) - 1;
        if (LFSR86540(&LFSRstate))
        {
            //xor_lane(0, 0, ((__u64)1 << bitPosition));
            //xor_lane_data->x = 0;
            //xor_lane_data->y = 0;
            //xor_lane_data->value = ((__u64)1 << bitPosition);
            temp_struct.x = 0;
            temp_struct.y = 0;
            temp_struct.value = ((__u64)1 << bitPosition);
            bpf_loop(1, xor_lane, &temp_struct, 0);
        }

        //bpf_printk("iota step done\n");
    }

    return 0;
}
