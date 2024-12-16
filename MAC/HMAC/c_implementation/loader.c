#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>  // For if_nametoindex()
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>  // For XDP program-related functions

#define INTERFACE_NAME "wlp0s20f3"  // Set the interface name here

int main() {
    // Open the BPF object
    struct bpf_object *obj;
    int prog_fd, ifindex, ret;

    obj = bpf_object__open_file("hash.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // Load the BPF object
    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Find the program within the object by name
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "keccak_xdp");
    if (!prog) {
        fprintf(stderr, "Failed to find program\n");
        return 1;
    }

    // Get program file descriptor
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        return 1;
    }

    // Get interface index from the interface name
    ifindex = if_nametoindex(INTERFACE_NAME);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", INTERFACE_NAME);
        return 1;
    }

    // Attach the XDP program to the interface using the updated API
    ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_REPLACE, NULL);
    if (ret) {
        fprintf(stderr, "Failed to attach XDP program\n");
        return 1;
    }

    printf("XDP program successfully attached to interface %s\n", INTERFACE_NAME);

    // Clean up and close BPF object
    bpf_object__close(obj);

    return 0;
}
