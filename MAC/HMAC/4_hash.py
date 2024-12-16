#!/usr/bin/python3
from bcc import BPF
from time import sleep

file_path = "hash.bpf.c"

# Read the eBPF c file
b = BPF(src_file=file_path)

interface = "wlp0s20f3"

# Ensure that no programs are attached to the interface
b.remove_xdp(interface, 0)

# Load the XDP program
f_in = b.load_func("keccak_xdp", BPF.XDP)
b.attach_xdp(interface, f_in)


print(" [+] Loaded XDP program. Press CTRL+C to stop and unload it.")

while 1:
    try:
        sleep(1)
    except KeyboardInterrupt:
        b.remove_xdp(interface, 0)
        exit(0)