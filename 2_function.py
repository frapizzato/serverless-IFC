#!/usr/bin/python3
from bcc import BPF
import pyroute2
from time import sleep
import re
import argparse
import os

#########################################
def clean_up_tc(interface):
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[interface].index
    except:
        print(f" [!] Interface {interface} not found.")
        return False, False, False
    
    try:
        # clean the qdisc (should also remove all filters)
        ip.tc("del", "clsact", idx)
    except:
        pass
#########################################

file_path = "function.bpf.c"
OLD_VARIABLE = "POD_NAME"

# Parse the arguments
parser = argparse.ArgumentParser(description="Program to load eBPF code inside a Pod network ns. Accept as argument the Pod name, to dynamically modify the eBPF code.")
parser.add_argument("NEW_VARIABLE", help="The name of the Pod to inject into eBPF code.")

args = parser.parse_args()

# Read the eBPF c file
with open(file_path, "r") as f:
    code = f.read()

# Replace the POD_NAME variable with the Pod name, using regex
code_modified = re.sub(r'\b' + re.escape(OLD_VARIABLE) + r'\b', args.NEW_VARIABLE, code)

# Create a new file with the modified code
new_file_path = "function_" + args.NEW_VARIABLE + ".bpf.c"

# Write the modified code back to the C file
with open(new_file_path, "w") as f:
    f.write(code_modified)

#b = BPF(src_file="function.bpf.c")
b = BPF(src_file=new_file_path)

interface = "eth0"

# Ensure that no programs are attached to the interface
b.remove_xdp(interface, 0)
clean_up_tc(interface)

# Load the XDP program
f_in = b.load_func("handle_ingress", BPF.XDP)
b.attach_xdp(interface, f_in)

# Load the TC program
f_out = b.load_func("handle_egress", BPF.SCHED_CLS)
ipr = pyroute2.IPRoute()
eth = ipr.link_lookup(ifname=interface)[0]
ipr.tc("add", "clsact", eth)
ipr.tc("add-filter", "bpf", eth, ":1", fd=f_out.fd, name=f_out.name, parent="ffff:fff3", classid=1, direct_action=True)

print(" [+] Loaded XDP and TC programs. Press CTRL+C to stop and unload them.")

while 1:
    try:
        sleep(1)
    except KeyboardInterrupt:
        os.remove(new_file_path)
        b.remove_xdp(interface, 0)
        clean_up_tc(interface)
        exit(0)