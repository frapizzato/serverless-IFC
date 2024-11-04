#!/usr/bin/python3
from bcc import BPF
import pyroute2
from time import sleep


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


b = BPF(src_file="function.bpf.c")

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
        b.remove_xdp(interface, 0)
        clean_up_tc(interface)
        exit(0)