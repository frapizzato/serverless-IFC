#!/usr/bin/python3
from bcc import BPF
import pyroute2
import ctypes


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
class LabelT(ctypes.Structure):
    _fields_ = [
        ('label', ctypes.c_uint64),
        ('timestamp', ctypes.c_uint64)
    ]

class LabelHdrT(ctypes.Structure):
    _fields_ = [
        ('init_sequence', ctypes.c_uint16, 11),
        ('f_counter', ctypes.c_uint16, 5),
        ('id_label', ctypes.c_uint16),
        ('label', ctypes.c_uint8 * 24)
    ]

class KeyT(ctypes.Structure):
    _fields_ = [
        ('auth_token', ctypes.c_uint8 * 16)
    ]

def create_entry(bpf_map, key, init_seq, f_counter, id_label, label):
    c_value = LabelHdrT()
    c_value.init_sequence = init_seq
    c_value.f_counter = f_counter
    c_value.id_label = id_label
    c_value.label = (ctypes.c_uint8 * 24) (*label)
    #c_value = LabelHdrT(init_seq, f_counter, id_label, label)
    key_bytearray = (ctypes.c_uint8 * 16)(*map(ord, key))
    c_key = KeyT(key_bytearray)
    bpf_map[c_key] = c_value


def create_L_entry(bpf_map, key, label, timestamp):
    c_value = LabelT(label, timestamp)
    key_bytearray = (ctypes.c_uint8 * 16)(*map(ord, key))
    c_key = KeyT(key_bytearray)
    bpf_map[c_key] = c_value 

#########################################

b = BPF(src_file="gateway.bpf.c")

interface = "eth0"

# Ensure that no programs are attached to the interface
b.remove_xdp(interface, 0)
clean_up_tc(interface)

# Initialize the mapping users-labels
auth_map = b.get_table("auth_map")
create_entry(auth_map, 'YWRtaW46dTk3ZXlO', 1, 0, 65535, [255]+[0]*23)
#create_L_entry(auth_map, 'YWRtaW46dTk3ZXlO', 72623859790382856, 72623859790382856)

# Load the XDP program
f_in = b.load_func("handle_ingress", BPF.XDP)
b.attach_xdp(interface, f_in)

# Load the TC program
f_out = b.load_func("handle_egress", BPF.SCHED_CLS)
ipr = pyroute2.IPRoute()
eth = ipr.link_lookup(ifname=interface)[0]
ipr.tc("add", "clsact", eth)
ipr.tc("add-filter", "bpf", eth, ":1", fd=f_out.fd, name=f_out.name, parent="ffff:fff3", classid=1, direct_action=True)


while 1:
    try:
        b.trace_print()

    except KeyboardInterrupt:
        b.remove_xdp(interface, 0)
        clean_up_tc(interface)
        exit(0)