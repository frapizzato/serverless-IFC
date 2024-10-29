#!/usr/bin/env python3
from kubernetes import config, client
from bcc import BPF
import struct
import re
import socket
from time import sleep

#########################################
# Retrieve "allowed" IPs from cluster
def extract_cluster_ips():

    config.load_kube_config()
    v1 = client.CoreV1Api()
    
    ret = v1.list_service_for_all_namespaces(watch=False)
    output = []
    for i in ret.items:
        #print("%s\t%s\t%s" % (i.spec.cluster_ip, i.metadata.namespace, i.metadata.name))
        if(i.spec.cluster_ip != "None"):
            output.append(i.spec.cluster_ip)
    return output

def extract_pod_ips():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    
    ret = v1.list_pod_for_all_namespaces(watch=False)
    output = []
    pattern = r'^gateway'
    gateway = []
    tagged = []
    for i in ret.items:
        if(i.status.pod_ip == "None"):
            continue
        #print("%s\t%s\t%s" % (i.status.pod_ip, i.metadata.namespace, i.metadata.name))
        if(i.metadata.namespace == "openfaas-fn"):
            tagged.append(i.status.pod_ip)
        elif(re.match(pattern,i.metadata.name)):
            gateway.append(i.status.pod_ip)
        else:
            output.append(i.status.pod_ip)

    return output, gateway, tagged

def fill_bpf_allow_map(bpf_map, allowed_ips):
    for ip in allowed_ips:
        print(f"[+] Adding {ip} to allowed IPs")
        bpf_map[bpf_map.Key(ip_string_to_32bit_int(ip))] = bpf_map.Leaf(0)
        sleep(5)

def fill_bpf_tagged_map(bpf_map, tagged_ips):
    for ip in tagged_ips:
        print(f"[+] Adding {ip} to tagged IPs")
        bpf_map[bpf_map.Key(ip_string_to_32bit_int(ip))] = bpf_map.Leaf(1)


def ip_string_to_32bit_int(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]

#########################################

cluster_ips = extract_cluster_ips()
pod_ips, gateway_pod_ips, tagged_pod_ips = extract_pod_ips()

print("Cluster IPs:")
for ip in cluster_ips:
    print(ip)

print("Pod IPs:")
for ip in pod_ips:
    print(ip)

print("Gateway Pod IP:")
for ip in gateway_pod_ips:
    print(ip)

print("Tagged Pod IPs:")
for ip in tagged_pod_ips:
    print(ip)


#########################################################################
# Populate the eBPF map with the IPs: value 0 do not tag, 1 need to tag #
#########################################################################

bpf = BPF(text="""
#include <bcc/proto.h>
#include <uapi/linux/bpf.h>
BPF_TABLE_PINNED("hash", int, int, tags_map, 1024, "/sys/fs/bpf/tags");
""")

tagsMap = bpf["tags_map"]

allow_list = cluster_ips + pod_ips
fill_bpf_allow_map(tagsMap, allow_list)

tagged_list = tagged_pod_ips + gateway_pod_ips
fill_bpf_tagged_map(tagsMap, tagged_list)

