#!/usr/bin/env python3
from kubernetes import config, client, watch
import threading
from bcc import BPF
import struct
import re
import socket
import ctypes

####################################################################################
# Extra step: fill in another map associating pod's names with a tag value.        #
# Tag is computed as SHA256(pod_name)[0-63] (i.e., the first 64 bits of the hash). #
####################################################################################
import hashlib

# Convert pod_name to 32-bit integer using hash function
def name_to_32bit(pod_name):
    name_bytes = pod_name.encode('utf-8')
    sha256 = hashlib.sha256(name_bytes).digest()
    return struct.unpack(">I", sha256[:4])[0]

# Convert pod_name to c_ubyte_Array_63
def string_to_c_ubyte_array(pod_name):
    # Ensure the string is no longer than 63 characters and encode it as bytes
    pod_name_bytes = pod_name.encode('utf-8')[:63]
    key = (ctypes.c_ubyte * 63)()  # Create an array of 63 unsigned bytes
    # Fill the array with the bytes of pod_name, padding with zeroes if necessary
    for i in range(len(pod_name_bytes)):
        key[i] = pod_name_bytes[i]
    return key

####################################################################################
# This script creates and populate the eBPF map with the K8s IPs for svc and pod.  #
# Associated value means: 0 do not tag, 1 need to tag                              #
####################################################################################

# create the BPF program
bpf = BPF(text="""
#include <bcc/proto.h>
#include <uapi/linux/bpf.h>

struct string_key {
    __u8    value[63];
};

   
BPF_TABLE_PINNED("hash", int, int, tags_map, 1024, "/sys/fs/bpf/tags");
          
BPF_TABLE_PINNED("hash", struct string_key, u32, pod_tags_map, 1024, "/sys/fs/bpf/pod_tags"); // note: value should be 24 bit, for simplicity we use u32 and mask it in the eBPF program
""")

#extract the map
podTagsMap = bpf["pod_tags_map"]

# function to remove a pod from the eBPF map
def del_tag_bpf_map(pod_name):
    print(f"[+] Removing '{pod_name}' from the TAG map.")
    try:
        del podTagsMap[podTagsMap.Key(string_to_c_ubyte_array(pod_name))]
    except KeyError:
        print(f"[!] Pod '{pod_name}' not found in the map (already deleted).")

# function to fill the eBPF map with the pod names and tags
def fill_tag_bpf_map(pod_name):
    print(f"[+] Adding '{pod_name}' to the TAG map.")
    podTagsMap[podTagsMap.Key(string_to_c_ubyte_array(pod_name))] = podTagsMap.Leaf(name_to_32bit(pod_name))


#extract the map
tagsMap = bpf["tags_map"]

# function to remove an IP from the eBPF map
def del_bpf_map(bpf_map, ip):
    print(f"[+] Removing '{ip}' from the map.")
    try:
        del bpf_map[bpf_map.Key(ip_string_to_32bit_int(ip))]
    except KeyError:
        print(f"[!] IP '{ip}' not found in the map (already deleted).")

# function to fill the eBPF map with the IPs
def fill_bpf_map(bpf_map, ip, decision):
    print(f"[+] Adding '{ip}:{decision}' to the map.")
    if(decision == 0 or decision == 1):
        bpf_map[bpf_map.Key(ip_string_to_32bit_int(ip))] = bpf_map.Leaf(decision)
    else:
        print(f"[!] Invalid decision value. Decision: {decision}")

def ip_string_to_32bit_int(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]

#Load the kubernetes configuration (assumes that script is running inside the cluster)
config.load_kube_config()

v1 = client.CoreV1Api()

# define what to do when a new watched resource (pod or svc) is created
def handle_creation(kind, name, namespace, phase, ip):
    if(kind == "Service"):
        print(f"Service '{name}'/'{namespace}' with IP '{ip}' was created. ADDED")
        if(ip != "None"):
            if(name == "gateway" or name == "gateway-external"):
                # tagging decision -> 1
                fill_bpf_map(tagsMap, ip, 1)
            else:
                # tagging decision -> 0
                fill_bpf_map(tagsMap, ip, 0)
    elif(kind == "Pod"):
        if(phase == "Running"):
            print(f"Pod '{name}'/'{namespace}' with IP '{ip}' was created. ADDED")
            if(ip != "None"):
                if(namespace == "openfaas-fn"):
                    # tagging decision -> 1
                    fill_tag_bpf_map(name)
                    fill_bpf_map(tagsMap, ip, 1)
                elif(re.match(r'^gateway',name)):
                    # tagging decision -> 1
                    fill_bpf_map(tagsMap, ip, 1)
                elif(namespace == "openfaas"):
                    # tagging decision -> 0
                    fill_bpf_map(tagsMap, ip, 0)
                # all other pods are IGNORED!

# define what to do when a new watched resource (pod or svc) is deleted
def handle_deletion(kind, name, namespace, phase, ip):
    if(kind == "Service"):
        print(f"Service '{name}' in '{namespace}' with IP '{ip}' was deleted. REMOVED")
        if(ip != "None"):
            del_bpf_map(tagsMap, ip)
    elif(kind == "Pod"):
        print(f"Pod '{name}' in '{namespace}' with IP '{ip}' was deleted (phase: '{phase}').")

# define what to do when a new watched resource (pod or svc) is updated
def handle_update(kind, name, namespace, phase, ip):
    if(kind == "Service"):
        print(f"Service '{name}' in '{namespace}' with IP '{ip}' was updated. MODIFIED")
    elif(kind == "Pod"):
        if(phase == "Running"):
            print(f"Pod '{name}' in '{namespace}' with IP '{ip}' was updated to phase '{phase}'.")
            if(ip != "None"):
                if(namespace == "openfaas-fn"):
                    # tagging decision -> 1
                    fill_tag_bpf_map(name)
                    fill_bpf_map(tagsMap, ip, 1)
                elif(re.match(r'^gateway',name)):
                    # tagging decision -> 1
                    fill_bpf_map(tagsMap, ip, 1)
                elif(namespace == "openfaas"):
                    # tagging decision -> 0
                    fill_bpf_map(tagsMap, ip, 0)
        elif(phase == "Succeeded" or phase == "Failed"):
            print(f"Pod '{name}' in '{namespace}' with IP '{ip}' was updated to phase '{phase}'. REMOVED")
            if(ip != "None"):
                del_bpf_map(tagsMap, ip)
                del_tag_bpf_map(name)
        else:
            print(f"Pod '{name}' in '{namespace}' with IP '{ip}' was updated to phase '{phase}'.")

# watch for resource events
def watch_resources(kind, resource_watch_func):
    w = watch.Watch()
    for event in w.stream(resource_watch_func):
        resource = event['object']
        event_type = event['type']
        name = resource.metadata.name
        namespace = resource.metadata.namespace if hasattr(resource.metadata, 'namespace') else 'N/A'
        phase = resource.status.phase if hasattr(resource.status, 'phase') else 'N/A'
        if kind == 'Service':
            ip = resource.spec.cluster_ip if hasattr(resource.spec, 'cluster_ip') else 'N/A'
        elif kind == 'Pod':
            ip = resource.status.pod_ip if hasattr(resource.status, 'pod_ip') else 'N/A'

        if(event_type == 'ADDED'):    
            handle_creation(kind, name, namespace, phase, ip)
        elif(event_type == 'DELETED'):
            handle_deletion(kind, name, namespace, phase, ip)
        elif(event_type == 'MODIFIED'):
            handle_update(kind, name, namespace, phase, ip)
        
# function to start a watcher in a separate thread
def start_watcher(kind, resource_watch_func):
    thread = threading.Thread(target=watch_resources, args=(kind, resource_watch_func))
    thread.daemon = True # with this the thread will automatically die when the main program ends
    thread.start()

def main():
    print("Starting to watch for pods, services and namespaces...")
    
    print("Starting watcher for pods...")
    start_watcher('Pod', v1.list_pod_for_all_namespaces)
    print("Starting watcher for services...")
    start_watcher('Service', v1.list_service_for_all_namespaces)

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Stopping resource watchers.")

if __name__ == "__main__":
    main()
