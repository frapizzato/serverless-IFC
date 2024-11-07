#!/usr/bin/env python3
from kubernetes import config, client, watch
import threading
from bcc import BPF
import struct
import re
import socket

####################################################################################
# This script creates and populate the eBPF map with the K8s IPs for svc and pod.  #
# Associated value means: 0 do not tag, 1 need to tag                              #
####################################################################################

# create the BPF program
bpf = BPF(text="""
#include <bcc/proto.h>
#include <uapi/linux/bpf.h>
BPF_TABLE_PINNED("hash", int, int, tags_map, 1024, "/sys/fs/bpf/tags");
""")

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
