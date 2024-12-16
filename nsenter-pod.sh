#!/bin/bash

# Define the function
function nsenter-pod() {
    POD=$1  # Pod name
    # Extract the network namespace path
    NETNS=$(sudo crictl inspectp --name $POD | grep netns | sed -n 's/.*"path": "\([^"]*\)".*/\1/p')
    shift 1
    # Enter the network namespace and execute the command
    sudo nsenter --net=$NETNS "$@"
}

# Check if a pod name is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <pod-name> [command] [args...]"
    exit 1
fi

# Call the function with the provided arguments
nsenter-pod "$@"
