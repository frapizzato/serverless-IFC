# serverless-IFC
Repository for the code developed during the research period abroad in Telefonica Research

## Authenticate the faas-cli to access OpenFaas
Setup openfaas gateway connection + authentication of faas-cli (this commands should be runned to access it through **the same machine running OpenFaaS**):
```bash
$ kubectl port-forward -n openfaas svc/gateway 8080:8080 &
$ PASSWORD=$(kubectl get secret -n openfaas basic-auth -o jsonpath="{.data.basic-auth-password}" | base64 --decode; echo)
$ echo -n $PASSWORD | faas-cli login --username admin --password-stdin
```
Note that same password and user could be used to login through the ui @ 127.0.0.1:8080.

## Authenticate and access OpenFaaS from another host (on same LAN)
OpenFaaS gateway is also exposed through a Kubernetes NodePort Service, more specifically it could be accessed by contacting the port **31112** of the machine running the cluster. Note that the requests need to be authenticate with the same credentials seen before:

```bash
$ PASSWORD=$(kubectl get secret -n openfaas basic-auth -o jsonpath="{.data.basic-auth-password}" | base64 --decode; echo)
$ curl -u admin:$PASSWORD localhost:<port_of_gatewat_external>/system/functions
$ curl -u admin:u97eyNLhVuMj 192.168.1.159:31112/system/functions
```

## Deploy a function from the OpenFaaS store
Then, try to deploy a simple function and check for its correctness:
```bash
$ faas-cli store deploy figlet
$ faas-cli list
$ echo "test" | faas-cli invoke figlet
```

## Create and deploy a function
Can also create custom functions, the simple way to do so is to start from the templates offered by OpenFaaS. Beware that this is not the only available possibility and that each template may have some difference in the way in which the application is exposed, and could need some customization.

```bash
...skipping the creation (TODO)

faas-cli up -f <functionName>.yml

faas-cli delete -f <functionName>.yml
```

<!--
The current demo want to show the eBPF components in a simple environment. To start the demo you need to create a K8s cluster and install openfaas:

```bash
kind create cluster -n demo --config=./kind-config.yml
```

Then, for an easy installation of openFaaS, do:
```bash
arkade install openfaas
```

-->

**the following procedure works for the current lab setup in the office, needs to be updated in the future!**

First step to work with the files in this repo is to launch the python script that acts like a Kubernetes Controller, starting two watchers for Pods and Services, and then passing the necessary information down into the Kernel through eBPF maps. Note that the script, if let running, could dynamically modify the eBPF maps information whenever a new pod is scheduler or removed (same for the service). To launch it (in the **host** - i.e., where the K8s cluster is running):
```bash
$ sudo -E python3 ./0_k8s_information_controller.py
```

Note that you can check the creation of the maps and their content with **bpftool**:
```bash
$ sudo bpftool map list
$ sudo bptfool map dump id <mad-id>
```

Then, we need to inject the eBPF programs on both gateway and OpenFaaS functions. To do so, we need to enther each of the respective network namespace when launching the python script. For making the process easier can use the **nsenter-pod** like so:
```bash
$ kubectl get pods -n openfaas  # to retrieve the name of the gateway's pod
$ nsenter-pod <name-of-gateway-pod> python3 ./1_gateway.py
```
In current version, once loaded the eBPF programs, the script will remain pending and reading all the messages written on the common tracelog used by the different eBPF functions.

Finally, the same can be done for any of the OpenFaaS function's pods.
```bash
$ kubectl get pods -n openfaas-fn  # to retrieve the name of the functions' pod
$ nsenter-pod <name-of-func-pod> python3 ./2_function.py <name-of-func-pod>
```

## Random
To quiclky enter into the network namespace of a running pod, you could use the following bash function which takes as argument the name of the running pod (needs to be executed in the same machine in which the pod's container is present).

```bash
function nsenter-pod (){
   POD=$1  #pod name
   NETNS=$(sudo crictl inspectp --name $POD | grep netns | sed -n 's/.*"path": "\([^"]*\)".*/\1/p')
   shift 1
   sudo nsenter --net=$NETNS $@
}
```

