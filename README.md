# Tower

Tower is a network tunnel used to proxy KubeSphere API requests to member clusters. Tower is built on top HTTP, secured via SSH. The main idea is stolen from Chisel(https://github.com/jpillora/chisel).

# How does it work

    Proxy  <------>  Agent |--> ks-apiserver  
                           |--> kube-apiserver

In short, agents running in member cluster will connect proxy running in host cluster. After successfully handshaking, agents will establish a secured ssh connection with proxy, allowing traffic from host cluster to forward to local kubernetes apiserver and kubesphere apiserver.

# How to build
Clone the repo and run make under tower. There will be two binaries generated under directory `bin/`
```bash
$ make
$ ls bin/
proxy agent
```

# How to use it
* Install tower crd in host cluster
```bash
$ cd config/crd
$ kustomize build | kubectl create -f -
customresourcedefinition.apiextensions.k8s.io/agents.tower.kubesphere.io created
```
* Run proxy on host cluster, the publish-service-address needs to be a address accessible for all member clusters.
```bash
$ ./bin/proxy  --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key --host 0.0.0.0 --port 8080 --publish-service-address 192.168.100.3 --kubeconfig ~/.kube/config

I0325 18:17:40.076125   16267 options.go:41] CA set to "./certs/ca.crt".
I0325 18:17:40.076242   16267 options.go:42] CA key file set to "./certs/ca.key".
I0325 18:17:40.076247   16267 options.go:43] Host set to 0.0.0.0
I0325 18:17:40.076250   16267 options.go:44] Agent port set to 8080.
I0325 18:17:40.076253   16267 options.go:45] Kubeconfig set to "~/.kube/config".
I0325 18:17:40.361937   16267 agent_controller.go:83] Starting agent controller...
```
* Create a agent object in host cluster
```bash
$ cat agent.yaml    
apiVersion: tower.kubesphere.io/v1alpha1
kind: Agent
metadata:
  name: alpha
  namespace: kubesphere-system
spec:
  kubernetesAPIServerPort: 0
  kubesphereAPIServerPort: 0
  token:
$ kubectl -n kubesphere-system create -f agent.yaml
```
* Waiting for proxy to generate a token for us
```bash
$ kubectl -n kubesphere-system get agent alpha -o jsonpath='{.spec.token}' 
6888951db2eef4323fd4f84d05f490be86af102f43e47c3c58e6a1ddc81cc253
```
* Run agent in member cluster with token get from previous step
```bash
$ ./bin/agent --kubeconfig ~/.kube/config --token 6888951db2eef4323fd4f84d05f490be86af102f43e47c3c58e6a1ddc81cc253 --name alpha --v 4
I0325 10:25:40.729137       1 agent.go:210] Handshaking...
I0325 10:25:40.748094       1 agent.go:126] fingerprint7b:fa:2d:64:08:95:4d:d4:74:18:3e:78:39:03:76:ce
I0325 10:25:40.753106       1 agent.go:222] Sending config
I0325 10:25:40.757505       1 agent.go:231] Connected.
```

* Now your member cluster is connected to host cluster, you can access member cluster kube-apiserver or ks-apiserver in host cluster
```bash
$ kubectl -n kubesphere-system get agent alpha -o jsonpath='{.status.KubeConfig}' | base64 -d > config_alpha
$ kubectl --kubeconfig config_alpha get node 
NAME     STATUS   ROLES    AGE    VERSION
master   Ready    master   2d3h   v1.17.3
node1    Ready    worker   2d3h   v1.17.3
node2    Ready    worker   2d3h   v1.17.3
node3    Ready    worker   2d3h   v1.17.3
```