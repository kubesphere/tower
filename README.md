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
customresourcedefinition.apiextensions.k8s.io/clusters.cluster.kubesphere.io created
```
* Run proxy on host cluster, the publish-service-address needs to be a address accessible for all member clusters.
```bash
$ ./bin/proxy  --ca-cert ./certs/ca.crt --ca-key ./certs/ca.key --host 0.0.0.0 --port 8080 --publish-service-address 192.168.100.3 --kubeconfig ~/.kube/config

I1108 09:57:50.145666       1 options.go:46] CA set to "/ca.crt".
I1108 09:57:50.145795       1 options.go:47] CA key file set to "/ca.key".
I1108 09:57:50.145804       1 options.go:48] Host set to 0.0.0.0
I1108 09:57:50.145811       1 options.go:49] Agent port set to 8080.
I1108 09:57:50.145823       1 options.go:50] Kubeconfig set to "".
I1108 09:57:50.145842       1 options.go:51] Leader election set to false
I1108 09:57:50.275180       1 proxy.go:234] Listening on 0.0.0.0:8080...
```
* Create a agent object in host cluster
```bash
$ cat agent.yaml    
apiVersion: cluster.kubesphere.io/v1alpha1
kind: Cluster
metadata:
  name: alpha
  namespace: kubesphere-system
spec:
  connection:
    type: proxy
    token: ""
  joinFederation: true
$ kubectl -n kubesphere-system create -f agent.yaml
```

* Proxy server will generate token and update cluster object. Use following command to get the token.
```
$ kubectl get cluster alpha -o jsonpath='{.spec.connection.token}'
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
$ kubectl -n kubesphere-system get cluster alpha -o jsonpath='{.spec.connection.kubeconfig}' | base64 -d > config_alpha
$ kubectl --kubeconfig config_alpha get node 
NAME     STATUS   ROLES    AGE    VERSION
master   Ready    master   2d3h   v1.17.3
node1    Ready    worker   2d3h   v1.17.3
node2    Ready    worker   2d3h   v1.17.3
node3    Ready    worker   2d3h   v1.17.3
```

* Use tower to make a member cluster kubeapi accessable to public
  
If you want to make you member cluster kubeapi accessable to public, create a cluster resource as follows:

```
apiVersion: cluster.kubesphere.io/v1alpha1
kind: Cluster
metadata:
  name: kind-test
  namespace: kubesphere-system
  annotations:
    tower.kubesphere.io/external-lb-service-annoations: '{"eip.porter.kubesphere.io/v1alpha2":"porter-bgp-eip","lb.kubesphere.io/v1alpha1":"porter","protocol.porter.kubesphere.io/v1alpha1":"bgp"}'
spec:
  connection:
    type: proxy
    token: ""
  joinFederation: true
  externalKubeAPIEnabled: true
```

With `externalKubeAPIEnabled=true` and `connection.type=proxy` tower will create the serivce with `LoadBlancer` type, content in annotation with key `tower.kubesphere.io/external-lb-service-annoations` will be applied to the service anntations as k-v, so that your can control how the `ccm` process the service.