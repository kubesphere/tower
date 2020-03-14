package proxy

import (
	"context"
	"fmt"
	"io/ioutil"
	"k8s.io/klog"
	"kubesphere.io/tower/pkg/agent"
	"kubesphere.io/tower/pkg/utils"
)

type HTTPProxy struct {
	name   string
	config *agent.Config

	kubernetesApiserverProxy *Server
	kubesphereApiserverProxy *Server
}

func NewHTTPProxy(ssh utils.GetSSHConn, kubernetesPort uint16, kubespherePort uint16, config *agent.Config, ca, serverCert, serverKey string) (*HTTPProxy, error) {

	serverCaData, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, err
	}

	serverCertData, err := ioutil.ReadFile(serverCert)
	if err != nil {
		return nil, err
	}

	serverKeyData, err := ioutil.ReadFile(serverKey)
	if err != nil {
		return nil, err
	}

	kubernetesApiserverProxy, err := newProxyServer(ssh, fmt.Sprintf("%s-kubernetes", config.Name), config.KubernetesSvcHost, "https", kubernetesPort, config.CAData, config.CertData, config.KeyData, config.BearerToken, serverCaData, serverCertData, serverKeyData)
	if err != nil {
		return nil, err
	}

	kubesphereApiserverProxy, err := newProxyServer(ssh, fmt.Sprintf("%s-kubesphere", config.Name), config.KubeSphereSvcHost, "http", kubespherePort, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	return &HTTPProxy{
		name:                     config.Name,
		kubernetesApiserverProxy: kubernetesApiserverProxy,
		kubesphereApiserverProxy: kubesphereApiserverProxy,
	}, nil
}

func (proxy *HTTPProxy) Start(ctx context.Context) error {
	if err := proxy.kubernetesApiserverProxy.Start(ctx); err != nil {
		klog.Errorf("HTTP Proxy %s: %v", proxy.name, err)
		return err
	}

	if err := proxy.kubesphereApiserverProxy.Start(ctx); err != nil {
		klog.Errorf("HTTP Proxy %s: %v", proxy.name, err)
		return err
	}
	return nil
}
