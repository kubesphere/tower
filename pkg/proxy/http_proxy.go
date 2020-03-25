package proxy

import (
	"context"
	"fmt"
	"k8s.io/klog"
	"kubesphere.io/tower/pkg/agent"
	"kubesphere.io/tower/pkg/utils"
)

type HTTPProxy struct {
	name   string
	config *agent.Config

	kubernetesAPIServerProxy *Server
	kubesphereAPIServerProxy *Server
}

func NewHTTPProxy(ssh utils.GetSSHConn, kubernetesPort uint16, kubespherePort uint16, config *agent.Config, ca, serverCert, serverKey []byte) (*HTTPProxy, error) {

	kubernetesAPIServerProxy, err := newProxyServer(ssh, fmt.Sprintf("%s-kubernetes", config.Name), config.KubernetesSvcHost, "https", kubernetesPort, config.CAData, config.CertData, config.KeyData, config.BearerToken, ca, serverCert, serverKey)
	if err != nil {
		return nil, err
	}

	kubesphereAPIServerProxy, err := newProxyServer(ssh, fmt.Sprintf("%s-kubesphere", config.Name), config.KubeSphereSvcHost, "http", kubespherePort, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	return &HTTPProxy{
		name:                     config.Name,
		kubernetesAPIServerProxy: kubernetesAPIServerProxy,
		kubesphereAPIServerProxy: kubesphereAPIServerProxy,
	}, nil
}

func (proxy *HTTPProxy) Start(ctx context.Context) error {
	if err := proxy.kubernetesAPIServerProxy.Start(ctx); err != nil {
		klog.Errorf("HTTP Proxy %s: %v", proxy.name, err)
		return err
	}

	if err := proxy.kubesphereAPIServerProxy.Start(ctx); err != nil {
		klog.Errorf("HTTP Proxy %s: %v", proxy.name, err)
		return err
	}
	return nil
}
