package proxy

import (
	"context"
	"fmt"
	"net/http"

	"k8s.io/klog"
	"kubesphere.io/tower/pkg/agent"
	"kubesphere.io/tower/pkg/utils"
)

type HTTPProxy struct {
	name   string
	config *agent.Config

	// ctx used to shutdown server
	ctx    context.Context
	cancel context.CancelFunc

	kubernetesAPIServerProxy *Server
	kubesphereAPIServerProxy *Server
}

func NewHTTPProxy(ssh utils.GetSSHConn, kubernetesPort uint16, kubespherePort uint16, config *agent.Config, ca, serverCert, serverKey []byte) (*HTTPProxy, *http.Transport, *http.Transport, error) {
	k8stransPort, useBearerToken, servertlsConfig, err := buildServerData(ssh, config.KubernetesSvcHost, config.CAData, config.CertData, config.KeyData, ca, serverCert, serverKey)
	if err != nil {
		return nil, nil, nil, err
	}

	kubernetesAPIServerProxy, err := newProxyServer(fmt.Sprintf("%s-kubernetes", config.Name), config.KubernetesSvcHost, "https", kubernetesPort, useBearerToken, k8stransPort, servertlsConfig, config.BearerToken)
	if err != nil {
		return nil, nil, nil, err
	}

	kstransPort, useBearerToken, _, err := buildServerData(ssh, config.KubeSphereSvcHost, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	kubesphereAPIServerProxy, err := newProxyServer(fmt.Sprintf("%s-kubesphere", config.Name), config.KubeSphereSvcHost, "http", kubespherePort, useBearerToken, kstransPort, nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &HTTPProxy{
		name:                     config.Name,
		ctx:                      ctx,
		cancel:                   cancel,
		kubernetesAPIServerProxy: kubernetesAPIServerProxy,
		kubesphereAPIServerProxy: kubesphereAPIServerProxy,
	}, k8stransPort, kstransPort, nil
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
