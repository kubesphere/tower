package main

import (
	"fmt"
	"github.com/spf13/pflag"
	"os"

	"k8s.io/klog"
)

type ProxyRunOptions struct {
	// Certificates to setup a proxy server.
	caCert     string
	serverCert string
	serverKey  string
	// Port listening for agent connections.
	agentPort uint
	// Path to kubeconfig
	kubeconfigPath string
}

func (o *ProxyRunOptions) Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("proxy", pflag.ContinueOnError)
	flags.StringVar(&o.caCert, "cacert", o.caCert, "CA file we use to validate server clients.")
	flags.StringVar(&o.serverCert, "cert", o.serverCert, "Cert file we use to set up TLS proxy, must be signed by CA provided above.")
	flags.StringVar(&o.serverKey, "key", o.serverKey, "Key file")
	flags.UintVar(&o.agentPort, "agent-port", o.agentPort, "Port listening for agent connections.")
	flags.StringVar(&o.kubeconfigPath, "kubeconfig", o.kubeconfigPath, "Kubeconfig file absolute path.")
	return flags
}

func (o *ProxyRunOptions) Validate() error {
	if o.caCert != "" {
		if _, err := os.Stat(o.caCert); os.IsNotExist(err) {
			return fmt.Errorf("error checking ca file %s, got %v", o.caCert, err)
		}
	}

	if o.serverCert != "" {
		if _, err := os.Stat(o.serverCert); os.IsNotExist(err) {
			return fmt.Errorf("error checking server crt file %s, got %v", o.serverCert, err)
		}

		if o.serverKey == "" {
			return fmt.Errorf("cannot have server key empty when server crt is set to %q", o.serverCert)
		}
	}

	if o.serverKey != "" {
		if _, err := os.Stat(o.serverKey); os.IsNotExist(err) {
			return fmt.Errorf("error checking server crt file %s, got %v", o.serverKey, err)
		}

		if o.serverCert == "" {
			return fmt.Errorf("cannot have server key empty when server crt is set to %q", o.serverKey)
		}
	}

	if o.agentPort > 49151 || o.agentPort < 1024 {
		return fmt.Errorf("please don't set agent port out of range (1024, 49151)")
	}

	if o.kubeconfigPath != "" {
		if _, err := os.Stat(o.kubeconfigPath); os.IsNotExist(err) {
			return fmt.Errorf("error checking kubeconfig file %s, got %v", o.kubeconfigPath, err)
		}
	}
	return nil
}

func (o *ProxyRunOptions) Print() {
	klog.V(0).Infof("CA set to %q.\n", o.caCert)
	klog.V(0).Infof("Server cert set to %q.\n", o.serverCert)
	klog.V(0).Infof("Server key set to %q.\n", o.serverKey)
	klog.V(0).Infof("Agent port set to %d.\n", o.agentPort)
	klog.V(0).Infof("Kubeconfig set to %q.\n", o.kubeconfigPath)
}

func newProxyRunOptions() *ProxyRunOptions {
	return &ProxyRunOptions{
		caCert:         "",
		serverCert:     "",
		serverKey:      "",
		agentPort:      8000,
		kubeconfigPath: "",
	}
}
