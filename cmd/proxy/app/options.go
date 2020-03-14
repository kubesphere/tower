package app

import (
	"fmt"
	"github.com/spf13/pflag"
	"kubesphere.io/tower/pkg/proxy"
	"os"

	"k8s.io/klog"
)

type ProxyRunOptions struct {
	ProxyOptions *proxy.Options
}

func (o *ProxyRunOptions) Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("proxy", pflag.ContinueOnError)
	flags.StringVar(&o.ProxyOptions.CaCert, "cacert", o.ProxyOptions.CaCert, "CA certificate file we use to validate server clients.")
	flags.StringVar(&o.ProxyOptions.CaKey, "cakey", o.ProxyOptions.CaKey, "CA private key to sign kubeconfig")
	flags.StringVar(&o.ProxyOptions.ServerCert, "cert", o.ProxyOptions.ServerCert, "Cert file we use to set up TLS proxy, must be signed by CA provided above.")
	flags.StringVar(&o.ProxyOptions.ServerKey, "key", o.ProxyOptions.ServerKey, "Key file")
	flags.StringVar(&o.ProxyOptions.Host, "host", "0.0.0.0", "Host listening for agent connections")
	flags.Uint16Var(&o.ProxyOptions.Port, "port", 8080, "Port listening for agent connections.")
	flags.StringVar(&o.ProxyOptions.ProxyServiceHost, "proxy-host", o.ProxyOptions.ProxyServiceHost, "Proxy service address, should be accessible for all agents.")
	flags.StringVar(&o.ProxyOptions.KubeconfigPath, "kubeconfig", o.ProxyOptions.KubeconfigPath, "Kubeconfig file absolute path.")
	return flags
}

func (o *ProxyRunOptions) Validate() error {
	if o.ProxyOptions.CaCert != "" {
		if _, err := os.Stat(o.ProxyOptions.CaCert); os.IsNotExist(err) {
			return fmt.Errorf("error checking ca file %s, got %v", o.ProxyOptions.CaCert, err)
		}
	}

	if o.ProxyOptions.ServerCert != "" {
		if _, err := os.Stat(o.ProxyOptions.ServerCert); os.IsNotExist(err) {
			return fmt.Errorf("error checking server crt file %s, got %v", o.ProxyOptions.ServerCert, err)
		}

		if o.ProxyOptions.ServerKey == "" {
			return fmt.Errorf("cannot have server key empty when server crt is set to %q", o.ProxyOptions.ServerCert)
		}
	}

	if o.ProxyOptions.ServerKey != "" {
		if _, err := os.Stat(o.ProxyOptions.ServerKey); os.IsNotExist(err) {
			return fmt.Errorf("error checking server crt file %s, got %v", o.ProxyOptions.ServerKey, err)
		}

		if o.ProxyOptions.ServerCert == "" {
			return fmt.Errorf("cannot have server key empty when server crt is set to %q", o.ProxyOptions.ServerKey)
		}
	}

	if o.ProxyOptions.Port > 49151 || o.ProxyOptions.Port < 1024 {
		return fmt.Errorf("please don't set agent port out of range (1024, 49151)")
	}

	if o.ProxyOptions.KubeconfigPath != "" {
		if _, err := os.Stat(o.ProxyOptions.KubeconfigPath); os.IsNotExist(err) {
			return fmt.Errorf("error checking kubeconfig file %s, got %v", o.ProxyOptions.KubeconfigPath, err)
		}
	}
	return nil
}

func (o *ProxyRunOptions) Print() {
	klog.V(0).Infof("CA set to %q.\n", o.ProxyOptions.CaCert)
	klog.V(0).Infof("CA key file set to %q.\n", o.ProxyOptions.CaKey)
	klog.V(0).Infof("Proxy cert set to %q.\n", o.ProxyOptions.ServerCert)
	klog.V(0).Infof("Proxy key set to %q.\n", o.ProxyOptions.ServerKey)
	klog.V(0).Infof("Host set to %s\n", o.ProxyOptions.Host)
	klog.V(0).Infof("Agent port set to %d.\n", o.ProxyOptions.Port)
	klog.V(0).Infof("Kubeconfig set to %q.\n", o.ProxyOptions.KubeconfigPath)
}

func newProxyRunOptions() *ProxyRunOptions {
	options := &proxy.Options{
		CaCert:           "",
		ServerCert:       "",
		ServerKey:        "",
		Host:             "0.0.0.0",
		Port:             8080,
		KubeconfigPath:   "",
		ProxyServiceHost: "127.0.0.1",
	}

	return &ProxyRunOptions{ProxyOptions: options}
}
