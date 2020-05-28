package app

import (
	"fmt"
	"github.com/spf13/pflag"
	"k8s.io/client-go/tools/leaderelection"
	"kubesphere.io/tower/pkg/proxy"
	"os"
	"time"

	"k8s.io/klog"
)

type ProxyRunOptions struct {
	ProxyOptions   *proxy.Options
	LeaderElect    bool
	LeaderElection *leaderelection.LeaderElectionConfig
}

func (o *ProxyRunOptions) Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("proxy", pflag.ContinueOnError)
	flags.StringVar(&o.ProxyOptions.CaCert, "ca-cert", o.ProxyOptions.CaCert, "CA certificate file we use to validate server clients.")
	flags.StringVar(&o.ProxyOptions.CaKey, "ca-key", o.ProxyOptions.CaKey, "CA private key to sign kubeconfig")
	flags.StringVar(&o.ProxyOptions.Host, "host", "0.0.0.0", "Host listening for agent connections")
	flags.IntVar(&o.ProxyOptions.Port, "port", 8080, "Port listening for agent connections.")
	flags.StringVar(&o.ProxyOptions.PublishServiceAddress, "publish-service-address", o.ProxyOptions.PublishServiceAddress, "Proxy service address, should be accessible for all agents.")
	flags.StringVar(&o.ProxyOptions.KubeConfigPath, "kubeconfig", o.ProxyOptions.KubeConfigPath, "Kubeconfig file absolute path.")
	flags.BoolVar(&o.LeaderElect, "leader-elect", o.LeaderElect, "whether to enable leader election or not")
	return flags
}

func (o *ProxyRunOptions) Validate() error {
	if o.ProxyOptions.Port > 49151 || o.ProxyOptions.Port < 1024 {
		return fmt.Errorf("please don't set agent port out of range (1024, 49151)")
	}

	if o.ProxyOptions.KubeConfigPath != "" {
		if _, err := os.Stat(o.ProxyOptions.KubeConfigPath); os.IsNotExist(err) {
			return fmt.Errorf("error checking kubeconfig file %s, got %v", o.ProxyOptions.KubeConfigPath, err)
		}
	}
	return nil
}

func (o *ProxyRunOptions) Print() {
	klog.V(0).Infof("CA set to %q.\n", o.ProxyOptions.CaCert)
	klog.V(0).Infof("CA key file set to %q.\n", o.ProxyOptions.CaKey)
	klog.V(0).Infof("Host set to %s\n", o.ProxyOptions.Host)
	klog.V(0).Infof("Agent port set to %d.\n", o.ProxyOptions.Port)
	klog.V(0).Infof("Kubeconfig set to %q.\n", o.ProxyOptions.KubeConfigPath)
	klog.V(0).Infof("Leader election set to %t", o.LeaderElect)
}

func newProxyRunOptions() *ProxyRunOptions {
	options := &proxy.Options{
		CaCert:                "",
		CaKey:                 "",
		Host:                  "0.0.0.0",
		Port:                  8080,
		KubeConfigPath:        "",
		PublishServiceAddress: "127.0.0.1",
	}

	return &ProxyRunOptions{
		ProxyOptions: options,
		LeaderElect:  false,
		LeaderElection: &leaderelection.LeaderElectionConfig{
			LeaseDuration: 30 * time.Second,
			RenewDeadline: 15 * time.Second,
			RetryPeriod:   5 * time.Second,
		},
	}
}
