package app

import (
	"fmt"
	"github.com/spf13/pflag"
	"github.com/zryfish/tower/pkg/agent"
	"github.com/zryfish/tower/pkg/utils"
	"k8s.io/klog"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type AgentRunOptions struct {
	AgentOptions *agent.Options
	Remotes      []string
}

func NewAgentRunOptions() *AgentRunOptions {
	options := &agent.Options{
		Name:             "",
		Server:           "",
		KeepAlive:        1 * time.Minute,
		MaxRetryCount:    0,
		MaxRetryInterval: 5 * time.Minute,
		Token:            "",
	}

	return &AgentRunOptions{AgentOptions: options}
}

func (o *AgentRunOptions) Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("agent", pflag.ContinueOnError)
	flags.StringVar(&o.AgentOptions.Name, "name", o.AgentOptions.Name, "Agent name")
	flags.StringVar(&o.AgentOptions.KubernetesApiserverSvc, "kubernetes-service", "kubernetes.default.svc", "Kubernetes service name")
	flags.StringVar(&o.AgentOptions.KubesphereApiserverSvc, "kubesphere-service", "ks-apigateway.kubesphere-system.svc", "KubeSphere service name")
	flags.DurationVar(&o.AgentOptions.KeepAlive, "keepalive", o.AgentOptions.KeepAlive, "Keepalive duration")
	flags.IntVar(&o.AgentOptions.MaxRetryCount, "max-retry", o.AgentOptions.MaxRetryCount, "Maximum retries, 0 means never stop")
	flags.DurationVar(&o.AgentOptions.MaxRetryInterval, "max-retry-interval", o.AgentOptions.MaxRetryInterval, "Maximum duration between two retries")
	flags.StringVar(&o.AgentOptions.Server, "proxy-server", "http://127.0.0.1:8080", "Proxy server address")
	flags.StringSliceVar(&o.Remotes, "proxy-address", []string{"127.0.0.1:8090:127.0.0.1:443"}, "Proxy settings")
	flags.StringVar(&o.AgentOptions.Token, "token", "", "Token to authenticate with proxy server")
	flags.StringVar(&o.AgentOptions.FingerPrint, "fingerprint", o.AgentOptions.FingerPrint, "Server fingerprint for validation")
	flags.StringVar(&o.AgentOptions.Auth, "auth", o.AgentOptions.Auth, "Authentication information")
	flags.StringVar(&o.AgentOptions.Kubeconfig, "kubeconfig", o.AgentOptions.Kubeconfig, "Use kubeconfig instead of in-cluster config")

	return flags
}

func (o *AgentRunOptions) Validate() error {
	if o.AgentOptions.Server == "" {
		return fmt.Errorf("invalid proxy server url: %s", o.AgentOptions.Server)
	} else {
		u, err := url.Parse(o.AgentOptions.Server)
		if err != nil {
			return err
		}

		if !regexp.MustCompile(`\d+$`).MatchString(u.Host) {
			if u.Scheme == "https" || u.Scheme == "wss" {
				u.Host = u.Host + ":443"
			} else {
				u.Host = u.Host + ":80"
			}
		}

		u.Scheme = strings.Replace(u.Scheme, "http", "ws", 1)
		o.AgentOptions.Server = u.String()
	}

	if len(o.Remotes) == 0 {
		return fmt.Errorf("empty remotes")
	} else {
		for _, s := range o.Remotes {
			r, err := utils.DecodeRemote(s)
			if err != nil {
				return fmt.Errorf("invalid remote %s, %v", s, err)
			}
			o.AgentOptions.Remotes = append(o.AgentOptions.Remotes, r)
		}
	}

	if o.AgentOptions.MaxRetryInterval < time.Second {
		o.AgentOptions.MaxRetryInterval = 5 * time.Minute
	}

	return nil
}

func (o *AgentRunOptions) Print() {
	klog.V(0).Infof("Name set to %s\n", o.AgentOptions.Name)
	klog.V(0).Infof("Server set to %s\n", o.AgentOptions.Server)
	klog.V(0).Infof("Remote address set to %s\n", o.Remotes)
	klog.V(0).Infof("KeepAlive set to %s\n", o.AgentOptions.KeepAlive)
	klog.V(0).Infof("MaxRetries set to %d\n", o.AgentOptions.MaxRetryCount)
	klog.V(0).Infof("MaxRetryInterval set to %s\n", o.AgentOptions.MaxRetryInterval)
	klog.V(0).Infof("Token set to %s\n", o.AgentOptions.Token)
	klog.V(0).Infof("Fingerprint set to %s\n", o.AgentOptions.FingerPrint)
	klog.V(0).Infof("Auth set to %s\n", o.AgentOptions.Auth)
	klog.V(0).Infof("Kubeconfig set to %s\n", o.AgentOptions.Kubeconfig)
	klog.V(0).Infof("Kubernetes service set to %s\n", o.AgentOptions.KubernetesApiserverSvc)
	klog.V(0).Infof("Kubesphere service set to %s\n", o.AgentOptions.KubesphereApiserverSvc)

}
