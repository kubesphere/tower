package app

import (
	"flag"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"kubesphere.io/tower/pkg/certs"
	clientset "kubesphere.io/tower/pkg/client/clientset/versioned"
	informers "kubesphere.io/tower/pkg/client/informers/externalversions"
	"kubesphere.io/tower/pkg/controllers"
	"kubesphere.io/tower/pkg/proxy"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"

	"k8s.io/klog"
	"strings"
	"time"
)

func NewProxyCommand() *cobra.Command {
	options := newProxyRunOptions()

	cmd := &cobra.Command{
		Use:  "proxy",
		Long: "A proxy server, proxy requests to agents which forward to behind API server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			options.Print()
			if err := options.Validate(); err != nil {
				return err
			}

			var config *rest.Config
			config, err := clientcmd.BuildConfigFromFlags("", options.ProxyOptions.KubeConfigPath)
			if err != nil {
				return err
			}

			agentsClient, err := clientset.NewForConfig(config)
			if err != nil {
				return err
			}

			agentsInformerFactory := informers.NewSharedInformerFactory(agentsClient, 10*time.Minute)

			p, err := proxy.NewServer(options.ProxyOptions, agentsInformerFactory.Tower().V1alpha1().Agents(), agentsClient)
			if err != nil {
				return err
			}

			certificateIssuer, err := certs.NewSimpleCertificateIssuer(options.ProxyOptions.CaCert, options.ProxyOptions.CaKey, options.ProxyOptions.PublishServiceAddress)
			if err != nil {
				return err
			}

			agentController := controllers.NewAgentController(agentsInformerFactory.Tower().V1alpha1().Agents(), agentsClient, certificateIssuer)

			stopCh := signals.SetupSignalHandler()
			agentsInformerFactory.Start(stopCh)
			err = agentController.Start(stopCh)
			if err != nil {
				return err
			}

			if err := p.Run(stopCh); err != nil {
				return err
			}

			return p.Wait()
		},
	}

	fs := cmd.Flags()
	fs.AddFlagSet(options.Flags())
	local := flag.NewFlagSet("", flag.ExitOnError)
	klog.InitFlags(local)
	local.VisitAll(func(fl *flag.Flag) {
		fl.Name = strings.Replace(fl.Name, "_", "-", -1)
		fs.AddGoFlag(fl)
	})

	return cmd
}
