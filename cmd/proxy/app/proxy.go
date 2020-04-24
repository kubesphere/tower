package app

import (
	"flag"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientset "kubesphere.io/tower/pkg/client/clientset/versioned"
	informers "kubesphere.io/tower/pkg/client/informers/externalversions"
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

			clusterClient, err := clientset.NewForConfig(config)
			if err != nil {
				return err
			}

			agentsInformerFactory := informers.NewSharedInformerFactory(clusterClient, 10*time.Minute)

			p, err := proxy.NewServer(options.ProxyOptions, agentsInformerFactory.Cluster().V1alpha1().Clusters(), clusterClient)
			if err != nil {
				return err
			}

			stopCh := signals.SetupSignalHandler()
			agentsInformerFactory.Start(stopCh)

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
