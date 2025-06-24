package app

import (
	"flag"
	"os"
	"strings"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	"kubesphere.io/tower/pkg/proxy"

	"kubesphere.io/tower/pkg/scheme"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
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

			return Run(options)
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

func Run(options *ProxyRunOptions) error {
	ctx := signals.SetupSignalHandler()

	config, err := clientcmd.BuildConfigFromFlags("", options.ProxyOptions.KubeConfigPath)
	if err != nil {
		klog.Errorf("Failed to create config from kubeconfig file, %v", err)
		return err
	}
	config.QPS = 50
	config.Burst = 100

	kubernetesClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Errorf("Failed to create kubernetes clientSets, %v", err)
		return err
	}

	client, err := runtimeclient.New(config, runtimeclient.Options{Scheme: scheme.Scheme})
	if err != nil {
		klog.Errorf("Failed to create runtime client, %v", err)
		return err
	}

	cmOptions := manager.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
	}
	if options.LeaderElect {
		id, err := os.Hostname()
		if err != nil {
			return err
		}

		// add a uniquifier so that two processes on the same host don't accidentally both become active
		id = id + "_" + string(uuid.NewUUID())

		lock, err := resourcelock.New(resourcelock.LeasesResourceLock,
			"kubesphere-system",
			"tower",
			kubernetesClient.CoreV1(),
			kubernetesClient.CoordinationV1(),
			resourcelock.ResourceLockConfig{
				Identity: id,
				EventRecorder: record.NewBroadcaster().NewRecorder(scheme.Scheme, v1.EventSource{
					Component: "tower",
				}),
			},
		)
		if err != nil {
			klog.Fatalf("error creating lock: %v", err)
		}
		cmOptions = manager.Options{
			Scheme:                              scheme.Scheme,
			MetricsBindAddress:                  "0",
			LeaderElection:                      options.LeaderElect,
			LeaseDuration:                       &options.LeaderElection.LeaseDuration,
			RenewDeadline:                       &options.LeaderElection.RenewDeadline,
			RetryPeriod:                         &options.LeaderElection.RetryPeriod,
			LeaderElectionResourceLockInterface: lock,
		}
	}

	mgr, err := manager.New(config, cmOptions)
	if err != nil {
		klog.Fatalf("Failed to create controller manager, %v", err)
	}

	p, err := proxy.NewServer(options.ProxyOptions, client, kubernetesClient)
	if err != nil {
		klog.Fatalf("Failed to create proxy server, %v", err)
	}

	err = p.SetupWithManager(mgr)
	if err != nil {
		klog.Fatalf("Failed to setup proxy server with manager, %v", err)
	}

	return mgr.Start(ctx)
}
