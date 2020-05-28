package app

import (
	"context"
	"flag"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	clientset "kubesphere.io/tower/pkg/client/clientset/versioned"
	informers "kubesphere.io/tower/pkg/client/informers/externalversions"
	"kubesphere.io/tower/pkg/proxy"
	"os"
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

			stopCh := signals.SetupSignalHandler()

			var config *rest.Config
			config, err := clientcmd.BuildConfigFromFlags("", options.ProxyOptions.KubeConfigPath)
			if err != nil {
				klog.Errorf("Failed to create config from kubeconfig file, %v", err)
				return err
			}

			kubernetesClient, err := kubernetes.NewForConfig(config)
			if err != nil {
				klog.Errorf("Failed to create kubernetes clientSets, %v", err)
				return err
			}

			clusterClient, err := clientset.NewForConfig(config)
			if err != nil {
				klog.Errorf("Failed to create cluster clientSets, %v", err)
				return err
			}

			run := func(ctx context.Context) {
				agentsInformerFactory := informers.NewSharedInformerFactory(clusterClient, 10*time.Minute)

				p, err := proxy.NewServer(options.ProxyOptions, agentsInformerFactory.Cluster().V1alpha1().Clusters(), clusterClient)
				if err != nil {
					klog.Fatalf("Failed to create proxy server, %v", err)
				}

				agentsInformerFactory.Start(stopCh)

				if err := p.Run(stopCh); err != nil {
					klog.Fatalf("Failed to start proxy server, %v", err)
				}

				err = p.Wait()
				if err != nil {
					klog.Fatalf("Failed to wait, %v", err)
				}

				select {}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				<-stopCh
				cancel()
			}()

			if !options.LeaderElect {
				run(ctx)
				return nil
			}

			id, err := os.Hostname()
			if err != nil {
				return err
			}

			// add a uniquifier so that two processes on the same host don't accidentally both become active
			id = id + "_" + string(uuid.NewUUID())

			// TODO: change lockType to lease
			// once we finished moving to Kubernetes v1.16+, we
			// change lockType to lease
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
				})

			if err != nil {
				klog.Fatalf("error creating lock: %v", err)
			}

			leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
				Lock:          lock,
				LeaseDuration: options.LeaderElection.LeaseDuration,
				RenewDeadline: options.LeaderElection.RenewDeadline,
				RetryPeriod:   options.LeaderElection.RetryPeriod,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: run,
					OnStoppedLeading: func() {
						klog.Errorf("leadership lost")
						os.Exit(0)
					},
				},
			})

			return nil
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
