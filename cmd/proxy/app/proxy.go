package app

import (
	"context"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	kubeinformer "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	clientset "kubesphere.io/kubesphere/pkg/client/clientset/versioned"
	informers "kubesphere.io/kubesphere/pkg/client/informers/externalversions"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"kubesphere.io/tower/pkg/proxy"
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

			ctx := signals.SetupSignalHandler()

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
				serviceInformerFactory := kubeinformer.NewSharedInformerFactory(kubernetesClient, 10*time.Minute)

				p, err := proxy.NewServer(options.ProxyOptions, agentsInformerFactory.Cluster().V1alpha1().Clusters(), serviceInformerFactory.Core().V1().Services(), clusterClient, kubernetesClient)
				if err != nil {
					klog.Fatalf("Failed to create proxy server, %v", err)
				}

				agentsInformerFactory.Start(ctx.Done())
				serviceInformerFactory.Start(ctx.Done())
				if err = p.Run(ctx.Done()); err != nil {
					klog.Fatalf("Failed to start proxy server, %v", err)
				}

				if err = p.Wait(); err != nil {
					klog.Fatalf("Failed to wait, %v", err)
				}

				select {}
			}

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
