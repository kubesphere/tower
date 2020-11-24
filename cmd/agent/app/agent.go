package app

import (
	"context"
	"flag"
	"os"
	"strings"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"

	"kubesphere.io/tower/pkg/agent"
)

func NewAgentCommand() *cobra.Command {
	o := NewAgentRunOptions()

	cmd := &cobra.Command{
		Use:  "Agent",
		Long: "Agent client run in user cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Print()
			if err := o.Validate(); err != nil {
				return err
			}

			stopCh := signals.SetupSignalHandler()
			agentrunfunc := func(ctx context.Context) {
				client, err := agent.NewAgent(o.AgentOptions)
				if err != nil {
					klog.Fatal(err)
				}

				if err := client.Run(); err != nil {
					klog.Fatal(err)
				}

				if err := client.Wait(); err != nil {
					klog.Fatal()
				}

				select {}

			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				<-stopCh
				cancel()
			}()

			if !o.LeaderElect {
				agentrunfunc(ctx)
				return nil
			}

			id, err := os.Hostname()
			if err != nil {
				return err
			}

			config, err := clientcmd.BuildConfigFromFlags("", o.AgentOptions.Kubeconfig)
			if err != nil {
				klog.Errorf("Failed to create config from kubeconfig file, %v", err)
				return err
			}

			kubernetesClient, err := kubernetes.NewForConfig(config)
			if err != nil {
				klog.Errorf("Failed to create kubernetes clientSets, %v", err)
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
				LeaseDuration: o.LeaderElection.LeaseDuration,
				RenewDeadline: o.LeaderElection.RenewDeadline,
				RetryPeriod:   o.LeaderElection.RetryPeriod,
				Callbacks: leaderelection.LeaderCallbacks{
					OnStartedLeading: agentrunfunc,
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
	fs.AddFlagSet(o.Flags())
	local := flag.NewFlagSet("", flag.ExitOnError)
	klog.InitFlags(local)
	local.VisitAll(func(fl *flag.Flag) {
		fl.Name = strings.Replace(fl.Name, "_", "-", -1)
		fs.AddGoFlag(fl)
	})

	return cmd
}
