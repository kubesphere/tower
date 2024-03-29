package app

import (
	"flag"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"kubesphere.io/tower/pkg/agent"
)

func NewAgentCommand() *cobra.Command {
	o := NewAgentRunOptions()

	cmd := &cobra.Command{
		Use:  "Agent",
		Long: "Agent client run in user cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}

			client, err := agent.NewAgent(o.AgentOptions)
			if err != nil {
				klog.Error(err)
				return err
			}

			if err := client.Run(); err != nil {
				klog.Error(err)
				return err
			}
			return client.Wait()
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
