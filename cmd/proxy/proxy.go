package main

import (
	"context"
	"fmt"
	"github.com/spf13/cobra"
)

type Proxy struct {
}

type StopFunc func()

func (o *Proxy) run(options *ProxyRunOptions) error {
	options.Print()

	if err := options.Validate(); err != nil {
		return fmt.Errorf("failed to validate options with error %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

}

func (o *Proxy) start(ctx context.Context, options *ProxyRunOptions) (StopFunc, error) {

}

func newProxyCommand(p *Proxy, o *ProxyRunOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "proxy",
		Long: "A proxy server, proxy requests to agents which forward to behind API server.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.run(o)
		},
	}

	return cmd
}
