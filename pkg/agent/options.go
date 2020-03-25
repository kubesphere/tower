package agent

import (
	"time"
)

type Options struct {
	KeepAlive              time.Duration
	MaxRetryCount          int
	MaxRetryInterval       time.Duration
	KubernetesApiserverSvc string
	KubesphereApiserverSvc string
	Server                 string
	Name                   string
	Token                  string

	Kubeconfig string
}
