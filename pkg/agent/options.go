package agent

import (
	"kubesphere.io/tower/pkg/utils"
	"time"
)

type Options struct {
	FingerPrint            string
	Auth                   string
	KeepAlive              time.Duration
	MaxRetryCount          int
	MaxRetryInterval       time.Duration
	KubernetesApiserverSvc string
	KubesphereApiserverSvc string
	Server                 string
	Name                   string
	Token                  string
	Remotes                []*utils.Remote

	Kubeconfig string
}
