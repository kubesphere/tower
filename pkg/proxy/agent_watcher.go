package proxy

import "kubesphere.io/tower/pkg/apis/tower/v1alpha1"

type ClientSet interface {
	Add(agent *v1alpha1.Agent) error

	Delete(name string) error
}
