package proxy

import "github.com/zryfish/tower/pkg/apis/tower/v1alpha1"

type ClientSet interface {
	Add(agent *v1alpha1.Agent) error

	Delete(name string) error
}
