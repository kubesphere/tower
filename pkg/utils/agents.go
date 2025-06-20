package utils

import (
	"sync"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubesphere.io/tower/pkg/api/cluster/v1alpha1"
)

type Agents struct {
	sync.RWMutex
	inner map[string]*v1alpha1.Cluster
}

func NewAgents() *Agents {
	return &Agents{
		inner: map[string]*v1alpha1.Cluster{},
	}
}

func FakeAgents() *Agents {
	agents := NewAgents()
	agents.inner["alpha"] = &v1alpha1.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name: "alpha",
		},
		Spec: v1alpha1.ClusterSpec{
			Connection: v1alpha1.Connection{
				Type:                    v1alpha1.ConnectionTypeProxy,
				Token:                   "abcedefg",
				KubernetesAPIServerPort: 6443,
				KubeSphereAPIServerPort: 16443,
			},
		},
	}

	return agents
}

// Len returns the number of agents
func (g *Agents) Len() int {
	g.RLock()
	l := len(g.inner)
	g.RUnlock()
	return l
}

// Get agent from the index by key
func (g *Agents) Get(key string) (*v1alpha1.Cluster, bool) {
	g.RLock()
	agent, found := g.inner[key]
	g.RUnlock()
	return agent, found
}

// Set an agent into the list by specific key
func (g *Agents) Set(key string, agent *v1alpha1.Cluster) {
	g.Lock()
	g.inner[key] = agent
	g.Unlock()
}

// Delete an agent from the list
func (g *Agents) Del(key string) {
	g.Lock()
	delete(g.inner, key)
	g.Unlock()
}

// Add adds an agent to the list
func (g *Agents) Add(cluster *v1alpha1.Cluster) {
	g.Set(cluster.Name, cluster)
}
