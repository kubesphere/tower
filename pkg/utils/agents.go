package utils

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubesphere.io/tower/pkg/apis/tower/v1alpha1"
	"sync"
)

type Agents struct {
	sync.RWMutex
	inner map[string]*v1alpha1.Agent
}

func NewAgents() *Agents {
	return &Agents{
		inner: map[string]*v1alpha1.Agent{},
	}
}

func FakeAgents() *Agents {
	agents := NewAgents()
	agents.inner["alpha"] = &v1alpha1.Agent{
		ObjectMeta: v1.ObjectMeta{
			Name: "alpha",
		},
		Spec: v1alpha1.AgentSpec{
			Token:                   "abcedefg",
			KubernetesAPIServerPort: 6443,
			KubeSphereAPIServerPort: 16443,
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
func (g *Agents) Get(key string) (*v1alpha1.Agent, bool) {
	g.RLock()
	agent, found := g.inner[key]
	g.RUnlock()
	return agent, found
}

// Set an agent into the list by specific key
func (g *Agents) Set(key string, agent *v1alpha1.Agent) {
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
func (g *Agents) Add(agent *v1alpha1.Agent) {
	g.Set(agent.Name, agent)
}
