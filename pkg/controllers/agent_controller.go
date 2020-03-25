package controllers

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"kubesphere.io/tower/pkg/apis/tower/v1alpha1"
	"kubesphere.io/tower/pkg/certs"
	clientset "kubesphere.io/tower/pkg/client/clientset/versioned"
	towerinformers "kubesphere.io/tower/pkg/client/informers/externalversions/tower/v1alpha1"
	towerlisters "kubesphere.io/tower/pkg/client/listers/tower/v1alpha1"
	"math/rand"
	"reflect"
	"time"
)

const (
	// maxRetries is the number of times a service will be retried before it is dropped out of the queue.
	// With the current rate-limiter in use (5ms*2^(maxRetries-1)) the following numbers represent the
	// sequence of delays between successive queuings of a service.
	//
	// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1.3s, 2.6s, 5.1s, 10.2s, 20.4s, 41s, 82s
	maxRetries = 15

	// allocate kubernetesAPIServer port in range [portRangeMin, portRangeMax] for agents if port is not specified
	// kubesphereAPIServer port is defaulted to kubernetesAPIServerPort + 10000
	portRangeMin = 6000
	portRangeMax = 7000
)

type AgentController struct {
	agentClient clientset.Interface

	agentLister towerlisters.AgentLister
	agentSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	workerLoopPeriod time.Duration

	certificateIssuer certs.CertificateIssuer
}

func NewAgentController(agentInformer towerinformers.AgentInformer,
	client clientset.Interface,
	certificateIssuer certs.CertificateIssuer) *AgentController {
	v := &AgentController{
		agentClient:       client,
		queue:             workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "agent"),
		workerLoopPeriod:  time.Second,
		certificateIssuer: certificateIssuer,
	}

	agentInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: v.addAgent,
		UpdateFunc: func(old, new interface{}) {
			v.addAgent(new)
		},
		DeleteFunc: v.addAgent,
	})

	v.agentLister = agentInformer.Lister()
	v.agentSynced = agentInformer.Informer().HasSynced

	return v
}

func (c *AgentController) Start(stopCh <-chan struct{}) error {
	return c.Run(5, stopCh)
}

func (c *AgentController) Run(workers int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.V(0).Info("Starting agent controller...")
	defer klog.V(0).Info("Shutting down agent controller...")

	if !cache.WaitForCacheSync(stopCh, c.agentSynced) {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, stopCh)
	}
	<-stopCh
	return nil
}

func (c *AgentController) worker() {
	for c.processNextWorkItem() {

	}
}

func (c *AgentController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	err := c.syncAgent(key.(string))
	c.handleError(err, key)

	return true
}

func (c *AgentController) addAgent(obj interface{}) {
	agent := obj.(*v1alpha1.Agent)
	key, err := cache.MetaNamespaceKeyFunc(agent)
	if err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.queue.Add(key)
}

func (c *AgentController) syncAgent(key string) error {
	startTime := time.Now()
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		klog.Error(err, "not a valid controller key", "key", key)
		return err
	}

	defer func() {
		klog.V(4).Infof("Finished syncing agent %s/%s in %s", namespace, name, time.Since(startTime))
	}()

	agent, err := c.agentLister.Agents(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		klog.Error(err)
		return err
	}

	klog.V(2).Info("New agent added, needed to prepare...", agent.Name)

	newAgent := agent.DeepCopy()
	// filled spec if not specified
	if agent.Spec.KubernetesAPIServerPort == 0 || agent.Spec.KubeSphereAPIGatewayPort == 0 {
		port, err := c.allocatePort()
		if err != nil {
			klog.Error(err)
			return err
		}

		agent.Spec.KubernetesAPIServerPort = port
		agent.Spec.KubeSphereAPIGatewayPort = port + 10000
	}

	// token uninitialized, generate a new token
	if len(agent.Spec.Token) == 0 {
		agent.Spec.Token = c.generateToken()
	}

	if agent.Status.Conditions == nil {
		agent.Status.Conditions = make([]v1alpha1.AgentCondition, 0)

		initializedCondition := v1alpha1.AgentCondition{
			Type:               v1alpha1.AgentInitialized,
			Status:             corev1.ConditionTrue,
			LastUpdateTime:     v1.NewTime(time.Now()),
			LastTransitionTime: v1.NewTime(time.Now()),
			Reason:             "",
			Message:            "Agent has been initialized, waiting for connection...",
		}

		agent.Status.Conditions = append(agent.Status.Conditions, initializedCondition)
	}

	// kubeConfig not issued
	if len(agent.Status.KubeConfig) == 0 {
		// Issue kubeConfig
		config, err := c.certificateIssuer.IssueKubeConfig("kubernetes", agent.Spec.KubernetesAPIServerPort)
		if err != nil {
			klog.Error(err)
			return err
		}
		agent.Status.KubeConfig = config
	}

	if !reflect.DeepEqual(agent, newAgent) {
		_, err = c.agentClient.TowerV1alpha1().Agents(agent.Namespace).Update(agent)
		if err != nil {
			klog.Error(err)
			return err
		}
	}

	return nil
}

func (c *AgentController) handleError(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < maxRetries {
		klog.V(2).Info("Error syncing agent, retrying", key, err)
		c.queue.AddRateLimited(key)
		return
	}

	klog.V(4).Info("Dropping agent out of queue.", key, err)
	c.queue.Forget(key)
	utilruntime.HandleError(err)
}

// allocatePort find a available port between [portRangeMin, portRangeMax] in maximumRetries
// TODO: only works with handful clusters
func (c *AgentController) allocatePort() (uint16, error) {
	rand.Seed(time.Now().UnixNano())

	agents, err := c.agentLister.List(labels.Everything())
	if err != nil {
		return 0, err
	}

	const maximumRetries = 10
	for i := 0; i < maximumRetries; i++ {
		collision := false
		port := uint16(portRangeMin + rand.Intn(portRangeMax-portRangeMin+1))

		for _, item := range agents {
			if item.Spec.KubernetesAPIServerPort != 0 && item.Spec.KubernetesAPIServerPort == port {
				collision = true
				break
			}
		}

		if !collision {
			return port, nil
		}
	}

	return 0, fmt.Errorf("unable to allocate port after %d retries", maximumRetries)
}

// generateToken returns a random 32-byte string as token
func (c *AgentController) generateToken() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
