package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"kubesphere.io/tower/pkg/agent"
	"kubesphere.io/tower/pkg/api/cluster/v1alpha1"
	"kubesphere.io/tower/pkg/certs"
	"kubesphere.io/tower/pkg/utils"
	"kubesphere.io/tower/pkg/version"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	// allocate kubernetesAPIServer port in range [portRangeMin, portRangeMax] for agents if port is not specified
	// kubesphereAPIServer port is defaulted to kubernetesAPIServerPort + 10000
	portRangeMin = 6000
	portRangeMax = 7000

	// Proxy service port
	kubernetesPort = 6443
	kubespherePort = 80

	defaultAgentNamespace = "kubesphere-system"
	svcPrefix             = "mc-"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Proxy struct {
	httpServer *HTTPServer
	agents     *utils.Agents
	sessions   map[string]*HTTPProxy
	sshConfig  *ssh.ServerConfig

	certificateIssuer certs.CertificateIssuer

	host string
	port int

	caCert []byte
	caKey  []byte

	clusterClient runtimeclient.Client
	k8sClientSet  *kubernetes.Clientset
}

func (s *Proxy) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Cluster{}).
		Watches(
			&source.Kind{Type: &corev1.Service{}},
			handler.EnqueueRequestsFromMapFunc(
				func(h client.Object) []reconcile.Request {
					if !strings.HasPrefix(h.GetName(), svcPrefix) {
						klog.V(4).Infof("service:%s has no relation with tower", h.GetName())
						return nil
					}

					// get cluster by svc name
					clusterName := strings.TrimPrefix(h.GetName(), svcPrefix)
					return []reconcile.Request{{
						NamespacedName: types.NamespacedName{
							Name: clusterName,
						},
					}}
				}),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					return true
				},
				CreateFunc: func(e event.CreateEvent) bool {
					return true
				},
				DeleteFunc: func(e event.DeleteEvent) bool {
					return false
				},
			}),
		).
		Named("ProxyController").
		Complete(s)
	if err != nil {
		klog.Errorf("Failed to setup controller for Proxy: %v", err)
		return err
	}

	return mgr.Add(s)
}

// Reconcile reconciles the Cluster object.
func (s *Proxy) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.V(4).Infof("Starting to sync cluster %s", req.Name)
	defer klog.V(4).Infof("Finished syncing cluster %s", req.Name)

	cluster := &v1alpha1.Cluster{}
	if err := s.clusterClient.Get(ctx, req.NamespacedName, cluster); err != nil {
		if apierrors.IsNotFound(err) {
			s.delete(req.Name)
			klog.V(4).Infof("Cluster %s not found, skipping reconcile", req.Name)
			return ctrl.Result{}, nil
		}
		klog.Errorf("Failed to get cluster %s: %v", req.Name, err)
		return ctrl.Result{}, err
	}

	if !cluster.DeletionTimestamp.IsZero() {
		s.delete(cluster.Name)
		klog.V(4).Infof("Cluster %s is being deleted, skipping reconcile", req.Name)
		return ctrl.Result{}, nil
	}

	// currently we didn't set cluster.Spec.Enable when creating cluster at client side, so only check
	// if we enable cluster.Spec.JoinFederation now
	if !cluster.Spec.JoinFederation || cluster.Spec.Connection.Type != v1alpha1.ConnectionTypeProxy {
		s.delete(cluster.Name)
		return ctrl.Result{}, nil
	}

	if err := s.addCluster(cluster); err != nil {
		klog.Errorf("Failed to add cluster %s: %v", req.Name, err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, s.addSVC(cluster)
}

func NewServer(options *Options, client runtimeclient.Client, k8sClientSet *kubernetes.Clientset) (*Proxy, error) {
	s := &Proxy{
		httpServer:    NewHTTPServer(),
		agents:        utils.NewAgents(),
		sessions:      make(map[string]*HTTPProxy, 0),
		host:          options.Host,
		port:          options.Port,
		clusterClient: client,
		k8sClientSet:  k8sClientSet,
	}

	key, _ := generateKey()
	private, err := ssh.ParsePrivateKey(key)
	if err != nil {
		klog.Fatalf("Failed to parse key %v", err)
	}
	s.sshConfig = &ssh.ServerConfig{
		ServerVersion:    "SSH-" + version.ProtocolVersion + "-server",
		PasswordCallback: s.authenticate,
	}
	s.sshConfig.AddHostKey(private)

	s.caCert, s.caKey = loadCertificateOrDie(options.CaCert), loadCertificateOrDie(options.CaKey)

	s.certificateIssuer, err = certs.NewSimpleCertificateIssuer(options.CaCert, options.CaKey, "")
	if err != nil {
		klog.Fatal(err)
	}

	return s, nil
}

func (s *Proxy) handleClientHandler(w http.ResponseWriter, r *http.Request) {
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if upgrade == "websocket" && strings.HasPrefix(protocol, "kubesphere-") {
		if protocol == version.ProtocolVersion {
			s.handleWebsocket(w, r)
			return
		}
		klog.V(4).Infof("Ignoring client connection using protocol '%s', expected '%s'", protocol, version.ProtocolVersion)
	}

	switch r.URL.String() {
	case "/health":
		w.Write([]byte("OK\n"))
		return
	case "/version":
		w.Write([]byte(version.BuildVersion))
		return
	}

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Not Found"))
}

func (s *Proxy) handleWebsocket(w http.ResponseWriter, req *http.Request) {
	klog.V(4).Info("New agent connection")
	wsConn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		klog.Error("Failed to upgrade connection", err)
		return
	}
	connection := utils.NewWebSocketConn(wsConn)

	klog.V(4).Info("Handshaking...")

	sshConn, chans, reqs, err := ssh.NewServerConn(connection, s.sshConfig)
	if err != nil {
		klog.Error("Failed to handshake", err)
		return
	}

	klog.V(4).Info("Verifying configuration")
	var r *ssh.Request
	select {
	case r = <-reqs:
	case <-time.After(10 * time.Second):
		sshConn.Close()
		return
	}

	failed := func(err error) {
		klog.Error("failed ", err)
		r.Reply(false, []byte(err.Error()))
	}

	if r.Type != "config" {
		failed(errors.New("expecting config request"))
		return
	}

	c := &agent.Config{}
	err = c.Unmarshal(r.Payload)
	if err != nil {
		klog.Error("Unable to unmarshal config from agent", r.Payload)
		return
	}

	client, ok := s.agents.Get(c.Name)
	if !ok || (c.Token != client.Spec.Connection.Token) {
		r.Reply(false, []byte("Unauthorized agent"))
		return
	}

	u, err := url.Parse(client.Spec.Connection.KubeSphereAPIEndpoint)
	if err != nil {
		klog.Errorf("Failed to get host %#v", err)
		failed(err)
		return
	}
	dnsNames := []string{u.Hostname()}
	ips := []string{u.Hostname()}
	if client.Spec.ExternalKubeAPIEnabled && len(client.Spec.Connection.ExternalKubernetesAPIEndpoint) > 0 {
		eu, err := url.Parse(client.Spec.Connection.ExternalKubernetesAPIEndpoint)
		if err != nil {
			klog.Errorf("Failed to get external host %#v", err)
		} else {
			dnsNames = append(dnsNames, eu.Hostname())
			ips = append(ips, eu.Hostname())
		}
	}
	klog.V(4).Infof("IssueCertAndKey for %v", dnsNames)

	cert, key, err := s.certificateIssuer.IssueCertAndKey(ips, dnsNames)
	if err != nil {
		klog.Errorf("Failed to issue certificates, %#v", err)
		return
	}

	var (
		proxy        *HTTPProxy
		k8sTransport *http.Transport
		ksTransport  *http.Transport
	)

	// if the agent has connected the server with the same cluster name, we don't need to create HttpProxy anymore
	// we only create two new httpTransport objects, then put them into the server's httpClient set.
	if proxy, ok = s.sessions[c.Name]; !ok {
		proxy, k8sTransport, ksTransport, err = NewHTTPProxy(sshConn, client.Spec.Connection.KubernetesAPIServerPort, client.Spec.Connection.KubeSphereAPIServerPort, c, s.caCert, cert, key)
		if err != nil {
			failed(err)
			return
		}

		if err = proxy.Start(proxy.ctx); err != nil {
			failed(err)
			return
		}

		s.sessions[c.Name] = proxy
	} else {
		k8sTransport, _, _, err = buildServerData(sshConn, c.KubernetesSvcHost, c.CAData, c.CertData, c.KeyData, s.caCert, cert, key)
		if err != nil {
			failed(err)
			return
		}

		ksTransport, _, _, err = buildServerData(sshConn, c.KubeSphereSvcHost, c.CAData, c.CertData, c.KeyData, s.caCert, cert, key)
		if err != nil {
			failed(err)
			return
		}

		proxy.kubernetesAPIServerProxy.rwLock.Lock()
		proxy.kubernetesAPIServerProxy.httpClient = append(proxy.kubernetesAPIServerProxy.httpClient, &http.Client{Transport: k8sTransport})
		proxy.kubernetesAPIServerProxy.rwLock.Unlock()

		proxy.kubesphereAPIServerProxy.rwLock.Lock()
		proxy.kubesphereAPIServerProxy.httpClient = append(proxy.kubesphereAPIServerProxy.httpClient, &http.Client{Transport: ksTransport})
		proxy.kubesphereAPIServerProxy.rwLock.Unlock()
	}

	r.Reply(true, nil)
	klog.V(0).Infof("Connection established with %s", client.Name)
	retry.OnError(retry.DefaultBackoff, apierrors.IsConflict, func() error {
		return s.Update(client, true)
	})

	go s.handleSSHRequests(reqs)
	go s.handleSSHChannels(chans)
	sshConn.Wait()
	klog.V(0).Infof("Connection closed with %s", client.Name)

	proxy.kubernetesAPIServerProxy.rwLock.Lock()
	defer proxy.kubernetesAPIServerProxy.rwLock.Unlock()
	k8sLen := len(proxy.kubernetesAPIServerProxy.httpClient)

	proxy.kubesphereAPIServerProxy.rwLock.Lock()
	defer proxy.kubesphereAPIServerProxy.rwLock.Unlock()
	ksLen := len(proxy.kubesphereAPIServerProxy.httpClient)

	// httpClientLength <= 1 means there is not enough agent connection
	// we need to delete the key, call cancel(), update cluster status
	// httpClientLength > 1 means there are enough agent connections
	// we just update the httpTransport set safely
	if k8sLen <= 1 || ksLen <= 1 {
		delete(s.sessions, c.Name)
		proxy.cancel()
		retry.OnError(retry.DefaultBackoff, apierrors.IsConflict, func() error {
			return s.Update(client, false)
		})
	} else {
		for i, v := range proxy.kubernetesAPIServerProxy.httpClient {
			if v.Transport == k8sTransport {
				proxy.kubernetesAPIServerProxy.httpClient = append(proxy.kubernetesAPIServerProxy.httpClient[:i],
					proxy.kubernetesAPIServerProxy.httpClient[i+1:]...)
				break
			}
		}

		for i, v := range proxy.kubesphereAPIServerProxy.httpClient {
			if v.Transport == ksTransport {
				proxy.kubesphereAPIServerProxy.httpClient = append(proxy.kubesphereAPIServerProxy.httpClient[:i],
					proxy.kubesphereAPIServerProxy.httpClient[i+1:]...)
				break
			}
		}
	}
}

func (s *Proxy) Start(ctx context.Context) error {
	port := strconv.Itoa(s.port)
	klog.V(0).Infof("Listening on %s:%d...", s.host, port)

	h := http.Handler(http.HandlerFunc(s.handleClientHandler))
	h = wrap(h)

	if err := s.httpServer.GoListenAndServe(s.host+":"+port, h); err != nil {
		klog.Errorf("Failed to start HTTP server on %s:%d: %v", s.host, s.port, err)
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Wait()
	}()

	select {
	case <-ctx.Done():
		klog.V(0).Info("Shutting down HTTP server...")
		s.Close()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		t0 := time.Now()
		next.ServeHTTP(w, req)

		klog.V(4).Infof("Connection to %s lasts for %s", req.Host, time.Since(t0))

	})
}

func (s *Proxy) Wait() error {
	return s.httpServer.Wait()
}

func (s *Proxy) Close() error {
	return s.httpServer.Close()
}

func (s *Proxy) handleSSHRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "ping":
			r.Reply(true, nil)
		default:
			klog.V(4).Info("unknown request", r)
		}
	}
}

func (s *Proxy) handleSSHChannels(chans <-chan ssh.NewChannel) {
	for ch := range chans {
		remote := string(ch.ExtraData())
		stream, reqs, err := ch.Accept()
		if err != nil {
			klog.Error("failed to accept stream", err)
			continue
		}
		go ssh.DiscardRequests(reqs)
		go utils.HandleTCPStream(stream, remote)
	}
}

func (s *Proxy) authenticate(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	klog.V(4).Infof("%s is connecting from %s", c.User(), c.RemoteAddr())
	return nil, nil
}

// addCluster funcition is called when a cluster object is created or updated
// if the cluster type is not proxy, it returns.
// if not and the cluster object is not initialized, it will allocate port, create a proxy svc(or update the
// existed svc), generate a token for the proxy connection, finally update the cluster to initialized status.
func (s *Proxy) addCluster(cluster *v1alpha1.Cluster) error {
	// save a old copy of cluster
	oldCluster := cluster.DeepCopy()
	serviceName := fmt.Sprintf("%s%s", svcPrefix, cluster.Name)

	// if the cluster has been initialized, we update the cache and check if we need to change service
	if isConditionTrue(cluster, v1alpha1.ClusterInitialized) {
		s.agents.Add(cluster)

		if !cluster.Spec.ExternalKubeAPIEnabled {
			return nil
		}

		service, err := s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			klog.Error(err)
			return err
		}
		updateServiceByExternalKubeAPI(cluster, service)
		if _, err = s.createOrUpdateService(serviceName, service); err != nil {
			klog.Error(err)
			return err
		}
		return nil
	}

	// allocate ports for kubernetes and kubesphere endpoint
	port, err := s.allocatePort()
	if err != nil {
		klog.Errorf("failed to allocate port for cluster %s, err: %+v", cluster.Name, err)
		return err
	}

	cluster.Spec.Connection.KubernetesAPIServerPort = port
	cluster.Spec.Connection.KubeSphereAPIServerPort = port + 10000

	if len(cluster.Spec.Connection.Token) == 0 {
		cluster.Spec.Connection.Token = s.generateToken()
	}

	// create a proxy service spec
	mcService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: defaultAgentNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": serviceName,
				"app":                    serviceName,
			},
		},
		Spec: corev1.ServiceSpec{
			Type: "ClusterIP",
			Selector: map[string]string{
				"app.kubernetes.io/name": "tower",
				"app":                    "tower",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "kubernetes",
					Protocol:   corev1.ProtocolTCP,
					Port:       kubernetesPort,
					TargetPort: intstr.FromInt(int(cluster.Spec.Connection.KubernetesAPIServerPort)),
				},
				{
					Name:       "kubesphere",
					Protocol:   corev1.ProtocolTCP,
					Port:       kubespherePort,
					TargetPort: intstr.FromInt(int(cluster.Spec.Connection.KubeSphereAPIServerPort)),
				},
			},
		},
	}

	if cluster.Spec.ExternalKubeAPIEnabled {
		updateServiceByExternalKubeAPI(cluster, mcService)
	}

	service, err := s.createOrUpdateService(serviceName, mcService)
	if err != nil {
		klog.Error(err)
		return err
	}

	klog.V(4).Infof("service.Spec.ClusterIP '%s'", service.Spec.ClusterIP)
	// populates the kubernetes apiEndpoint and kubesphere apiEndpoint
	cluster.Spec.Connection.KubernetesAPIEndpoint = fmt.Sprintf("https://%s:%d", service.Spec.ClusterIP, kubernetesPort)
	cluster.Spec.Connection.KubeSphereAPIEndpoint = fmt.Sprintf("http://%s:%d", service.Spec.ClusterIP, kubespherePort)

	initializedCondition := v1alpha1.ClusterCondition{
		Type:               v1alpha1.ClusterInitialized,
		Status:             corev1.ConditionTrue,
		Reason:             string(v1alpha1.ClusterInitialized),
		Message:            "Cluster has been initialized",
		LastUpdateTime:     metav1.Now(),
		LastTransitionTime: metav1.Now(),
	}

	updateClusterCondition(cluster, initializedCondition)

	if !reflect.DeepEqual(oldCluster, cluster) {
		err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			c := &v1alpha1.Cluster{}
			err := s.clusterClient.Get(context.TODO(), types.NamespacedName{Name: cluster.Name}, c)
			if err != nil {
				return err
			}

			cluster.ResourceVersion = c.ResourceVersion
			err = s.clusterClient.Update(context.TODO(), cluster)
			return err
		})
		if err != nil {
			klog.Errorf("failed to update cluster %s, err: %+v", cluster.Name, err)
			return err
		}
	}
	s.agents.Add(cluster)
	return nil
}

func updateServiceByExternalKubeAPI(cluster *v1alpha1.Cluster, service *corev1.Service) {
	// get lb annotations from cluster annotations
	externalLBAnnotations, ok := cluster.Annotations["tower.kubesphere.io/external-lb-service-annoations"]
	if ok {
		var annotation map[string]string
		if err := json.Unmarshal([]byte(externalLBAnnotations), &annotation); err != nil {
			klog.Errorf("failed to decode annotation for tower.kubesphere.io/external-lb.err: %+v", err)
		} else {
			service.Annotations = annotation
		}
	}
	service.Spec.Type = "LoadBalancer"
}

func (s *Proxy) createOrUpdateService(serviceName string, mcService *corev1.Service) (*corev1.Service, error) {
	service, err := s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get service %s. err: %+v", serviceName, err)
		}
		// proxy service not found, we create the proxy service
		service, err = s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Create(context.TODO(), mcService, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create service %s. err: %+v", serviceName, err)
		}
		return service, nil
	}

	// update existed proxy service
	if reflect.DeepEqual(service.Spec, mcService.Spec) {
		return service, nil
	}

	service.ObjectMeta.Annotations = mcService.Annotations
	mcService.ObjectMeta = service.ObjectMeta
	mcService.Spec.ClusterIP = service.Spec.ClusterIP

	if err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		svc, err := s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Get(context.TODO(),
			mcService.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		mcService.ResourceVersion = svc.ResourceVersion
		_, err = s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Update(context.TODO(),
			mcService, metav1.UpdateOptions{})
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to update svc: %s, err: %+v", serviceName, err)
	}
	return mcService, nil
}

func (s *Proxy) delete(clusterName string) {
	_, found := s.agents.Get(clusterName)
	if found {
		s.agents.Del(clusterName)
	}

	serviceName := fmt.Sprintf("%s%s", svcPrefix, clusterName)
	if err := s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Delete(context.TODO(), serviceName,
		*metav1.NewDeleteOptions(0)); err != nil && !apierrors.IsNotFound(err) {
		klog.Errorf("failed to delete service %s, err: %+v", serviceName, err)
	}
}

func (s *Proxy) Update(cluster *v1alpha1.Cluster, connected bool) error {
	err := s.clusterClient.Get(context.TODO(), types.NamespacedName{Name: cluster.Name}, cluster)
	if err != nil {
		klog.Error(err)
		return err
	}

	statusCondition := v1alpha1.ClusterCondition{
		Type:               v1alpha1.ClusterAgentAvailable,
		Status:             corev1.ConditionTrue,
		LastUpdateTime:     metav1.Time{Time: time.Now()},
		LastTransitionTime: metav1.Time{Time: time.Now()},
		Reason:             "",
		Message:            "Agent has connected to proxy successfully.",
	}

	// issue kubeconfig to cluster
	if connected {
		cluster.Spec.Connection.KubeConfig, err = s.certificateIssuer.IssueKubeConfig(cluster.Name, cluster.Spec.Connection.KubernetesAPIEndpoint)
		if err != nil {
			message := fmt.Sprintf("Error issuing kubeconfig to cluster %s, error %s", cluster.Name, err)
			statusCondition.Message = message
			statusCondition.Status = corev1.ConditionFalse
		}
	}

	if !connected {
		statusCondition.Status = corev1.ConditionFalse
		statusCondition.Message = "Agent has not connected to proxy."
	}

	newConditions := make([]v1alpha1.ClusterCondition, 0)
	for _, condition := range cluster.Status.Conditions {
		if condition.Type == v1alpha1.ClusterAgentAvailable {
			continue
		}
		newConditions = append(newConditions, condition)
	}
	newConditions = append(newConditions, statusCondition)
	cluster.Status.Conditions = newConditions

	err = s.clusterClient.Update(context.TODO(), cluster)
	if err != nil {
		klog.Error(err)
		return err
	}

	return nil
}

// allocatePort find a available port between [portRangeMin, portRangeMax] in maximumRetries
// TODO: only works with handful clusters
func (s *Proxy) allocatePort() (uint16, error) {
	mrand.Seed(time.Now().UnixNano())

	clusters := &v1alpha1.ClusterList{}
	err := s.clusterClient.List(context.TODO(), clusters)
	if err != nil {
		return 0, err
	}

	const maximumRetries = 10
	for i := 0; i < maximumRetries; i++ {
		collision := false
		port := uint16(portRangeMin + mrand.Intn(portRangeMax-portRangeMin+1))

		for _, item := range clusters.Items {
			if item.Spec.Connection.Type == v1alpha1.ConnectionTypeProxy &&
				item.Spec.Connection.KubernetesAPIServerPort != 0 &&
				item.Spec.Connection.KubeSphereAPIServerPort == port {
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
func (s *Proxy) generateToken() string {
	mrand.Seed(time.Now().UnixNano())
	b := make([]byte, 32)
	mrand.Read(b)
	return fmt.Sprintf("%x", b)
}

// when external svc becomes active update cluster info
func (s *Proxy) addSVC(cluster *v1alpha1.Cluster) error {
	clone := cluster.DeepCopy()
	serviceName := fmt.Sprintf("%s%s", svcPrefix, cluster.Name)
	svc, err := s.k8sClientSet.CoreV1().Services(defaultAgentNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		klog.Error(err)
		return err
	}

	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		klog.V(2).Infof("service:%s has ready with external ip", svc.Name)
		// get cluster by service name
		var externalAddr string
		if len(svc.Status.LoadBalancer.Ingress[0].IP) > 0 {
			externalAddr = svc.Status.LoadBalancer.Ingress[0].IP
		} else if len(svc.Status.LoadBalancer.Ingress[0].Hostname) > 0 {
			externalAddr = svc.Status.LoadBalancer.Ingress[0].Hostname
		}
		cluster.Spec.Connection.ExternalKubernetesAPIEndpoint = fmt.Sprintf("https://%s:%d", externalAddr, kubernetesPort)
		err = s.clusterClient.Update(context.TODO(), cluster)
		if err != nil {
			klog.Errorf("update cluster:%s error:%v", cluster.Name, err)
			return err
		}

		externalLBCondition := v1alpha1.ClusterCondition{
			Type:               v1alpha1.ClusterExternalAccessReady,
			Status:             corev1.ConditionTrue,
			Reason:             string(v1alpha1.ClusterInitialized),
			Message:            "Cluster external kubeapi has been initialized",
			LastUpdateTime:     metav1.Now(),
			LastTransitionTime: metav1.Now(),
		}
		updateClusterCondition(cluster, externalLBCondition)

		if !reflect.DeepEqual(clone, cluster) {
			err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				c := &v1alpha1.Cluster{}
				err := s.clusterClient.Get(context.TODO(), types.NamespacedName{Name: cluster.Name}, c)
				if err != nil {
					return err
				}

				cluster.ResourceVersion = c.ResourceVersion
				err = s.clusterClient.Update(context.TODO(), cluster)
				return err
			})
			if err != nil {
				klog.Errorf("failed to update cluster %s, err: %+v", cluster.Name, err)
				return err
			}
		}
	}

	return nil
}

func generateKey() ([]byte, error) {
	r := rand.Reader

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, err
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECDSA private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

func loadCertificateOrDie(path string) []byte {
	cert, err := os.ReadFile(path)
	if err != nil {
		klog.Fatalf("error loading certificate %s, %v", path, err)
	}
	return cert
}

// isConditionTrue checks cluster specific condition value is True, return false if condition not exists
func isConditionTrue(cluster *v1alpha1.Cluster, conditionType v1alpha1.ClusterConditionType) bool {
	for _, condition := range cluster.Status.Conditions {
		if condition.Type == conditionType && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// updateClusterCondition updates condition in cluster conditions using giving condition
// adds condition if not existed
func updateClusterCondition(cluster *v1alpha1.Cluster, condition v1alpha1.ClusterCondition) {
	if cluster.Status.Conditions == nil {
		cluster.Status.Conditions = make([]v1alpha1.ClusterCondition, 0)
	}

	newConditions := make([]v1alpha1.ClusterCondition, 0)
	for _, cond := range cluster.Status.Conditions {
		if cond.Type == condition.Type {
			continue
		}
		newConditions = append(newConditions, cond)
	}

	newConditions = append(newConditions, condition)
	cluster.Status.Conditions = newConditions
}
