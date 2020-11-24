package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"

	"kubesphere.io/tower/pkg/agent"
	"kubesphere.io/tower/pkg/apis/cluster/v1alpha1"
	"kubesphere.io/tower/pkg/certs"
	clientset "kubesphere.io/tower/pkg/client/clientset/versioned"
	clusterinformers "kubesphere.io/tower/pkg/client/informers/externalversions/cluster/v1alpha1"
	"kubesphere.io/tower/pkg/utils"
	"kubesphere.io/tower/pkg/version"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

//
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

	clusterClient clientset.Interface
	clusterSynced cache.InformerSynced
}

func NewServer(options *Options, clusterInformer clusterinformers.ClusterInformer, client clientset.Interface) (*Proxy, error) {

	s := &Proxy{
		httpServer:    NewHTTPServer(),
		agents:        utils.NewAgents(),
		sessions:      make(map[string]*HTTPProxy, 0),
		host:          options.Host,
		port:          options.Port,
		clusterClient: client,
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

	clusterInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: s.addCluster,
		UpdateFunc: func(old, new interface{}) {
			s.addCluster(new)
		},
		DeleteFunc: s.delete,
	})
	s.clusterSynced = clusterInformer.Informer().HasSynced

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

	if _, ok := s.sessions[c.Name]; ok {
		r.Reply(false, []byte("A session already allocated for this client."))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	u, err := url.Parse(client.Spec.Connection.KubeSphereAPIEndpoint)
	if err != nil {
		klog.Errorf("Failed to get host %#v", err)
		failed(err)
		return
	}

	cert, key, err := s.certificateIssuer.IssueCertAndKey(u.Hostname(), u.Hostname())
	if err != nil {
		klog.Errorf("Failed to issue certificates, %#v", err)
		return
	}

	proxy, _ := NewHTTPProxy(func() ssh.Conn { return sshConn }, client.Spec.Connection.KubernetesAPIServerPort, client.Spec.Connection.KubeSphereAPIServerPort, c, s.caCert, cert, key)
	if err := proxy.Start(ctx); err != nil {
		failed(err)
		return
	}

	s.sessions[c.Name] = proxy

	r.Reply(true, nil)
	klog.V(0).Infof("Connection established with %s", client.Name)
	retry.OnError(retry.DefaultBackoff, apierrors.IsConflict, func() error {
		return s.Update(client, true)
	})

	go s.handleSSHRequests(reqs)
	go s.handleSSHChannels(chans)
	sshConn.Wait()
	klog.V(0).Infof("Connection closed with %s", client.Name)
	delete(s.sessions, c.Name)
	retry.OnError(retry.DefaultBackoff, apierrors.IsConflict, func() error {
		return s.Update(client, false)
	})
}

func (s *Proxy) Run(stopCh <-chan struct{}) error {

	if !cache.WaitForCacheSync(stopCh, s.clusterSynced) {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	if err := s.Start(s.host, strconv.Itoa(s.port)); err != nil {
		return err
	}

	return s.Wait()
}

func (s *Proxy) Start(host, port string) error {
	klog.V(0).Infof("Listening on %s:%s...", host, port)

	h := http.Handler(http.HandlerFunc(s.handleClientHandler))
	h = wrap(h)

	return s.httpServer.GoListenAndServe(host+":"+port, h)
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

func (s *Proxy) addCluster(obj interface{}) {
	cluster := obj.(*v1alpha1.Cluster)

	if !cluster.Spec.Enable || cluster.Spec.Connection.Type != v1alpha1.ConnectionTypeProxy {
		if _, ok := s.agents.Get(cluster.Name); ok {
			s.delete(obj)
		}
	}

	// skip uninitialized agent
	if cluster.Spec.Connection.KubernetesAPIServerPort == 0 ||
		cluster.Spec.Connection.KubeSphereAPIServerPort == 0 ||
		len(cluster.Spec.Connection.Token) == 0 ||
		len(cluster.Spec.Connection.KubernetesAPIEndpoint) == 0 ||
		len(cluster.Spec.Connection.KubeSphereAPIEndpoint) == 0 {
		return
	}

	s.agents.Add(cluster)
}

func (s *Proxy) delete(obj interface{}) {
	cluster := obj.(*v1alpha1.Cluster)

	_, found := s.agents.Get(cluster.Name)
	if !found {
		return
	}
	s.agents.Del(cluster.Name)
}

//
func (s *Proxy) Update(cluster *v1alpha1.Cluster, connected bool) error {

	cluster, err := s.clusterClient.ClusterV1alpha1().Clusters().Get(cluster.Name, v1.GetOptions{})
	if err != nil {
		klog.Error(err)
		return err
	}

	statusCondition := v1alpha1.ClusterCondition{
		Type:               v1alpha1.ClusterAgentAvailable,
		Status:             corev1.ConditionTrue,
		LastUpdateTime:     v1.Time{Time: time.Now()},
		LastTransitionTime: v1.Time{Time: time.Now()},
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

	cluster, err = s.clusterClient.ClusterV1alpha1().Clusters().Update(cluster)
	if err != nil {
		klog.Error(err)
		return err
	}

	klog.V(4).Infof("successfully updated cluster to %+v:", cluster)
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
	cert, err := ioutil.ReadFile(path)
	if err != nil {
		klog.Fatalf("error loading certificate %s, %v", path, err)
	}
	return cert
}
