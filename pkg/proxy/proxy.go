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
	"github.com/gorilla/websocket"
	"io/ioutil"
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
	agentinformers "kubesphere.io/tower/pkg/client/informers/externalversions/cluster/v1alpha1"
	"kubesphere.io/tower/pkg/utils"
	"kubesphere.io/tower/pkg/version"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

//
type Proxy struct {
	httpServer *HTTPServer
	sessions   *utils.Agents
	sshConfig  *ssh.ServerConfig

	certificateIssuer certs.CertificateIssuer

	host string
	port int

	caCert []byte
	caKey  []byte

	agentClient clientset.Interface
	agentSynced cache.InformerSynced
}

func NewServer(options *Options, agentInformer agentinformers.AgentInformer, client clientset.Interface) (*Proxy, error) {

	s := &Proxy{
		httpServer:  NewHTTPServer(),
		sessions:    utils.NewAgents(),
		host:        options.Host,
		port:        options.Port,
		agentClient: client,
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

	agentInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: s.addAgent,
		UpdateFunc: func(old, new interface{}) {
			s.addAgent(new)
		},
		DeleteFunc: s.delete,
	})
	s.agentSynced = agentInformer.Informer().HasSynced

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

	client, ok := s.sessions.Get(c.Name)
	if !ok || (c.Token != client.Spec.Token) {
		r.Reply(false, []byte("Unauthorized agent"))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cert, key, err := s.certificateIssuer.IssueCertAndKey(client.Spec.Proxy, client.Spec.Proxy)
	if err != nil {
		klog.Errorf("Failed to issue certificates, %#v", err)
		return
	}

	proxy, _ := NewHTTPProxy(func() ssh.Conn { return sshConn }, client.Spec.KubernetesAPIServerPort, client.Spec.KubeSphereAPIServerPort, c, s.caCert, cert, key)
	if err := proxy.Start(ctx); err != nil {
		failed(err)
		return
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
	retry.OnError(retry.DefaultBackoff, apierrors.IsConflict, func() error {
		return s.Update(client, false)
	})

}

func (s *Proxy) Run(stopCh <-chan struct{}) error {

	if !cache.WaitForCacheSync(stopCh, s.agentSynced) {
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

func (s *Proxy) addAgent(obj interface{}) {
	agt := obj.(*v1alpha1.Agent)

	if agt.Spec.Paused {
		s.delete(obj)
		return
	}

	// skip uninitialized agent
	if agt.Spec.KubernetesAPIServerPort == 0 ||
		agt.Spec.KubeSphereAPIServerPort == 0 ||
		len(agt.Spec.Token) == 0 ||
		len(agt.Spec.Proxy) == 0 {
		return
	}

	s.sessions.Add(agt)
}

func (s *Proxy) delete(obj interface{}) {
	agt := obj.(*v1alpha1.Agent)

	_, found := s.sessions.Get(agt.Name)
	if !found {
		return
	}
	s.sessions.Del(agt.Name)
}

//
func (s *Proxy) Update(agent *v1alpha1.Agent, connected bool) error {

	agt, err := s.agentClient.ClusterV1alpha1().Agents().Get(agent.Name, v1.GetOptions{})
	if err != nil {
		klog.Error(err)
		return err
	}

	statusCondition := v1alpha1.AgentCondition{
		Type:               v1alpha1.AgentConnected,
		Status:             corev1.ConditionTrue,
		LastUpdateTime:     v1.Time{Time: time.Now()},
		LastTransitionTime: v1.Time{Time: time.Now()},
		Reason:             "",
		Message:            "Agent has connected to proxy successfully.",
	}

	if !connected {
		statusCondition.Status = corev1.ConditionFalse
		statusCondition.Message = "Agent has not connected to proxy."
	}

	newConditions := make([]v1alpha1.AgentCondition, 0)
	for _, condition := range agt.Status.Conditions {
		if condition.Type == v1alpha1.AgentConnected {
			continue
		}
		newConditions = append(newConditions, condition)
	}
	newConditions = append(newConditions, statusCondition)
	agt.Status.Conditions = newConditions

	agt, err = s.agentClient.ClusterV1alpha1().Agents().Update(agt)
	if err != nil {
		klog.Error(err)
		return err
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
	cert, err := ioutil.ReadFile(path)
	if err != nil {
		klog.Fatalf("error loading certificate %s, %v", path, err)
	}
	return cert
}
