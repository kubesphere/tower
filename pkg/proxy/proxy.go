package proxy

import (
	"context"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/zryfish/tower/pkg/agent"
	"github.com/zryfish/tower/pkg/apis/tower/v1alpha1"
	clientset "github.com/zryfish/tower/pkg/client/clientset/versioned"
	"github.com/zryfish/tower/pkg/utils"
	"github.com/zryfish/tower/pkg/version"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
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

type Proxy struct {
	httpServer  *HTTPServer
	sessCount   int32
	sessions    *utils.Agents
	sshConfig   *ssh.ServerConfig
	fingerprint string
	options     *Options
	clientSet   clientset.Interface
}

func NewServer(options *Options, client clientset.Interface) (*Proxy, error) {
	s := &Proxy{
		httpServer: NewHTTPServer(),
		sessCount:  0,
		sessions:   utils.NewAgents(),
		options:    options,
		clientSet:  client,
	}

	key, _ := utils.GenerateKey("kubesphere")
	private, err := ssh.ParsePrivateKey(key)
	if err != nil {
		klog.Fatal("failed to parse key", private)
	}

	s.fingerprint = utils.FingerprintKey(private.PublicKey())

	s.sshConfig = &ssh.ServerConfig{
		ServerVersion:    "SSH-" + version.ProtocolVersion + "-server",
		PasswordCallback: s.authenticate,
	}

	s.sshConfig.AddHostKey(private)

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
		klog.V(4).Infof("ignoring client connection using protocol '%s', expected '%s'", protocol, version.ProtocolVersion)
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
	klog.V(4).Info("new agent connection")
	wsConn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		klog.Error("failed to upgrade connection", err)
		return
	}
	connection := utils.NewWebSocketConn(wsConn)

	klog.V(4).Info("handshaking...")

	sshConn, chans, reqs, err := ssh.NewServerConn(connection, s.sshConfig)
	if err != nil {
		klog.Error("failed to handshake", err)
		return
	}

	klog.V(4).Info("verifying configuration")
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
		klog.Error("unable to unmarshal config from agent", r.Payload)
		return
	}

	client, ok := s.sessions.Get(c.Name)
	if !ok || (c.Token != client.Spec.Token) {
		r.Reply(false, []byte("Unauthorized agent"))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy, _ := NewHTTPProxy(func() ssh.Conn { return sshConn }, client.Spec.KubernetesAPIServerPort, client.Spec.KubeSphereAPIGatewayPort, c, s.options.CaCert, s.options.ServerCert, s.options.ServerKey)
	if err := proxy.Start(ctx); err != nil {
		failed(err)
		return
	}

	r.Reply(true, nil)
	klog.V(4).Info("connection established")
	s.Update(client, true)

	go s.handleSSHRequests(reqs)
	go s.handleSSHChannels(chans)
	sshConn.Wait()
	klog.V(4).Info("connection closed")
	s.Update(client, false)
}

func (s *Proxy) Run(stopCh <-chan struct{}) error {
	if err := s.Start(s.options.Host, strconv.Itoa(int(s.options.Port))); err != nil {
		return err
	}

	return s.Wait()
}

func (s *Proxy) Start(host, port string) error {
	klog.V(0).Infof("Fingerprint %s", s.fingerprint)
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
	klog.V(4).Infof("%s with session %s from %s", c.User(), string(c.SessionID()), c.RemoteAddr())
	return nil, nil
}

func (s *Proxy) Add(agent *v1alpha1.Agent) error {
	s.sessions.Add(agent)
	return nil
}

func (s *Proxy) Delete(name string) error {
	_, found := s.sessions.Get(name)
	if !found {
		return fmt.Errorf("agent %s not found", name)
	}
	s.sessions.Del(name)

	return nil
}

func (s *Proxy) Update(agent *v1alpha1.Agent, connected bool) error {
	agent, err := s.clientSet.TowerV1alpha1().Agents(agent.Namespace).Get(agent.Name, v1.GetOptions{})
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
	for _, condition := range agent.Status.Conditions {
		if condition.Type == v1alpha1.AgentConnected {
			continue
		}
		newConditions = append(newConditions, condition)
	}
	newConditions = append(newConditions, statusCondition)

	agent, err = s.clientSet.TowerV1alpha1().Agents(agent.Namespace).UpdateStatus(agent)
	if err != nil {
		klog.Error(err)
		return err
	}

	return nil
}
