package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	k8sproxy "k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/klog"

	"kubesphere.io/tower/pkg/utils"
)

type Server struct {
	// Server name used to identify
	name string

	// Local listening port
	port uint16

	// Remote proxy address
	host string

	// Remote proxy scheme, https or http
	scheme string

	//
	server *http.Server

	// http client to do the real proxy
	httpClient []*http.Client

	// RWMutex to implement safe operation while read or update httpClient Slice
	rwLock sync.RWMutex

	// Whether to use bearer token, if false, need to pass TLS client certificates
	useBearerToken bool

	// Bearer token to do oauth
	bearerToken []byte
}

func newProxyServer(name, host, scheme string, port uint16, useBearerToken bool, transport *http.Transport, servertlsConfig *tls.Config, bearerToken []byte) (*Server, error) {
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: servertlsConfig,
	}

	return &Server{
		name:   name,
		host:   host,
		scheme: scheme,
		port:   port,
		server: server,
		httpClient: []*http.Client{
			{Transport: transport},
		},
		useBearerToken: useBearerToken,
		bearerToken:    bearerToken,
	}, nil
}

// buildServerData returns http.Transport and tlsConfig, which are necessary for creating proxy server.
func buildServerData(sshConn utils.GetSSHConn, host string, ca, cert, key, serverCa, serverCert, serverKey []byte) (*http.Transport, bool, *tls.Config, error) {
	useBearerToken := true

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
			c := sshConn()
			if c == nil {
				return nil, fmt.Errorf("no remote connetion available")
			}
			return utils.NewSshConn(sshConn, host), nil
		},
	}

	tlsConfig := &tls.Config{}

	if len(ca) != 0 {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(ca)
		tlsConfig.RootCAs = caCertPool
	}

	if len(cert) != 0 && len(key) != 0 {
		certificate, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, true, nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}

		useBearerToken = false
	}
	tlsConfig.BuildNameToCertificate()
	transport.TLSClientConfig = tlsConfig

	var serverTLSConfig = &tls.Config{}
	if len(serverCa) != 0 {
		serverCaCertPool := x509.NewCertPool()
		serverCaCertPool.AppendCertsFromPEM(serverCa)

		// if server ca is given, client certificate are required
		serverTLSConfig.ClientCAs = serverCaCertPool
		serverTLSConfig.ClientAuth = tls.RequestClientCert
		serverTLSConfig.VerifyPeerCertificate = verifyClientCertificate
	}

	if len(serverKey) != 0 && len(serverCert) != 0 {
		serverCerts, err := tls.X509KeyPair(serverCert, serverKey)
		if err != nil {
			return nil, true, nil, err
		}

		serverTLSConfig.Certificates = []tls.Certificate{serverCerts}
	}

	return transport, useBearerToken, serverTLSConfig, nil
}

// TODO: verify issued client certificate
func verifyClientCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	return nil
}

func (s *Server) Start(ctx context.Context) error {
	klog.V(4).Infof("Proxy server %s: starting http proxy on %s, proxy address %s", s.name, s.server.Addr, s.host)
	s.server.Handler = s

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			err := s.server.Shutdown(ctx)
			if err != nil {
				klog.Errorf("Proxy server %s: %v", s.name, err)
			} else {
				klog.V(2).Infof("Proxy server %s shut down", s.name)
			}
		case <-done:
			klog.V(2).Infof("Proxy server %s shut down", s.name)
		}
	}()

	go func() {
		if s.server.TLSConfig != nil {
			if err := s.server.ListenAndServeTLS("", ""); err != nil {
				klog.Errorf("Proxy server %s: %v", s.name, err)
				close(done)
			}
		} else {
			if err := s.server.ListenAndServe(); err != nil {
				klog.Errorf("Proxy server %s: %v", s.name, err)
				close(done)
			}
		}

	}()

	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	u := *req.URL
	u.Host = s.host
	u.Scheme = s.scheme

	if s.useBearerToken && len(s.bearerToken) > 0 {
		req = utilnet.CloneRequest(req)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.bearerToken))
	}

	// we choose one httpClient randomly
	rand.Seed(time.Now().UnixNano())
	s.rwLock.RLock()
	index := rand.Intn(len(s.httpClient))
	klog.V(5).Infof("server %s current agent connection length %d, random slice index %d", s.name, len(s.httpClient), index)
	httpProxy := k8sproxy.NewUpgradeAwareHandler(&u, s.httpClient[index].Transport, false, false, s)
	s.rwLock.RUnlock()
	httpProxy.ServeHTTP(w, req)
}

func (s *Server) Error(_ http.ResponseWriter, req *http.Request, err error) {
	klog.Errorf("Proxy server %s: proxy %s encountered error %v", s.name, req.URL, err)
}
