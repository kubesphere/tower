package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	k8sproxy "k8s.io/apimachinery/pkg/util/proxy"
	"k8s.io/klog"
	"kubesphere.io/tower/pkg/utils"
	"net"
	"net/http"
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
	httpClient *http.Client

	// Whether to use bearer token, if false, need to pass TLS client certificates
	useBearerToken bool

	// Bearer token to do oauth
	bearerToken []byte
}

func newProxyServer(sshConn utils.GetSSHConn, name, host, scheme string, port uint16, ca, cert, key, bearerToken, serverCa, serverCert, serverKey []byte) (*Server, error) {
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
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}

		useBearerToken = false
	}
	tlsConfig.BuildNameToCertificate()
	transport.TLSClientConfig = tlsConfig

	server := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
	}

	if len(serverCa) != 0 {
		serverCaCertPool := x509.NewCertPool()
		serverCaCertPool.AppendCertsFromPEM(serverCa)

		if server.TLSConfig == nil {
			server.TLSConfig = &tls.Config{}
		}

		// if server ca is given, client certificate are required
		server.TLSConfig.ClientCAs = serverCaCertPool
		server.TLSConfig.ClientAuth = tls.RequestClientCert
		server.TLSConfig.VerifyPeerCertificate = verifyClientCertificate
	}

	if len(serverKey) != 0 && len(serverCert) != 0 {
		serverCerts, err := tls.X509KeyPair(serverCert, serverKey)
		if err != nil {
			return nil, err
		}

		if server.TLSConfig == nil {
			server.TLSConfig = &tls.Config{}
		}

		server.TLSConfig.Certificates = []tls.Certificate{serverCerts}
	}

	return &Server{
		name:           name,
		host:           host,
		scheme:         scheme,
		port:           port,
		server:         server,
		httpClient:     &http.Client{Transport: transport},
		useBearerToken: useBearerToken,
		bearerToken:    bearerToken,
	}, nil
}

// TODO: verify issued client certificate
func verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	//klog.V(0).Info(rawCerts, verifiedChains)
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

	httpProxy := k8sproxy.NewUpgradeAwareHandler(&u, s.httpClient.Transport, false, false, s)
	httpProxy.ServeHTTP(w, req)
}

func (s *Server) Error(_ http.ResponseWriter, req *http.Request, err error) {
	klog.Errorf("Proxy server %s: proxy %s encountered error %v", s.name, req.URL, err)
}
