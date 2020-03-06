package proxy

type Options struct {
	// Certificates to setup a proxy server.
	CaCert     string
	CaKey      string
	ServerCert string
	ServerKey  string
	// Port listening for agent connections.
	Host string
	Port uint16
	// Path to kubeconfig
	KubeconfigPath string

	// TODO: fill automatically
	ProxyServiceHost string
}
