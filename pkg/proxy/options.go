package proxy

type Options struct {
	// Certificates to setup a proxy server.
	CaCert string
	CaKey  string
	// Port listening for agent connections.
	Host string
	Port int
	// Path to kubeconfig
	KubeConfigPath string

	// TODO: fill automatically
	PublishServiceAddress string
}
