package agent

import (
	"encoding/json"
	"fmt"
)

type Config struct {
	// Protocol version
	Version string

	// Name of the agent
	Name string

	// Token used to authenticate with proxy server
	Token string

	// Kubernetes apiserver host
	KubernetesSvcHost string

	// KubeSphere apigateway host
	KubeSphereSvcHost string

	// agent certificates
	// CertData holds PEM-encoded bytes (typically read from a client certificate file).
	CertData []byte `json:",omitempty"`
	// KeyData holds PEM-encoded bytes (typically read from a client certificate key file).
	KeyData []byte `json:",omitempty"`
	// CAData holds PEM-encoded bytes (typically read from a root certificates bundle).
	CAData []byte `json:",omitempty"`

	// Server requires Bearer authentication. This client will not attempt to use
	// refresh tokens for an OAuth2 flow.
	BearerToken []byte `json:",omitempty"`
}

func (c *Config) Unmarshal(b []byte) error {
	err := json.Unmarshal(b, c)
	if err != nil {
		return fmt.Errorf("invalid json config")
	}
	return nil
}

func (c *Config) Marshal() ([]byte, error) {
	return json.Marshal(c)
}
