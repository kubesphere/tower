package utils

import (
	"crypto/x509"
	"fmt"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"os"
	"testing"
)

const (
	caCertFile = "/Users/zry/go/src/github.com/zryfish/tower/certs/ca.crt"
	caKeyFile  = "/Users/zry/go/src/github.com/zryfish/tower/certs/ca.key"
)

func TestIssuerKubeconfig(t *testing.T) {
	kubeconfigIssuer, err := NewSimpleKubeConfigIssuer(caCertFile, caKeyFile, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	config, err := kubeconfigIssuer.IssueKubeConfig("kubernetes", 6443)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(config))
}

func TestGenerateCACertificateAndWriteToFile(t *testing.T) {
	err := GenerateCACertificateAndWriteToFile(caCertFile, caKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(caCertFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(caKeyFile)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewCertAndKey(t *testing.T) {
	basePath := "/Users/zry/go/src/github.com/zryfish/tower/certs/%s"
	cacert, cakey, err := LoadCaAuthorityCertAndKey(caCertFile, caKeyFile)
	if err != nil {
		t.Fatal(err)
	}

	config := &certutil.Config{
		CommonName:   "Tower",
		Organization: []string{"KubeSphere"},
		AltNames:     certutil.AltNames{},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	cert, key, err := NewCertAndKey(cacert, cakey, config)
	if err != nil {
		t.Fatal(err)
	}

	err = certutil.WriteCert(fmt.Sprintf(basePath, "server.crt"), EncodeCertPEM(cert))
	if err != nil {
		t.Fatal(err)
	}

	keyData, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	err = keyutil.WriteKey(fmt.Sprintf(basePath, "server.key"), keyData)
	if err != nil {
		t.Fatal(err)
	}
}