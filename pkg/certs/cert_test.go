package certs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const (
	certsDir = "../../certs"
	ca       = "ca"
	server   = "server"
)

func pathForCert(certPath, name string) string {
	return filepath.Join(certPath, fmt.Sprintf("%s.crt", name))
}

func pathForKey(certPath, name string) string {
	return filepath.Join(certPath, fmt.Sprintf("%s.key", name))
}

func TestIssuerKubeConfig(t *testing.T) {
	kubeConfigIssuer, err := NewSimpleCertificateIssuer(pathForCert(certsDir, ca), pathForKey(certsDir, ca), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = kubeConfigIssuer.IssueKubeConfig("kubernetes", 6443)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateCACertificateAndWriteToFile(t *testing.T) {
	err := GenerateCACertificateAndWriteToFile(pathForCert(certsDir, ca), pathForKey(certsDir, ca))
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(pathForCert(certsDir, ca))
	if err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(pathForKey(certsDir, ca))
	if err != nil {
		t.Fatal(err)
	}
}

func TestIssueCertAndKey(t *testing.T) {
	_, _, err := LoadCaAuthorityCertAndKey(pathForCert(certsDir, ca), pathForKey(certsDir, ca))
	if err != nil {
		t.Fatal(err)
	}
}
