package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	certsDir = "../../certs"
	ca       = "testCa"
	server   = "server"
)

func pathForCert(certPath, name string) string {
	return filepath.Join(certPath, fmt.Sprintf("%s.crt", name))
}

func pathForKey(certPath, name string) string {
	return filepath.Join(certPath, fmt.Sprintf("%s.key", name))
}

func generateCACertificateAndWriteToFile(t *testing.T) {
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

func cleanCACertificate(t *testing.T) {
	err := os.Remove(pathForCert(certsDir, ca))
	if err != nil {
		t.Log("no ca certificate file found")
	}

	err = os.Remove(pathForKey(certsDir, ca))
	if err != nil {
		t.Log("no ca key file found")
	}
}

func TestIssuerKubeConfig(t *testing.T) {
	generateCACertificateAndWriteToFile(t)
	defer cleanCACertificate(t)

	var ips = []string{"127.0.0.1", "192.168.0.1"}
	var dnsNames = []string{"kubesphere.io"}

	certificateIssuer, err := NewSimpleCertificateIssuer(pathForCert(certsDir, ca), pathForKey(certsDir, ca), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	_, err = certificateIssuer.IssueKubeConfig("kubernetes", "0.0.0.0:6443")
	if err != nil {
		t.Fatal(err)
	}

	cert, _, err := certificateIssuer.IssueCertAndKey(ips, dnsNames)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		t.Fatal("Failed to parse key block")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("Unable to parse cert certificate")
	}

	var found = false
	for _, ip := range parsedCert.IPAddresses {
		for _, ipexpected := range ips {
			if ip.Equal(net.ParseIP(ipexpected)) {
				found = true
				break
			}
		}

	}

	if !found {
		t.Fatalf("%s not in certificate ip addresses %v", ips, parsedCert.IPAddresses)
	}

	certDnsNames := sets.NewString(parsedCert.DNSNames...)
	if !certDnsNames.HasAll(dnsNames...) {
		t.Fatalf("dns names %v not all included in certificate dns names %v", dnsNames, certDnsNames.List())
	}
}
