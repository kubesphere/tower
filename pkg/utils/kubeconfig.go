package utils

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"time"
)

const (
	SystemPrivilegedGroup = "system:masters"
)

type clientCertAuth struct {
	CAKey         crypto.Signer
	Organizations []string
}

type KubeConfigSpec struct {
	CACert         *x509.Certificate
	APIServer      string
	ClientName     string
	ClientCertAuth *clientCertAuth
}

// CreateBasic creates a basic, general KubeConfig object that then can be extended
func CreateBasic(serverURL, clusterName, userName string, caCert []byte) *clientcmdapi.Config {
	// Use the cluster and the username as the context name
	contextName := fmt.Sprintf("%s@%s", userName, clusterName)

	return &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   serverURL,
				CertificateAuthorityData: caCert,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:  clusterName,
				AuthInfo: userName,
			},
		},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{},
		CurrentContext: contextName,
	}
}

// CreateWithCerts creates a KubeConfig object with access to the API server with client certificates
func CreateWithCerts(serverURL, clusterName, userName string, caCert []byte, clientKey []byte, clientCert []byte) *clientcmdapi.Config {
	config := CreateBasic(serverURL, clusterName, userName, caCert)
	config.AuthInfos[userName] = &clientcmdapi.AuthInfo{
		ClientKeyData:         clientKey,
		ClientCertificateData: clientCert,
	}
	return config
}

func GenerateCACertificateAndWriteToFile(caCert, caKey string) error {
	config := &certutil.Config{
		CommonName: "kubesphere",
	}

	cert, key, err := NewCertificateAuthority(config)
	if err != nil {
		return err
	}

	if err := certutil.WriteCert(caCert, EncodeCertPEM(cert)); err != nil {
		return errors.Wrapf(err, "unable to write certificate to file %s", caCert)
	}

	encoded, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		errors.Wrapf(err, "unable to marshal private key to PEM")
	}

	if err := keyutil.WriteKey(caKey, encoded); err != nil {
		return errors.Wrapf(err, "unable to write private key to file %s", caKey)
	}

	return nil
}

func GenerateKubeconfig(clustername string, server string, caFile, keyFile string) (*clientcmdapi.Config, error) {
	config := &certutil.Config{
		CommonName: "kubesphere",
	}

	cert, key, err := NewCertificateAuthority(config)
	if err != nil {
		return nil, err
	}

	kubeConfigSpec := &KubeConfigSpec{
		CACert:     cert,
		APIServer:  "https://127.0.0.1:6443",
		ClientName: "kubernetes-admin",
		ClientCertAuth: &clientCertAuth{
			CAKey:         key,
			Organizations: []string{SystemPrivilegedGroup},
		},
	}

	return BuildKubeConfigFromSpec(kubeConfigSpec, clustername)
}

func BuildKubeConfigFromSpec(spec *KubeConfigSpec, clustername string) (*clientcmdapi.Config, error) {
	// create a client certs
	clientCertConfig := certutil.Config{
		CommonName:   spec.ClientName,
		Organization: spec.ClientCertAuth.Organizations,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCert, clientKey, err := NewCertAndKey(spec.CACert, spec.ClientCertAuth.CAKey, &clientCertConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "failure while creating %s client certificate", spec.ClientName)
	}

	encodedClientKey, err := keyutil.MarshalPrivateKeyToPEM(clientKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal private key to PEM")
	}
	// create a kubeconfig with the client certs
	return CreateWithCerts(
		spec.APIServer,
		clustername,
		spec.ClientName,
		EncodeCertPEM(spec.CACert),
		encodedClientKey,
		EncodeCertPEM(clientCert),
	), nil
}

type KubeConfigIssuer interface {
	IssueKubeConfig(clustername string, proxyPort uint16) ([]byte, error)
}

type simpleKubeConfigIssuer struct {
	cert        *x509.Certificate
	signer      crypto.Signer
	proxyServer string
}

func LoadCaAuthorityCertAndKey(caCert, caKey string) (*x509.Certificate, crypto.Signer, error) {
	certs, err := certutil.CertsFromFile(caCert)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "couldn't load the certificate file %s", caCert)
	}

	cert := certs[0]
	// Check so that the certificate is valid now
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, nil, errors.New("the certificate is not valid yet")
	}
	if now.After(cert.NotAfter) {
		return nil, nil, errors.New("the certificate has expired")
	}

	privKey, err := keyutil.PrivateKeyFromFile(caKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "couldn't load the private key file %s", caKey)
	}

	key, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.Errorf("the private key file %s is not RSA format", caKey)
	}

	return cert, key, nil
}

func NewSimpleKubeConfigIssuer(caCert, caKey, proxyServer string) (KubeConfigIssuer, error) {

	cert, key, err := LoadCaAuthorityCertAndKey(caCert, caKey)
	if err != nil {
		return nil, err
	}

	return &simpleKubeConfigIssuer{
		cert:        cert,
		signer:      key,
		proxyServer: proxyServer,
	}, nil
}

func (s *simpleKubeConfigIssuer) IssueKubeConfig(clustername string, port uint16) ([]byte, error) {
	kubeConfigSpec := &KubeConfigSpec{
		CACert:     s.cert,
		APIServer:  fmt.Sprintf("https://%s:%d", s.proxyServer, port),
		ClientName: "kubernetes-admin",
		ClientCertAuth: &clientCertAuth{
			CAKey:         s.signer,
			Organizations: []string{SystemPrivilegedGroup},
		},
	}

	config, err := BuildKubeConfigFromSpec(kubeConfigSpec, clustername)
	if err != nil {
		return nil, err
	}

	return clientcmd.Write(*config)
}
