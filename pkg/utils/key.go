package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"strings"
)

const DetermRandIter = 2048

func NewDetermRand(seed []byte) io.Reader {
	var out []byte
	//strengthen seed
	var next = seed
	for i := 0; i < DetermRandIter; i++ {
		next, out = hash(next)
	}
	return &DetermRand{
		next: next,
		out:  out,
	}
}

type DetermRand struct {
	next, out []byte
}

func (d *DetermRand) Read(b []byte) (int, error) {
	n := 0
	l := len(b)
	for n < l {
		next, out := hash(d.next)
		n += copy(b[n:], out)
		d.next = next
	}
	return n, nil
}

func hash(input []byte) (next []byte, output []byte) {
	nextout := sha512.Sum512(input)
	return nextout[:sha512.Size/2], nextout[sha512.Size/2:]
}

func GenerateKey(seed string) ([]byte, error) {
	var r io.Reader
	if seed == "" {
		r = rand.Reader
	} else {
		r = NewDetermRand([]byte(seed))
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, err
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECDSA private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

func FingerprintKey(k ssh.PublicKey) string {
	bytes := md5.Sum(k.Marshal())
	strbytes := make([]string, len(bytes))
	for i, b := range bytes {
		strbytes[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(strbytes, ":")
}
