package dsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

type X509KeyStore interface {
	GetKeyPair() (privateKey *rsa.PrivateKey, cert *x509.Certificate, err error)
}

type X509ChainStore interface {
	GetChain() (certs [][]byte, err error)
}

type X509CertificateStore interface {
	Certificates() (roots []*x509.Certificate, err error)
}

type MemoryX509CertificateStore struct {
	Roots []*x509.Certificate
}

func (mX509cs *MemoryX509CertificateStore) Certificates() ([]*x509.Certificate, error) {
	return mX509cs.Roots, nil
}

type MemoryX509KeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	// Parse the PEM-encoded certificate
	certBlock, _ := pem.Decode(ks.cert)
	if certBlock == nil {
		return nil, nil, errors.New("empty cert block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)

	return ks.privateKey, cert, err
}

func RandomKeyStoreForTest() X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return &MemoryX509KeyStore{
		privateKey: key,
		cert:       cert,
	}
}
