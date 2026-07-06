package tls

import (
	"crypto"
	"crypto/x509"
	"errors"

	circlPki "github.com/cloudflare/circl/pki"
)

func parseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	patchMLDSAPublicKey(cert)
	return cert, nil
}

func patchMLDSAPublicKey(cert *x509.Certificate) {
	if cert == nil || cert.PublicKey != nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return
	}
	pub, err := circlPki.UnmarshalPKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return
	}
	if isMLDSAPublicKey(pub) {
		cert.PublicKey = pub
	}
}

func parseMLDSAPrivateKey(der []byte) (crypto.PrivateKey, error) {
	priv, err := circlPki.UnmarshalPKIXPrivateKey(der)
	if err != nil {
		return nil, err
	}
	if !isMLDSAPrivateKey(priv) {
		return nil, errors.New("tls: parsed CIRCL key is not ML-DSA")
	}
	return priv, nil
}
