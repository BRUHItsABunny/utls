// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"errors"
	"fmt"

	circlSign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func goMLDSASupported() bool {
	return true
}

func defaultMLDSASignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{MLDSA44, MLDSA65, MLDSA87}
}

func mldsaSignatureSchemeForPublicKey(pub crypto.PublicKey) (SignatureScheme, bool) {
	switch pub.(type) {
	case *mldsa44.PublicKey:
		return MLDSA44, true
	case *mldsa65.PublicKey:
		return MLDSA65, true
	case *mldsa87.PublicKey:
		return MLDSA87, true
	}
	if pub, ok := pub.(circlSign.PublicKey); ok {
		switch pub.Scheme().Name() {
		case "ML-DSA-44":
			return MLDSA44, true
		case "ML-DSA-65":
			return MLDSA65, true
		case "ML-DSA-87":
			return MLDSA87, true
		}
	}
	return 0, false
}

func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := mldsaSignatureSchemeForPublicKey(pub)
	return ok
}

func isMLDSAPrivateKey(priv crypto.PrivateKey) bool {
	switch priv.(type) {
	case *mldsa44.PrivateKey, *mldsa65.PrivateKey, *mldsa87.PrivateKey:
		return true
	}
	if priv, ok := priv.(circlSign.PrivateKey); ok {
		_, ok := mldsaSignatureSchemeForPublicKey(priv.Public())
		return ok
	}
	return false
}

func publicKeyMatchesMLDSAPrivateKey(pub crypto.PublicKey, priv crypto.PrivateKey) bool {
	if pub == nil || priv == nil {
		return false
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return false
	}
	pubEq, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return pubEq.Equal(signer.Public())
}

func verifyMLDSAHandshakeSignature(pubkey crypto.PublicKey, signed, sig []byte) error {
	pub, ok := pubkey.(circlSign.PublicKey)
	if !ok {
		return fmt.Errorf("tls: expected ML-DSA public key, got %T", pubkey)
	}
	scheme := pub.Scheme()
	switch scheme.Name() {
	case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
	default:
		return fmt.Errorf("tls: unsupported ML-DSA public key scheme %q", scheme.Name())
	}
	if !scheme.Verify(pub, signed, sig, nil) {
		return errors.New("tls: invalid ML-DSA signature")
	}
	return nil
}

func legacyTypeAndHashFromMLDSAPublicKey(pub crypto.PublicKey) (uint8, crypto.Hash, error) {
	if isMLDSAPublicKey(pub) {
		return 0, 0, errors.New("tls: ML-DSA public keys are not supported before TLS 1.3")
	}
	return 0, 0, nil
}

func signatureSchemesForMLDSAPublicKey(version uint16, pub crypto.PublicKey) []SignatureScheme {
	if version != VersionTLS13 {
		return nil
	}
	if sigAlg, ok := mldsaSignatureSchemeForPublicKey(pub); ok {
		return []SignatureScheme{sigAlg}
	}
	return nil
}

func unsupportedMLDSACertificateError(pub crypto.PublicKey) error {
	if isMLDSAPublicKey(pub) {
		return errors.New("tls: ML-DSA certificates require TLS 1.3")
	}
	return nil
}

func defaultChromeAutoID() ClientHelloID {
	return ClientHelloID{helloChrome, "150", nil, nil}
}
