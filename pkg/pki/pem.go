// SPDX-FileCopyrightText: 2024 Christoph Mewes, 2016 The Kubernetes Authors
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	certificateBlockType   = "CERTIFICATE"
	rsaPrivateKeyBlockType = "RSA PRIVATE KEY"
	ecPrivateKeyBlockType  = "EC PRIVATE KEY"
	privateKeyBlockType    = "PRIVATE KEY"
)

func encodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  certificateBlockType,
		Bytes: cert.Raw,
	})
}

func encodePrivateKeyPEM(key any) ([]byte, error) {
	switch asserted := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  rsaPrivateKeyBlockType,
			Bytes: x509.MarshalPKCS1PrivateKey(asserted),
		}), nil
	case *ecdsa.PrivateKey:
		encoded, err := x509.MarshalECPrivateKey(asserted)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{
			Type:  ecPrivateKeyBlockType,
			Bytes: encoded,
		}), nil
	case ed25519.PrivateKey:
		encoded, err := x509.MarshalPKCS8PrivateKey(asserted)
		if err != nil {
			return nil, err
		}

		return pem.EncodeToMemory(&pem.Block{
			Type:  privateKeyBlockType,
			Bytes: encoded,
		}), nil
	default:
		return nil, fmt.Errorf("unknown private key type %T", key)
	}
}

func parsePrivateKeyPEM(keyData []byte) (any, error) {
	var privateKeyPemBlock *pem.Block
	for {
		privateKeyPemBlock, keyData = pem.Decode(keyData)
		if privateKeyPemBlock == nil {
			break
		}

		switch privateKeyPemBlock.Type {
		case ecPrivateKeyBlockType:
			// ECDSA Private Key in ASN.1 format
			if key, err := x509.ParseECPrivateKey(privateKeyPemBlock.Bytes); err == nil {
				return key, nil
			}
		case rsaPrivateKeyBlockType:
			// RSA Private Key in PKCS#1 format
			if key, err := x509.ParsePKCS1PrivateKey(privateKeyPemBlock.Bytes); err == nil {
				return key, nil
			}
		case privateKeyBlockType:
			// RSA or ECDSA Private Key in unencrypted PKCS#8 format
			if key, err := x509.ParsePKCS8PrivateKey(privateKeyPemBlock.Bytes); err == nil {
				return key, nil
			}
		default:
			// tolerate non-key PEM blocks for compatibility with things like "EC PARAMETERS" blocks
			// originally, only the first PEM block was parsed and expected to be a key block
		}
	}

	// we read all the PEM blocks and didn't recognize one
	return nil, fmt.Errorf("data does not contain a valid RSA or ECDSA private key")
}

// parseCertsPEM returns the x509.Certificates contained in the given PEM-encoded byte array
// Returns an error if a certificate could not be parsed, or if the data does not contain any certificates.
func parseCertsPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	ok := false
	certs := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		// Only use PEM "CERTIFICATE" blocks without extra headers
		if block.Type != certificateBlockType || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}

		certs = append(certs, cert)
		ok = true
	}

	if !ok {
		return certs, errors.New("data does not contain any valid RSA or ECDSA certificates")
	}
	return certs, nil
}
