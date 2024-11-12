// SPDX-FileCopyrightText: 2024 Christoph Mewes
// SPDX-License-Identifier: MIT

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	rsaKeySize          = 2048
	oneDay              = time.Hour * 24
	caValidity          = 10 * 365 * oneDay
	servingCertValidity = 7 * oneDay
	minCertValidity     = 1 * oneDay
)

type Options struct {
	Directory string
	Hostnames []string
}

func EnsurePKI(o Options) (servingKeyFile string, servingCertFile string, err error) {
	caKeyFile := filepath.Join(o.Directory, "ca.key")
	caKey, err := ensurePrivateKey(caKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to ensure CA private key: %w", err)
	}

	caCertFile := filepath.Join(o.Directory, "ca.crt")
	caCert, err := ensureCACertificate(caCertFile, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to ensure CA certificate: %w", err)
	}

	servingKeyFile = filepath.Join(o.Directory, "serving.key")
	servingKey, err := ensurePrivateKey(servingKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to ensure serving certificate private key: %w", err)
	}

	servingCertFile = filepath.Join(o.Directory, "serving.crt")
	servingCert, err := ensureServingCertificate(servingCertFile, servingKey, o.Hostnames, caCert, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to ensure serving certificate: %w", err)
	}

	fullchainCertFile := filepath.Join(o.Directory, "fullchain.crt")
	if err := ensureFullChain(fullchainCertFile, servingCert, caCert); err != nil {
		return "", "", fmt.Errorf("failed to ensure full chain certificate: %w", err)
	}

	return fullchainCertFile, servingKeyFile, nil
}

func ensurePrivateKey(filename string) (any, error) {
	if key, err := readValidPrivateKey(filename); err == nil {
		return key, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	encoded, err := encodePrivateKeyPEM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	if err := os.WriteFile(filename, encoded, 0600); err != nil {
		return nil, fmt.Errorf("failed to write key to file: %w", err)
	}

	return key, nil
}

func readValidPrivateKey(filename string) (any, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return parsePrivateKeyPEM(content)
}

func ensureCACertificate(filename string, key any) (*x509.Certificate, error) {
	if cert, err := readCertificate(filename, key); err == nil {
		return cert, nil
	}

	tmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "httest CA",
		},
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:     true,
	}

	return makeCertificate(filename, tmpl, key, caValidity, nil, key)
}

func ensureServingCertificate(filename string, certPrivKey any, hostnames []string, caCert *x509.Certificate, caPrivKey any) (*x509.Certificate, error) {
	if cert, err := readCertificate(filename, certPrivKey); err == nil {
		return cert, nil
	}

	if len(hostnames) == 0 {
		return nil, errors.New("no hostnames given")
	}

	var (
		dnsNames    []string
		ipAddresses []net.IP
	)

	for _, hostname := range hostnames {
		ip := net.ParseIP(hostname)
		if ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, hostname)
		}
	}

	tmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	return makeCertificate(filename, tmpl, certPrivKey, servingCertValidity, caCert, caPrivKey)
}

func readCertificate(filename string, privKey any) (*x509.Certificate, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certs, err := parseCertsPEM(content)
	if err != nil {
		return nil, err
	}

	if len(certs) != 1 {
		return nil, fmt.Errorf("expected a single certificate in %s, but found %d", filename, len(certs))
	}

	cert := certs[0]

	if remaining := time.Until(cert.NotAfter); remaining < minCertValidity {
		return nil, fmt.Errorf("certificate expires soon (in %v)", remaining)
	}

	privKeyEncoded, err := encodePrivateKeyPEM(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	if _, err := tls.X509KeyPair(encodeCertPEM(cert), privKeyEncoded); err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	return cert, nil
}

func getPublicKey(privKey any) (crypto.PublicKey, error) {
	switch asserted := privKey.(type) {
	case *rsa.PrivateKey:
		return asserted.Public(), nil
	case *ecdsa.PrivateKey:
		return asserted.Public(), nil
	case ed25519.PrivateKey:
		return asserted.Public(), nil
	default:
		return nil, fmt.Errorf("unknown private key type %T", privKey)
	}
}

func getSerial() (*big.Int, error) {
	// returns a uniform random value in [0, max-1), then add 1 to serial to make it a uniform random value in [1, max).
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	if err != nil {
		return nil, err
	}

	return new(big.Int).Add(serial, big.NewInt(1)), nil
}

func makeCertificate(filename string, certTempl x509.Certificate, certPrivKey any, validity time.Duration, caCert *x509.Certificate, caPrivKey any) (*x509.Certificate, error) {
	serial, err := getSerial()
	if err != nil {
		return nil, err
	}

	pubKey, err := getPublicKey(certPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine public key: %w", err)
	}

	now := time.Now()
	certTempl.SerialNumber = serial
	certTempl.NotBefore = now.UTC()
	certTempl.NotAfter = now.Add(validity).UTC()
	certTempl.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	certTempl.BasicConstraintsValid = true

	parent := caCert
	if parent == nil {
		parent = &certTempl
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &certTempl, parent, pubKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(filename, encodeCertPEM(cert), 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate to file: %w", err)
	}

	return cert, nil
}

func ensureFullChain(dst string, certs ...*x509.Certificate) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, cert := range certs {
		f.Write(encodeCertPEM(cert))
	}

	return nil
}
