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
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
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

type PKI struct {
	CAFile          string
	ServingCertFile string
	FullchainFile   string
	PrivateKeyFile  string
}

func EnsurePKI(log logrus.FieldLogger, o Options) (*PKI, error) {
	caKeyFile := filepath.Join(o.Directory, "ca.key")
	caKey, err := ensurePrivateKey(log, caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure CA private key: %w", err)
	}

	caCertFile := filepath.Join(o.Directory, "ca.crt")
	caCert, err := ensureCACertificate(log, caCertFile, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure CA certificate: %w", err)
	}

	servingKeyFile := filepath.Join(o.Directory, "serving.key")
	servingKey, err := ensurePrivateKey(log, servingKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure serving certificate private key: %w", err)
	}

	servingCertFile := filepath.Join(o.Directory, "serving.crt")
	servingCert, err := ensureServingCertificate(log, servingCertFile, servingKey, o.Hostnames, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure serving certificate: %w", err)
	}

	fullchainCertFile := filepath.Join(o.Directory, "fullchain.crt")
	if err := ensureFullChain(fullchainCertFile, servingCert, caCert); err != nil {
		return nil, fmt.Errorf("failed to ensure full chain certificate: %w", err)
	}

	return &PKI{
		CAFile:          caCertFile,
		ServingCertFile: servingCertFile,
		FullchainFile:   fullchainCertFile,
		PrivateKeyFile:  servingKeyFile,
	}, nil
}

func ensurePrivateKey(log logrus.FieldLogger, filename string) (any, error) {
	if key, err := readValidPrivateKey(filename); err == nil {
		return key, nil
	}

	log.WithField("file", filename).Info("Creating private key…")

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

func ensureCACertificate(log logrus.FieldLogger, filename string, key any) (*x509.Certificate, error) {
	tmpl := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "httest CA",
		},
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:     true,
	}

	if cert, err := validateCertificateFile(filename, key, tmpl); err == nil {
		return cert, nil
	}

	log.WithField("file", filename).Info("Creating CA certificate…")

	return makeCertificate(filename, tmpl, key, caValidity, nil, key)
}

func ensureServingCertificate(log logrus.FieldLogger, filename string, certPrivKey any, hostnames []string, caCert *x509.Certificate, caPrivKey any) (*x509.Certificate, error) {
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

	cert, err := validateCertificateFile(filename, certPrivKey, tmpl)
	if err == nil {
		return cert, nil
	}

	term := "Creating"
	if !errors.Is(err, os.ErrNotExist) {
		log = log.WithField("reason", err)
		term = "Recreating"
	}

	log.WithField("file", filename).WithField("cn", hostnames[0]).Infof("%s serving certificate…", term)

	return makeCertificate(filename, tmpl, certPrivKey, servingCertValidity, caCert, caPrivKey)
}

func validateCertificateFile(filename string, privKey any, template x509.Certificate) (*x509.Certificate, error) {
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

	if err := validateCertificate(cert, privKey, template); err != nil {
		return nil, err
	}

	return cert, nil
}

func validateCertificate(cert *x509.Certificate, privKey any, template x509.Certificate) error {
	if remaining := time.Until(cert.NotAfter); remaining < minCertValidity {
		return fmt.Errorf("certificate expires soon (in %v)", remaining)
	}

	if cert.Subject.CommonName != template.Subject.CommonName {
		return fmt.Errorf("common name %q does not match desired value %q", cert.Subject.CommonName, template.Subject.CommonName)
	}

	if cert.IsCA != template.IsCA {
		return fmt.Errorf("isCA flag does not match desired value %v", template.IsCA)
	}

	if cert.KeyUsage != template.KeyUsage {
		return fmt.Errorf("key usage %s does not match desired value %s", formatKeyUsage(cert.KeyUsage), formatKeyUsage(template.KeyUsage))
	}

	var missing []string
	for _, dnsName := range template.DNSNames {
		if !slices.Contains(cert.DNSNames, dnsName) {
			missing = append(missing, dnsName)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("DNS names do not contain %v", missing)
	}

	for _, ipAddress := range template.IPAddresses {
		if !slices.ContainsFunc(cert.IPAddresses, ipAddress.Equal) {
			missing = append(missing, ipAddress.String())
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("IP addresses do not contain %v", missing)
	}

	for _, eku := range template.ExtKeyUsage {
		if !slices.Contains(cert.ExtKeyUsage, eku) {
			missing = append(missing, formatExtKeyUsage(eku))
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("extended key usages do not contain %v", missing)
	}

	privKeyEncoded, err := encodePrivateKeyPEM(privKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	if _, err := tls.X509KeyPair(encodeCertPEM(cert), privKeyEncoded); err != nil {
		return fmt.Errorf("failed to load key pair: %w", err)
	}

	return nil
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var names []string
	if ku&x509.KeyUsageDigitalSignature > 0 {
		names = append(names, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment > 0 {
		names = append(names, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment > 0 {
		names = append(names, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment > 0 {
		names = append(names, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement > 0 {
		names = append(names, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign > 0 {
		names = append(names, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign > 0 {
		names = append(names, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly > 0 {
		names = append(names, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly > 0 {
		names = append(names, "DecipherOnly")
	}
	slices.Sort(names)

	if len(names) == 0 {
		return "<none>"
	}

	return strings.Join(names, "|")
}

func formatExtKeyUsage(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeServerGatedCrypto"
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "MicrosoftCommercialCodeSigning"
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return "MicrosoftKernelCodeSigning"
	default:
		return fmt.Sprintf("%d", eku)
	}
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
		if _, err := f.Write(encodeCertPEM(cert)); err != nil {
			return err
		}
	}

	return nil
}
