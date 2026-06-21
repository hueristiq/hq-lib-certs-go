package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func main() {
	tempDir, err := os.MkdirTemp("", "hq-lib-tls-go-ca-certs-*")
	if err != nil {
		log.Fatal("Failed to create temp directory:", err)
	}

	defer os.RemoveAll(tempDir)

	// Generate CA certificate & private key
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKeyBytes(
		hqgotls.CACertificatePrivateKeyWithCommonName("My Company CA"),
		hqgotls.CACertificatePrivateKeyWithOrganization([]string{"My Company"}),
		hqgotls.CACertificatePrivateKeyWithValidFor(2*365*24*time.Hour),
	)
	if err != nil {
		log.Fatal("Failed to generate CA certificate and private key:", err)
	}

	// Create CA
	ca, err := hqgotls.NewWithBytesCertificatePrivateKey(caCert, caKey)
	if err != nil {
		log.Fatal("Failed to create CA:", err)
	}

	// Generate a TLS Certificate
	tlsCert, tlsKey, err := ca.GenerateTLSCertificate(
		[]string{"example.com", "192.168.1.1", "user@example.com"},
		hqgotls.TLSCertificatePrivateKeyWithCommonName("example.com"),
		hqgotls.TLSCertificatePrivateKeyWithValidFor(30*24*time.Hour),
	)
	if err != nil {
		log.Fatal("Failed to create TLS Certificate:", err)
	}

	// Save to files
	TLSCertPath := filepath.Join(tempDir, "tls-cert.pem")
	TLSKeyPath := filepath.Join(tempDir, "tls-key.pem")

	if err = hqgotls.SaveCertificatePrivateKeyToFiles(tlsCert, TLSCertPath, tlsKey, TLSKeyPath); err != nil {
		log.Fatal("Failed to save TLS Certificate:", err)
	}
}
