# hq-lib-certs-go

![made with go](https://img.shields.io/badge/made%20with-Go-1E90FF.svg) [![go reference](https://pkg.go.dev/badge/github.com/hueristiq/hq-lib-certs-go.svg)](https://pkg.go.dev/github.com/hueristiq/hq-lib-certs-go) [![license](https://img.shields.io/badge/license-MIT-gray.svg?color=1E90FF)](https://github.com/hueristiq/hq-lib-certs-go/blob/master/LICENSE) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-1E90FF.svg) [![open issues](https://img.shields.io/github/issues-raw/hueristiq/hq-lib-certs-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-certs-go/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/hueristiq/hq-lib-certs-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-certs-go/issues?q=is:issue+is:closed) [![contribution](https://img.shields.io/badge/contributions-welcome-1E90FF.svg)](https://github.com/hueristiq/hq-lib-certs-go/blob/master/CONTRIBUTING.md)

`hq-lib-certs-go` is a [Go (Golang)](http://golang.org/) package for generating, managing, and signing X.509 certificates.

## Resource

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
	- [Generating a CA Certificate](#generating-a-ca-certificate)
	- [Choosing the Key Algorithm](#choosing-the-key-algorithm)
	- [Loading a Certificate from Files](#loading-a-certificate-from-files)
	- [Loading a CA from PEM Bytes](#loading-a-ca-from-pem-bytes)
	- [Generating a TLS Certificate](#generating-a-tls-certificate)
	- [Configuring a TLS Server with SNI](#configuring-a-tls-server-with-sni)
- [Contributing](#contributing)
- [Licensing](#licensing)

## Features

- **Self-Signed CA Generation:** Create CA certificates with customizable subject, validity, and key algorithm (RSA-2048, ECDSA P-256, or Ed25519).
- **TLS Certificate Issuance:** Issue signed leaf certificates for DNS names, IP addresses, email addresses, and URIs, with configurable subject, validity, and extended key usage (server or client/mTLS). Leaf keys match the CA's algorithm.
- **Dynamic TLS Configuration:** SNI-based certificate generation for TLS servers, with a minimum TLS version of 1.2 and ALPN protocols advertised for HTTP/2 (`h2`) and HTTP/1.1 (`http/1.1`).
- **Certificate Caching:** In-memory caching of dynamically generated certificates, with cache size and expiry configurable through options on `New`.
- **PEM and File Helpers:** Encode certificates and keys to PEM, save and load them from disk, and construct an authority directly from PEM bytes.
- **Standards Compliance:** Follows RFC 5280 for certificate generation and RFC 7468 for PEM encoding.

## Installation

To install `hq-lib-certs-go`, run the following command in your Go project:

```bash
go get -v -u github.com/hueristiq/hq-lib-certs-go
```

## Usage

### Generating a CA Certificate

Use `GenerateCACertificatePrivateKey` to create a self-signed CA certificate and its private key. By default it generates a 2048-bit RSA key; see [Choosing the Key Algorithm](#choosing-the-key-algorithm) to select ECDSA or Ed25519. Persist the result to PEM files with `SaveCertificatePrivateKeyToFiles`.

```go
package main

import (
	"log"
	"time"

	"github.com/hueristiq/hq-lib-certs-go"
)

func main() {
	// Generate a CA certificate with custom options.
	caCert, caKey, err := certs.GenerateCACertificatePrivateKey(
		certs.CACertificatePrivateKeyWithCommonName("My Root CA"),
		certs.CACertificatePrivateKeyWithOrganization([]string{"My Company"}),
		certs.CACertificatePrivateKeyWithValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Save to PEM files.
	if err = certs.SaveCertificatePrivateKeyToFiles(caCert, "ca-cert.pem", caKey, "ca-key.pem"); err != nil {
		log.Fatalf("Failed to save CA certificate: %v", err)
	}

	log.Println("CA certificate and key saved to ca-cert.pem and ca-key.pem")
}
```

### Choosing the Key Algorithm

Pass `CACertificatePrivateKeyWithKeyType` to control the CA's private key algorithm. Because every leaf certificate inherits the CA's algorithm, an ECDSA or Ed25519 CA also makes per-host issuance faster — useful for the SNI server below, which generates a key per hostname.

```go
caCert, caKey, err := certs.GenerateCACertificatePrivateKey(
	certs.CACertificatePrivateKeyWithCommonName("My Root CA"),
	certs.CACertificatePrivateKeyWithKeyType(certs.KeyTypeECDSAP256),
)
```

Available key types: `KeyTypeRSA2048` (default), `KeyTypeECDSAP256`, and `KeyTypeED25519`.

### Loading a Certificate from Files

Load a certificate and private key from PEM files with `LoadCertificatePrivateKeyFromFiles`.

```go
package main

import (
	"log"

	"github.com/hueristiq/hq-lib-certs-go"
)

func main() {
	caCert, caKey, err := certs.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	log.Println("Successfully loaded CA certificate and key")
}
```

### Loading a CA from PEM Bytes

When the certificate and key are already in memory (for example, read from a secret store), construct the authority directly with `NewWithBytesCertificatePrivateKey`.

```go
ca, err := certs.NewWithBytesCertificatePrivateKey(caCertPEM, caKeyPEM)
if err != nil {
	log.Fatalf("Failed to initialize CA: %v", err)
}
```

### Generating a TLS Certificate

Use a `CertificateAuthority` to issue a leaf certificate for specific hosts. Each host is routed into the matching Subject Alternative Name field — DNS name, IP address, email address, or URI.

```go
package main

import (
	"log"
	"time"

	"github.com/hueristiq/hq-lib-certs-go"
)

func main() {
	// Load CA certificate and private key.
	caCert, caKey, err := certs.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize the CertificateAuthority.
	ca, err := certs.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Generate a TLS certificate for multiple hosts.
	tlsCert, tlsKey, err := ca.GenerateTLSCertificate(
		[]string{"example.com", "www.example.com", "192.168.1.1", "user@example.com"},
		certs.TLSCertificatePrivateKeyWithCommonName("example.com"),
		certs.TLSCertificatePrivateKeyWithOrganization([]string{"My Company"}),
		certs.TLSCertificatePrivateKeyWithValidFor(30*24*time.Hour), // 30 days
	)
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// Save the TLS certificate and key.
	if err := certs.SaveCertificatePrivateKeyToFiles(tlsCert, "tls-cert.pem", tlsKey, "tls-key.pem"); err != nil {
		log.Fatalf("Failed to save TLS certificate: %v", err)
	}

	log.Println("TLS certificate and key saved to tls-cert.pem and tls-key.pem")
}
```

Certificates default to server authentication. To issue a client certificate for mutual TLS, set the extended key usage:

```go
clientCert, clientKey, err := ca.GenerateTLSCertificate(
	[]string{"client.example.com"},
	certs.TLSCertificatePrivateKeyWithExtKeyUsage(x509.ExtKeyUsageClientAuth),
)
```

### Configuring a TLS Server with SNI

`NewTLSConfig` returns a `*tls.Config` that generates a certificate for whatever hostname the client requests via SNI, caching results to avoid re-issuing on every connection. Tune the cache through options on `New`.

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/hueristiq/hq-lib-certs-go"
)

func main() {
	// Generate or load the CA certificate and key.
	caCert, caKey, err := certs.GenerateCACertificatePrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Initialize the CertificateAuthority, tuning the certificate cache.
	ca, err := certs.New(caCert, caKey,
		certs.CertificateAuthorityWithCacheMaxSize(1024),
		certs.CertificateAuthorityWithCacheMaxAge(6*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Build a TLS configuration with dynamic, SNI-driven certificates.
	tlsConfig := ca.NewTLSConfig()

	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, TLS with SNI!"))
		}),
	}

	log.Println("Starting TLS server on :443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

Because the certificates are signed by a self-signed CA, clients must trust `caCert` (for example, by adding it to their root pool) for the handshake to succeed. If a client connects without SNI, use `NewTLSConfigWithHost` to supply a default hostname.

## Contributing

Contributions are welcome and encouraged! Feel free to submit [Pull Requests](https://github.com/hueristiq/hq-lib-certs-go/pulls) or report [Issues](https://github.com/hueristiq/hq-lib-certs-go/issues). For more details, check out the [contribution guidelines](https://github.com/hueristiq/hq-lib-certs-go/blob/master/CONTRIBUTING.md).

A big thank you to all the [contributors](https://github.com/hueristiq/hq-lib-certs-go/graphs/contributors) for your ongoing support!

![contributors](https://contrib.rocks/image?repo=hueristiq/hq-lib-certs-go&max=500)

## Licensing

This package is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/hueristiq/hq-lib-certs-go/blob/master/LICENSE).
