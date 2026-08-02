# hq-lib-tls-go

![made with go](https://img.shields.io/badge/made%20with-Go-1E90FF.svg) [![go reference](https://pkg.go.dev/badge/github.com/hueristiq/hq-lib-tls-go.svg)](https://pkg.go.dev/github.com/hueristiq/hq-lib-tls-go) [![license](https://img.shields.io/badge/license-MIT-gray.svg?color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/blob/main/LICENSE) ![maintenance](https://img.shields.io/badge/maintained%3F-yes-1E90FF.svg) [![open issues](https://img.shields.io/github/issues-raw/hueristiq/hq-lib-tls-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/issues?q=is:issue+is:open) [![closed issues](https://img.shields.io/github/issues-closed-raw/hueristiq/hq-lib-tls-go.svg?style=flat&color=1E90FF)](https://github.com/hueristiq/hq-lib-tls-go/issues?q=is:issue+is:closed) [![contribution](https://img.shields.io/badge/contributions-welcome-1E90FF.svg)](https://github.com/hueristiq/hq-lib-tls-go/blob/main/CONTRIBUTING.md)

`hq-lib-tls-go` is a [Go](https://golang.org/) package for generating, managing, and signing X.509 certificates.

## Resources

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
	- [Generating a CA Certificate](#generating-a-ca-certificate)
	- [Choosing the Key Algorithm](#choosing-the-key-algorithm)
	- [Loading a Certificate from Files](#loading-a-certificate-from-files)
	- [Loading a CA from PEM Bytes](#loading-a-ca-from-pem-bytes)
	- [Generating a TLS Certificate](#generating-a-tls-certificate)
	- [Signing a Certificate Signing Request (CSR)](#signing-a-certificate-signing-request-csr)
	- [Configuring a TLS Server with SNI](#configuring-a-tls-server-with-sni)
	- [Restricting Issuance to Known Hosts](#restricting-issuance-to-known-hosts)
- [Contributing](#contributing)
- [Licensing](#licensing)

## Features

- **Self-Signed CA Generation:** Create CA certificates with custom subject, validity, and key algorithm (RSA-2048, ECDSA P-256, or Ed25519).
- **TLS Certificate Issuance:** Issue leaf certificates for DNS names, IPs, emails, or URIs, with keys inheriting the CA's algorithm.
- **Dynamic TLS Configuration:** SNI-driven per-host certificate generation, TLS 1.2 minimum, HTTP/2 and HTTP/1.1 ALPN.
- **Opt-In Certificate Caching:** Pluggable caching via the `cache` package; without it, certificates are regenerated per request.
- **SNI Allowlist:** Restrict dynamic issuance to known hostnames with `WithAllowedHosts`, bounding CPU use on Internet-facing servers.

## Installation

To install `hq-lib-tls-go`, run the following command in your Go project:

```bash
go get -v -u github.com/hueristiq/hq-lib-tls-go
```

## Usage

The examples below import the package under the `hqgotls` alias (and subpackage under `hqgotlscache`).

```go
import hqgotls "github.com/hueristiq/hq-lib-tls-go"
```

### Generating a CA Certificate

Use `GenerateCACertificatePrivateKey` to create a self-signed CA certificate and its private key. By default it generates a 2048-bit RSA key; see [Choosing the Key Algorithm](#choosing-the-key-algorithm) to select ECDSA or Ed25519. Persist the result to PEM files with `SaveCertificatePrivateKeyToFiles`.

```go
package main

import (
	"log"
	"time"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func main() {
	// Generate a CA certificate with custom options.
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(
		hqgotls.WithCACommonName("My Root CA"),
		hqgotls.WithCAOrganization([]string{"My Company"}),
		hqgotls.WithCAValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Save to PEM files.
	if err = hqgotls.SaveCertificatePrivateKeyToFiles(caCert, caKey, "ca-cert.pem", "ca-key.pem"); err != nil {
		log.Fatalf("Failed to save CA certificate: %v", err)
	}

	log.Println("CA certificate and key saved to ca-cert.pem and ca-key.pem")
}
```

### Choosing the Key Algorithm

Pass `WithCAKeyType` to control the CA's private key algorithm. Because every leaf certificate inherits the CA's algorithm, an ECDSA or Ed25519 CA also makes per-host issuance faster — useful for the SNI server below, which generates a key per hostname.

```go
caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(
	hqgotls.WithCACommonName("My Root CA"),
	hqgotls.WithCAKeyType(hqgotls.KeyTypeECDSAP256),
)
```

Available key types: `KeyTypeRSA2048` (default), `KeyTypeECDSAP256`, and `KeyTypeEd25519`.

### Loading a Certificate from Files

Load a certificate and private key from PEM files with `LoadCertificatePrivateKeyFromFiles`.

```go
package main

import (
	"log"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func main() {
	caCert, caKey, err := hqgotls.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	log.Printf("Loaded CA certificate %q with key type %T\n", caCert.Subject.CommonName, caKey)
}
```

### Loading a CA from PEM Bytes

When the certificate and key are already in memory (for example, read from a secret store), construct the authority directly with `NewFromPEM`.

```go
ca, err := hqgotls.NewFromPEM(caCertPEM, caKeyPEM)
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

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func main() {
	// Load CA certificate and private key.
	caCert, caKey, err := hqgotls.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize the CertificateAuthority.
	ca, err := hqgotls.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Generate a TLS certificate for multiple hosts.
	tlsCert, tlsKey, err := ca.GenerateTLSCertificate(
		[]string{"example.com", "www.example.com", "192.168.1.1", "user@example.com"},
		hqgotls.WithTLSCommonName("example.com"),
		hqgotls.WithTLSOrganization([]string{"My Company"}),
		hqgotls.WithTLSValidFor(30*24*time.Hour), // 30 days
	)
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	// Save the TLS certificate and key.
	if err := hqgotls.SaveCertificatePrivateKeyToFiles(tlsCert, tlsKey, "tls-cert.pem", "tls-key.pem"); err != nil {
		log.Fatalf("Failed to save TLS certificate: %v", err)
	}

	log.Println("TLS certificate and key saved to tls-cert.pem and tls-key.pem")
}
```

By default the extended key usage is derived from the SAN kinds present: server authentication when the certificate names a host (DNS name, IP address, or URI) and email protection when it names an email address. To issue a client certificate for mutual TLS, set the extended key usage explicitly:

```go
clientCert, clientKey, err := ca.GenerateTLSCertificate(
	[]string{"client.example.com"},
	hqgotls.WithTLSExtKeyUsage(x509.ExtKeyUsageClientAuth),
)
```

### Signing a Certificate Signing Request (CSR)

`SignCSR` signs a CSR with the CA's private key: the client keeps its private key, and the CA never sees it. The CSR's signature is verified before signing, its subject alternative names are copied to the certificate, and the default extended key usage is client authentication — suited to issuing client certificates for mutual TLS. The same `TLSOption`s as `GenerateTLSCertificate` override the defaults.

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
)

func main() {
	// Load CA certificate and private key.
	caCert, caKey, err := hqgotls.LoadCertificatePrivateKeyFromFiles("ca-cert.pem", "ca-key.pem")
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize the CertificateAuthority.
	ca, err := hqgotls.New(caCert, caKey)
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Client side: build a CSR (in practice it arrives from the client).
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate client key: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "client.example.com"},
		DNSNames: []string{"client.example.com"},
	}, clientKey)
	if err != nil {
		log.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		log.Fatalf("Failed to parse CSR: %v", err)
	}

	// CA side: sign the CSR.
	clientCert, err := ca.SignCSR(csr)
	if err != nil {
		log.Fatalf("Failed to sign CSR: %v", err)
	}

	log.Printf("Issued client certificate %q, valid until %v\n", clientCert.Subject.CommonName, clientCert.NotAfter)
}
```

### Configuring a TLS Server with SNI

`NewTLSConfig` returns a `*tls.Config` that generates a certificate for whatever hostname the client requests via SNI. Caching is opt-in: pass a cache from the `cache` package to `New` via `WithCache` to reuse certificates across connections, and tune entry expiry with `WithCacheMaxAge`. Without a cache, a certificate is regenerated for every request.

**Production use:** the cache is off by default — enable it with `WithCache(hqgotlscache.NewInMemory(maxSize))`, sized to the number of distinct hosts served, and set `WithCacheMaxAge` well below the leaf validity (24 hours for SNI-driven issuance). For dynamic per-host issuance, consider `WithCAKeyType(KeyTypeECDSAP256)`: ECDSA-P256 leaf generation is markedly faster than RSA-2048.

Note that the `GetCertificate` hook mints a new key pair for every distinct requested hostname, so an Internet-facing server should restrict issuance — see [Restricting Issuance to Known Hosts](#restricting-issuance-to-known-hosts) — to avoid CPU exhaustion from unbounded certificate generation.

```go
package main

import (
	"log"
	"net/http"
	"time"

	hqgotls "github.com/hueristiq/hq-lib-tls-go"
	hqgotlscache "github.com/hueristiq/hq-lib-tls-go/cache"
)

func main() {
	// Generate or load the CA certificate and key.
	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(
		hqgotls.WithCACommonName("My Root CA"),
	)
	if err != nil {
		log.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Initialize the certificate cache and the CertificateAuthority.
	certificateCache, err := hqgotlscache.NewInMemory(1024)
	if err != nil {
		log.Fatalf("Failed to initialize certificate cache: %v", err)
	}

	ca, err := hqgotls.New(caCert, caKey,
		hqgotls.WithCache(certificateCache),
		hqgotls.WithCacheMaxAge(6*time.Hour),
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

The returned configuration requires TLS 1.2 or higher and advertises the `h2` and `http/1.1` ALPN protocols by default; pass `WithNextProtos` to change them, or call it with no arguments to disable ALPN for non-HTTP servers. To get the same bundled certificate (leaf plus CA chain, with the `Leaf` field populated) outside of a server, call `ca.TLSCertificate("example.com")`.

### Restricting Issuance to Known Hosts

The `GetCertificate` hook mints a new key pair for every distinct requested hostname. On an Internet-facing server, restrict issuance to the hostnames you actually serve with `WithAllowedHosts`; a handshake for any other name fails before any key generation happens:

```go
tlsConfig := ca.NewTLSConfig(hqgotls.WithAllowedHosts("example.com", "app.example.com"))
```

Names are normalized exactly like requested SNI names (port stripped, case folded, trailing dot removed), so "Example.COM." and "example.com" are the same entry. A client that sends no SNI falls through to the wrapped configuration: `NewTLSConfig` errors, `NewTLSConfigWithHost` substitutes its default hostname. Calling `WithAllowedHosts` with no hosts rejects every SNI name.

## Contributing

Contributions are welcome and encouraged! Feel free to submit [Pull Requests](https://github.com/hueristiq/hq-lib-tls-go/pulls) or report [Issues](https://github.com/hueristiq/hq-lib-tls-go/issues). For more details, check out the [contribution guidelines](https://github.com/hueristiq/hq-lib-tls-go/blob/main/CONTRIBUTING.md).

A big thank you to all the [contributors](https://github.com/hueristiq/hq-lib-tls-go/graphs/contributors) for your ongoing support!

![contributors](https://contrib.rocks/image?repo=hueristiq/hq-lib-tls-go&max=500)

## Licensing

This package is licensed under the [MIT license](https://opensource.org/license/mit). You are free to use, modify, and distribute it, as long as you follow the terms of the license. You can find the full license text in the repository - [Full MIT license text](https://github.com/hueristiq/hq-lib-tls-go/blob/main/LICENSE).
