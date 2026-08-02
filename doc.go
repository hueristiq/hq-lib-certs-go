// Package tls generates, manages, and signs X.509 certificates for building TLS
// servers with dynamic, per-host certificate issuance.
//
// The package offers two complementary capabilities:
//
//   - One-off generation. [GenerateCACertificatePrivateKey] produces a
//     self-signed Certificate Authority (CA) —
//     [GenerateCACertificatePrivateKeyPEM] returns the same pair PEM-encoded —
//     and [CertificateAuthority.GenerateTLSCertificate] issues a leaf
//     certificate signed by that CA. PEM helpers ([CertificateToPEM],
//     [PrivateKeyToPEM]) and file helpers ([SaveCertificatePrivateKeyToFiles],
//     [LoadCertificatePrivateKeyFromFiles]) move certificates to and from disk.
//   - A long-lived signing authority. [CertificateAuthority] issues leaf
//     certificates on demand, optionally caching them via [WithCache] for at
//     most [WithCacheMaxAge]. Construct one with [New], or with [NewFromPEM]
//     when the CA pair is stored as PEM. Its
//     [CertificateAuthority.NewTLSConfig]
//     returns a [crypto/tls.Config] whose GetCertificate hook mints a
//     certificate for the hostname a client requests via Server Name Indication
//     (SNI), and [CertificateAuthority.TLSCertificate] returns the same bundled
//     *tls.Certificate (leaf plus CA chain) for a host programmatically.
//     [CertificateAuthority.SignCSR] signs certificate signing requests, for
//     example to issue client certificates for mutual TLS (client
//     authentication is the default extended key usage). This suits
//     TLS-intercepting proxies and multi-tenant servers that cannot enumerate
//     their hostnames in advance.
//
// # Production use
//
// The certificate cache is off by default: an authority created without
// [WithCache] regenerates a certificate on every request. Enable caching with
// [WithCache], passing a cache sized to the number of distinct hosts served
// (NewInMemory in the cache subpackage is the ready-made implementation), and
// set [WithCacheMaxAge] well below the leaf validity. For dynamic per-host
// issuance, consider [WithCAKeyType] with [KeyTypeECDSAP256]: ECDSA-P256 leaf
// generation is markedly faster than RSA-2048.
//
// # Key algorithms
//
// RSA-2048, ECDSA (NIST P-256), and Ed25519 are supported through the
// [crypto.Signer] interface. Select the CA's algorithm with
// [WithCAKeyType]. Every leaf certificate inherits the
// CA's algorithm, so an ECDSA or Ed25519 CA yields markedly faster per-host
// issuance than RSA.
//
// # Basic usage
//
// Generate a CA, wrap it in an authority, and serve TLS with SNI-driven
// certificates:
//
//	caCert, caKey, err := hqgotls.GenerateCACertificatePrivateKey(
//		hqgotls.WithCACommonName("Example Root CA"),
//		hqgotls.WithCAKeyType(hqgotls.KeyTypeECDSAP256),
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	authority, err := hqgotls.New(caCert, caKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	server := &http.Server{
//		Addr:      ":443",
//		TLSConfig: authority.NewTLSConfig(),
//	}
//
//	log.Fatal(server.ListenAndServeTLS("", ""))
//
// Clients must trust the generated CA certificate (for example by adding it to
// their root pool) for the handshake to succeed.
//
// # Standards and safety
//
// Certificates follow RFC 5280 — random 128-bit serial numbers and SHA-256
// subject key identifiers — and are PEM-encoded per RFC 7468. Leaf certificates
// are clamped to the CA's expiry so they never outlive their issuer. TLS configs
// produced by the authority require TLS 1.2 or higher and, by default, advertise
// the HTTP/2 and HTTP/1.1 ALPN protocols (overridable with
// [WithNextProtos]). A [CertificateAuthority] is safe for concurrent
// use by multiple goroutines.
package tls
