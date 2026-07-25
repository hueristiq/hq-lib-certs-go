package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSuccess(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	ca, err := New(cert, key)
	require.NoError(t, err)

	assert.Same(t, cert, ca.CACertificate())
	assert.Equal(t, key, ca.CACertificatePrivateKey())
}

func TestNewCacheOptions(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	ca, err := New(cert, key,
		CertificateAuthorityWithCacheMaxAge(2*time.Hour),
		CertificateAuthorityWithCacheMaxSize(99),
	)
	require.NoError(t, err)

	assert.Equal(t, 2*time.Hour, ca.cacheMaxAge)
	assert.Equal(t, 99, ca.cacheMaxSize)
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = New(nil, rsaKey)
	require.ErrorContains(t, err, "CA certificate is nil")

	_, err = New(&x509.Certificate{IsCA: false}, rsaKey)
	require.ErrorContains(t, err, "not configured as a CA")

	noSign := &x509.Certificate{IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature, PublicKey: &rsaKey.PublicKey}
	_, err = New(noSign, rsaKey)
	require.ErrorContains(t, err, "KeyUsageCertSign")

	validRSA := &x509.Certificate{IsCA: true, KeyUsage: x509.KeyUsageCertSign, PublicKey: &rsaKey.PublicKey}
	_, err = New(validRSA, nil)
	require.ErrorContains(t, err, "CA private key is nil")

	_, err = New(validRSA, ecKey)
	require.ErrorContains(t, err, "private key is")

	unsupported := &x509.Certificate{IsCA: true, KeyUsage: x509.KeyUsageCertSign, PublicKey: fakePublicKey{}}
	_, err = New(unsupported, rsaKey)
	require.ErrorContains(t, err, "unsupported certificate public key type")
}

func TestNewRejectsInvalidCacheOptions(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	_, err = New(cert, key, CertificateAuthorityWithCacheMaxSize(0))
	require.ErrorContains(t, err, "cache max size")

	_, err = New(cert, key, CertificateAuthorityWithCacheMaxAge(-time.Second))
	require.ErrorContains(t, err, "cache max age")
}

func TestNewTLSConfigDefaults(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cfg := ca.NewTLSConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Contains(t, cfg.NextProtos, "h2")
	assert.Contains(t, cfg.NextProtos, "http/1.1")
}

func TestNewTLSConfigGetCertificate(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cfg := ca.NewTLSConfig()

	_, err := cfg.GetCertificate(nil)
	require.ErrorContains(t, err, "ClientHelloInfo is nil")

	_, err = cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	require.ErrorContains(t, err, "missing server name")

	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Contains(t, cert.Leaf.DNSNames, "example.com")
}

func TestNewTLSConfigWithHostFallback(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cfg := ca.NewTLSConfigWithHost("default.example.com")
	require.NotNil(t, cfg)

	// A nil ClientHelloInfo is rejected rather than panicking.
	_, err := cfg.GetCertificate(nil)
	require.ErrorContains(t, err, "ClientHelloInfo is nil")

	// Empty SNI falls back to the configured host.
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	require.NoError(t, err)
	assert.Contains(t, cert.Leaf.DNSNames, "default.example.com")

	// Provided SNI takes precedence.
	cert, err = cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "explicit.example.com"})
	require.NoError(t, err)
	assert.Contains(t, cert.Leaf.DNSNames, "explicit.example.com")
}

func TestTLSConfigNilCA(t *testing.T) {
	t.Parallel()

	var nilCA *CertificateAuthority

	assert.Nil(t, nilCA.NewTLSConfig())
	assert.Nil(t, nilCA.NewTLSConfigWithHost("example.com"))
}

func TestGetTLSCertificateCacheHit(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	first, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)

	second, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)

	assert.Same(t, first, second)
}

// TestGetTLSCertificateRegeneratesAfterExpiry guards the regression where an expired cache
// entry caused getTLSCertificate to return (nil, nil), breaking the TLS handshake.
func TestGetTLSCertificateRegeneratesAfterExpiry(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	first, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, first.Leaf)

	ca.cacheMutex.Lock()
	ca.cache["example.com"].createdAt = time.Now().Add(-2 * ca.cacheMaxAge)
	ca.cacheMutex.Unlock()

	second, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)
	require.NotNil(t, second, "expired cache entry was not regenerated")
	require.NotNil(t, second.Leaf)

	assert.NotEqual(t, first.Leaf.SerialNumber, second.Leaf.SerialNumber)
}

func TestGetTLSCertificateEvictsToMaxSize(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256, CertificateAuthorityWithCacheMaxSize(2))

	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		_, err := ca.getTLSCertificate(host)
		require.NoError(t, err)
	}

	ca.cacheMutex.RLock()
	size := len(ca.cache)
	ca.cacheMutex.RUnlock()

	assert.LessOrEqual(t, size, 2)
}

func TestGetTLSCertificateNormalizesHostPort(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	withoutPort, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)

	withPort, err := ca.getTLSCertificate("example.com:8443")
	require.NoError(t, err)

	// Both forms normalize to the same cache key, so the cached certificate is reused.
	assert.Same(t, withoutPort, withPort)
}

// TestTLSServerHandshake exercises the full SNI-driven path end to end: a real TLS server
// using the dynamic config, and a client that trusts only the CA.
func TestTLSServerHandshake(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = ca.NewTLSConfig()
	server.StartTLS()

	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.CACertificate())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "example.com",
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSignCSRSuccess(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test-station",
		},
		DNSNames: []string{"test.example.com"},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr,
		TLSCertificatePrivateKeyWithValidFor(1*time.Hour),
		TLSCertificatePrivateKeyWithExtKeyUsage(x509.ExtKeyUsageClientAuth),
	)
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, "test-station", cert.Subject.CommonName)
	assert.Contains(t, cert.DNSNames, "test.example.com")
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Equal(t, ca.CACertificate().Subject, cert.Issuer)

	err = cert.CheckSignatureFrom(ca.CACertificate())
	require.NoError(t, err)
}

func TestSignCSRUsesClientAuthDefault(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "default-eku"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr, TLSCertificatePrivateKeyWithValidFor(1*time.Hour))
	require.NoError(t, err)

	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestSignCSRInvalidSignature(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "tampered"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err)

	// Tamper with the public key so the signature no longer matches.
	csr.PublicKey = &otherKey.PublicKey

	_, err = ca.SignCSR(csr)
	require.ErrorContains(t, err, "verifying CSR signature")
}

// TestNewRejectsMismatchedPrivateKey guards the regression where New only checked that the
// private key's *type* matched the certificate's public key, allowing a CA whose key does not
// correspond to its certificate to mint unverifiable certificates.
func TestNewRejectsMismatchedPrivateKey(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	otherECKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	edPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, otherEDKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name       string
		publicKey  crypto.PublicKey
		privateKey crypto.Signer
	}{
		{"rsa", &rsaKey.PublicKey, otherRSAKey},
		{"ecdsa", &ecKey.PublicKey, otherECKey},
		{"ed25519", edPublicKey, otherEDKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cert := &x509.Certificate{IsCA: true, KeyUsage: x509.KeyUsageCertSign, PublicKey: tc.publicKey}

			_, err := New(cert, tc.privateKey)
			require.ErrorContains(t, err, "does not match")
		})
	}
}

func TestNewTLSConfigNextProtosOption(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cfg := ca.NewTLSConfig(TLSConfigWithNextProtos("acme/1"))
	assert.Equal(t, []string{"acme/1"}, cfg.NextProtos)

	// Calling the option with no protocols disables ALPN.
	cfg = ca.NewTLSConfig(TLSConfigWithNextProtos())
	assert.Empty(t, cfg.NextProtos)
}

func TestGenerateTLSCertificateClampsValidityToCAExpiry(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cert, _, err := ca.GenerateTLSCertificate(
		[]string{"example.com"},
		TLSCertificatePrivateKeyWithValidFor(100*365*24*time.Hour),
	)
	require.NoError(t, err)

	assert.True(t, cert.NotAfter.Equal(ca.CACertificate().NotAfter))
}

func TestSignCSRClampsValidityToCAExpiry(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "clamped"},
	}, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrBytes)
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr, TLSCertificatePrivateKeyWithValidFor(100*365*24*time.Hour))
	require.NoError(t, err)

	assert.True(t, cert.NotAfter.Equal(ca.CACertificate().NotAfter))
}

func TestGenerateTLSCertificateDefaultCommonNameUsesFirstHost(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cert, _, err := ca.GenerateTLSCertificate([]string{"first.example.com", "second.example.com"})
	require.NoError(t, err)

	assert.Equal(t, "first.example.com", cert.Subject.CommonName)
}

// TestZeroValueCertificateAuthority verifies that the documented-unusable zero value fails
// with a clear error instead of panicking inside x509.CreateCertificate.
func TestZeroValueCertificateAuthority(t *testing.T) {
	t.Parallel()

	ca := &CertificateAuthority{}

	_, _, err := ca.GenerateTLSCertificate([]string{"example.com"})
	require.ErrorContains(t, err, "not initialized")

	_, err = ca.SignCSR(&x509.CertificateRequest{})
	require.ErrorContains(t, err, "not initialized")

	_, err = ca.getTLSCertificate("example.com")
	require.ErrorContains(t, err, "not initialized")
}

// TestGetTLSCertificateRegeneratesWhenLeafExpired covers the case where the cached certificate
// itself has expired even though the cache entry is younger than cacheMaxAge.
func TestGetTLSCertificateRegeneratesWhenLeafExpired(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	first, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)

	// Simulate a cached certificate that has itself expired, without aging the entry.
	ca.cacheMutex.Lock()

	entry := ca.cache["example.com"]
	expired := *entry.certificate
	expiredLeaf := *entry.certificate.Leaf
	expiredLeaf.NotAfter = time.Now().Add(-time.Minute)
	expired.Leaf = &expiredLeaf
	entry.certificate = &expired

	ca.cacheMutex.Unlock()

	second, err := ca.getTLSCertificate("example.com")
	require.NoError(t, err)

	assert.NotSame(t, first, second)
}

// TestGetTLSCertificateConcurrentSameHost hammers the single-host generation path: under the
// in-flight deduplication, every goroutine must converge on one shared certificate.
func TestGetTLSCertificateConcurrentSameHost(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	const goroutines = 32

	var wg sync.WaitGroup

	certificates := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)

		go func() {
			defer wg.Done()

			certificates[i], errs[i] = ca.getTLSCertificate("concurrent.example.com")
		}()
	}

	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i])
		assert.Same(t, certificates[0], certificates[i])
	}
}

func BenchmarkGetTLSCertificateCacheHit(b *testing.B) {
	cert, key, err := GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithKeyType(KeyTypeECDSAP256))
	require.NoError(b, err)

	ca, err := New(cert, key)
	require.NoError(b, err)

	_, err = ca.getTLSCertificate("bench.example.com")
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err = ca.getTLSCertificate("bench.example.com")
		if err != nil {
			b.Fatal(err)
		}
	}
}
