package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
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

	assert.Same(t, cert, ca.GetCACertificate())
	assert.Equal(t, key, ca.GetCACertificatePrivateKey())
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
	roots.AddCert(ca.GetCACertificate())

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
