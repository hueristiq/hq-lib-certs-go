package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hqgotlscache "github.com/hueristiq/hq-lib-tls-go/cache"
)

var testKeyTypes = []struct {
	name    string
	keyType KeyType
}{
	{"rsa", KeyTypeRSA2048},
	{"ecdsa", KeyTypeECDSAP256},
	{"ed25519", KeyTypeED25519},
}

func newTestCACertificatePrivateKey(t *testing.T, ofs ...CAOption) (certificate *x509.Certificate, privateKey crypto.Signer) {
	t.Helper()

	ofs = append([]CAOption{WithCACommonName("Test CA")}, ofs...)

	certificate, privateKey, err := GenerateCACertificatePrivateKey(ofs...)
	require.NoError(t, err)
	require.NotNil(t, certificate)
	require.NotNil(t, privateKey)

	return certificate, privateKey
}

func newTestAuthority(t *testing.T, ofs ...AuthorityOption) (ca *CertificateAuthority) {
	t.Helper()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t)

	ca, err := New(caCertificate, caPrivateKey, ofs...)
	require.NoError(t, err)
	require.NotNil(t, ca)

	return ca
}

func mustNewInMemory(t *testing.T, maxSize int) (c *hqgotlscache.InMemory) {
	t.Helper()

	c, err := hqgotlscache.NewInMemory(maxSize)
	require.NoError(t, err)

	return c
}

type recordingCertificateCache struct {
	mutex   sync.Mutex
	entries map[string]*hqgotlscache.CertificateCacheEntry
	gets    int
	sets    int
}

func (c *recordingCertificateCache) Get(host string) (entry *hqgotlscache.CertificateCacheEntry, found bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.gets++

	entry, found = c.entries[host]

	return entry, found
}

func (c *recordingCertificateCache) Set(host string, entry *hqgotlscache.CertificateCacheEntry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.sets++

	c.entries[host] = entry
}

func newTestCSR(t *testing.T, commonName string, dnsNames []string) (csr *x509.CertificateRequest) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		DNSNames: dnsNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	csr, err = x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	return csr
}

func newSelfSignedCACertificate(t *testing.T, privateKey crypto.Signer, mutate func(*x509.Certificate)) (certificate *x509.Certificate) {
	t.Helper()

	serialNumber, err := generateSerialNumber()
	require.NoError(t, err)

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
	}

	if mutate != nil {
		mutate(template)
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	require.NoError(t, err)

	certificate, err = x509.ParseCertificate(certificateDER)
	require.NoError(t, err)

	return certificate
}

func requirePublicKeysEqual(t *testing.T, expected, actual crypto.PublicKey) {
	t.Helper()

	expectedDER, err := x509.MarshalPKIXPublicKey(expected)
	require.NoError(t, err)

	actualDER, err := x509.MarshalPKIXPublicKey(actual)
	require.NoError(t, err)

	assert.Equal(t, expectedDER, actualDER)
}

func handshakeOverPipe(t *testing.T, serverConfig, clientConfig *tls.Config) (clientState tls.ConnectionState, serverErr, clientErr error) {
	t.Helper()

	serverConn, clientConn := net.Pipe()

	server := tls.Server(serverConn, serverConfig)
	client := tls.Client(clientConn, clientConfig)

	serverErrCh := make(chan error, 1)

	go func() {
		serverErrCh <- server.HandshakeContext(t.Context())
	}()

	clientErr = client.HandshakeContext(t.Context())
	clientState = client.ConnectionState()

	_ = clientConn.Close()

	serverErr = <-serverErrCh

	_ = serverConn.Close()

	return clientState, serverErr, clientErr
}

func TestNewSuccess(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t)

	ca, err := New(caCertificate, caPrivateKey)
	require.NoError(t, err)
	require.NotNil(t, ca)

	assert.Equal(t, time.Hour, ca.cacheMaxAge)
	assert.Nil(t, ca.cache)
	assert.NotNil(t, ca.inflight)

	assert.Equal(t, caCertificate.Raw, ca.CACertificate().Raw)
	assert.Same(t, caPrivateKey, ca.CACertificatePrivateKey())
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	rsaCertificate, rsaPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeRSA2048))
	ecdsaCertificate, ecdsaPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeECDSAP256))
	ed25519Certificate, ed25519PrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeED25519))

	_, otherEd25519PrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeED25519))

	authority, err := New(ecdsaCertificate, ecdsaPrivateKey)
	require.NoError(t, err)

	leafCertificate, _, err := authority.GenerateTLSCertificate([]string{"leaf.example.com"})
	require.NoError(t, err)

	withoutCertSign := *rsaCertificate
	withoutCertSign.KeyUsage = x509.KeyUsageCRLSign

	unsupportedPublicKeyCertificate := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		PublicKey:             "unsupported",
	}

	tests := []struct {
		name        string
		certificate *x509.Certificate
		privateKey  crypto.Signer
		errContains string
	}{
		{"nil certificate", nil, rsaPrivateKey, "CA certificate is nil"},
		{"certificate is not a CA", leafCertificate, ecdsaPrivateKey, "not configured as a CA"},
		{"CA certificate lacks cert sign usage", &withoutCertSign, rsaPrivateKey, "lacks KeyUsageCertSign"},
		{"nil private key", rsaCertificate, nil, "CA private key is nil"},
		{"RSA certificate with ECDSA private key", rsaCertificate, ecdsaPrivateKey, "certificate public key is RSA, but private key is"},
		{"ECDSA certificate with Ed25519 private key", ecdsaCertificate, ed25519PrivateKey, "certificate public key is ECDSA, but private key is"},
		{"Ed25519 certificate with RSA private key", ed25519Certificate, rsaPrivateKey, "certificate public key is Ed25519, but private key is"},
		{"private key does not match public key", ed25519Certificate, otherEd25519PrivateKey, "does not match the certificate's public key"},
		{"unsupported public key type", unsupportedPublicKeyCertificate, ed25519PrivateKey, "unsupported certificate public key type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := New(tt.certificate, tt.privateKey)
			require.ErrorContains(t, err, tt.errContains)
			assert.Nil(t, ca)
		})
	}
}

func TestNewRejectsInvalidCacheOptions(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t)

	tests := []struct {
		name        string
		ofs         []AuthorityOption
		errContains string
	}{
		{"zero cache max age", []AuthorityOption{WithCacheMaxAge(0)}, "cache max age must be positive"},
		{"negative cache max age", []AuthorityOption{WithCacheMaxAge(-time.Hour)}, "cache max age must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := New(caCertificate, caPrivateKey, tt.ofs...)
			require.ErrorContains(t, err, tt.errContains)
			assert.Nil(t, ca)
		})
	}
}

func TestNewRejectsUnusableCACertificate(t *testing.T) {
	t.Parallel()

	newEd25519CA := func(t *testing.T, mutate func(*x509.Certificate)) (certificate *x509.Certificate, privateKey crypto.Signer) {
		t.Helper()

		_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		return newSelfSignedCACertificate(t, ed25519PrivateKey, mutate), ed25519PrivateKey
	}

	t.Run("expired CA certificate", func(t *testing.T) {
		t.Parallel()

		certificate, privateKey := newEd25519CA(t, func(template *x509.Certificate) {
			template.NotBefore = time.Now().Add(-2 * time.Hour)
			template.NotAfter = time.Now().Add(-time.Hour)
		})

		ca, err := New(certificate, privateKey)
		require.ErrorContains(t, err, "CA certificate has expired")
		assert.Nil(t, ca)
	})

	t.Run("not yet valid CA certificate", func(t *testing.T) {
		t.Parallel()

		certificate, privateKey := newEd25519CA(t, func(template *x509.Certificate) {
			template.NotBefore = time.Now().Add(time.Hour)
			template.NotAfter = time.Now().Add(2 * time.Hour)
		})

		ca, err := New(certificate, privateKey)
		require.ErrorContains(t, err, "CA certificate is not yet valid")
		assert.Nil(t, ca)
	})

	t.Run("basic constraints not valid", func(t *testing.T) {
		t.Parallel()

		certificate, privateKey := newEd25519CA(t, nil)

		certificate.BasicConstraintsValid = false

		ca, err := New(certificate, privateKey)
		require.ErrorContains(t, err, "BasicConstraintsValid is false")
		assert.Nil(t, ca)
	})
}

func TestNewFromPEM(t *testing.T) {
	t.Parallel()

	for _, kt := range testKeyTypes {
		t.Run(kt.name, func(t *testing.T) {
			t.Parallel()

			certificatePEM, privateKeyPEM, err := GenerateCACertificatePrivateKeyPEM(WithCACommonName("Test CA"), WithCAKeyType(kt.keyType))
			require.NoError(t, err)

			ca, err := NewFromPEM(certificatePEM, privateKeyPEM)
			require.NoError(t, err)

			certificateBlock, _ := pem.Decode(certificatePEM)
			require.NotNil(t, certificateBlock)

			assert.Equal(t, certificateBlock.Bytes, ca.CACertificate().Raw)
		})
	}

	t.Run("pkcs8 wrapped RSA private key", func(t *testing.T) {
		t.Parallel()

		caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeRSA2048))

		certificatePEM, err := CertificateToPEM(caCertificate)
		require.NoError(t, err)

		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(caPrivateKey)
		require.NoError(t, err)

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

		ca, err := NewFromPEM(certificatePEM, privateKeyPEM)
		require.NoError(t, err)

		assert.Equal(t, caCertificate.Raw, ca.CACertificate().Raw)
	})

	t.Run("authority options forwarded", func(t *testing.T) {
		t.Parallel()

		certificatePEM, privateKeyPEM, err := GenerateCACertificatePrivateKeyPEM(WithCACommonName("Test CA"), WithCAKeyType(KeyTypeED25519))
		require.NoError(t, err)

		ca, err := NewFromPEM(certificatePEM, privateKeyPEM, WithCacheMaxAge(2*time.Minute))
		require.NoError(t, err)

		assert.Equal(t, 2*time.Minute, ca.cacheMaxAge)
	})
}

func TestNewFromPEMValidation(t *testing.T) {
	t.Parallel()

	certificatePEM, privateKeyPEM, err := GenerateCACertificatePrivateKeyPEM(WithCACommonName("Test CA"), WithCAKeyType(KeyTypeED25519))
	require.NoError(t, err)

	_, otherPrivateKeyPEM, err := GenerateCACertificatePrivateKeyPEM(WithCACommonName("Other CA"), WithCAKeyType(KeyTypeED25519))
	require.NoError(t, err)

	garbageCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	unsupportedKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("not a private key")})

	tests := []struct {
		name           string
		certificatePEM []byte
		privateKeyPEM  []byte
		errContains    string
	}{
		{"empty certificate bytes", nil, privateKeyPEM, "CA certificate bytes are empty"},
		{"empty private key bytes", certificatePEM, nil, "CA private key bytes are empty"},
		{"malformed certificate PEM", []byte("not pem"), privateKeyPEM, "decoding PEM block for CA certificate"},
		{"wrong certificate block type", privateKeyPEM, privateKeyPEM, "invalid PEM block type for CA certificate"},
		{"unparseable certificate DER", garbageCertificatePEM, privateKeyPEM, "parsing X.509 certificate from PEM data"},
		{"malformed private key PEM", certificatePEM, []byte("not pem"), "decoding PEM block for private key"},
		{"unsupported private key block type", certificatePEM, unsupportedKeyPEM, "unsupported PEM block type for private key"},
		{"mismatched certificate and key", certificatePEM, otherPrivateKeyPEM, "does not match the certificate's public key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca, err := NewFromPEM(tt.certificatePEM, tt.privateKeyPEM)
			require.ErrorContains(t, err, tt.errContains)
			assert.Nil(t, ca)
		})
	}
}

func TestCACertificateReturnsCopy(t *testing.T) {
	t.Parallel()

	t.Run("nil authority returns nil", func(t *testing.T) {
		t.Parallel()

		var ca *CertificateAuthority

		assert.Nil(t, ca.CACertificate())
		assert.Nil(t, ca.CACertificatePrivateKey())
	})

	t.Run("uninitialized authority returns nil", func(t *testing.T) {
		t.Parallel()

		ca := &CertificateAuthority{}

		assert.Nil(t, ca.CACertificate())
		assert.Nil(t, ca.CACertificatePrivateKey())
	})

	t.Run("mutating the returned certificate does not affect the authority", func(t *testing.T) {
		t.Parallel()

		ca := newTestAuthority(t)

		certificate := ca.CACertificate()
		require.NotNil(t, certificate)

		originalNotAfter := certificate.NotAfter
		certificate.NotAfter = time.Now().Add(-time.Hour)

		refetched := ca.CACertificate()
		require.NotNil(t, refetched)

		assert.True(t, refetched.NotAfter.Equal(originalNotAfter))
	})
}

func TestZeroValueCertificateAuthority(t *testing.T) {
	t.Parallel()

	ca := &CertificateAuthority{}

	_, _, err := ca.GenerateTLSCertificate([]string{"example.com"})
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")

	_, err = ca.SignCSR(newTestCSR(t, "client.example.com", nil))
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")

	_, err = ca.TLSCertificate("example.com")
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")

	assert.Nil(t, ca.CACertificate())
	assert.Nil(t, ca.CACertificatePrivateKey())

	config := ca.NewTLSConfig()
	require.NotNil(t, config)

	_, err = config.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")

	configWithHost := ca.NewTLSConfigWithHost("fallback.example.com")
	require.NotNil(t, configWithHost)

	_, err = configWithHost.GetCertificate(&tls.ClientHelloInfo{})
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")
}

func TestTLSCertificateValidation(t *testing.T) {
	t.Parallel()

	var nilAuthority *CertificateAuthority

	_, err := nilAuthority.TLSCertificate("example.com")
	require.ErrorContains(t, err, "CertificateAuthority is nil")

	zeroAuthority := &CertificateAuthority{}

	_, err = zeroAuthority.TLSCertificate("example.com")
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")
}

func TestTLSCertificateSuccess(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	certificate, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)
	require.NotNil(t, certificate)
	require.NotNil(t, certificate.Leaf)

	require.Len(t, certificate.Certificate, 2)
	assert.Equal(t, certificate.Leaf.Raw, certificate.Certificate[0])
	assert.Equal(t, ca.CACertificate().Raw, certificate.Certificate[1])
	assert.Contains(t, certificate.Leaf.DNSNames, "example.com")

	roots := x509.NewCertPool()
	roots.AddCert(ca.CACertificate())

	_, err = certificate.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots})
	require.NoError(t, err)
}

func TestTLSCertificateCacheHit(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t, WithCache(mustNewInMemory(t, 8)))

	first, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	second, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	assert.Same(t, first, second)
}

func TestTLSCertificateNormalizesHostname(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t, WithCache(mustNewInMemory(t, 8)))

	first, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	second, err := ca.TLSCertificate("EXAMPLE.com:443")
	require.NoError(t, err)

	assert.Same(t, first, second)
}

func TestTLSCertificateConcurrentSameHost(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeECDSAP256))

	ca, err := New(caCertificate, caPrivateKey, WithCache(mustNewInMemory(t, 16)))
	require.NoError(t, err)

	const goroutines = 16

	type callResult struct {
		certificate *tls.Certificate
		err         error
	}

	results := make(chan callResult, goroutines)

	var wg sync.WaitGroup

	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()

			certificate, err := ca.TLSCertificate("concurrent.example.com")
			results <- callResult{certificate: certificate, err: err}
		}()
	}

	wg.Wait()
	close(results)

	var first *tls.Certificate

	for result := range results {
		require.NoError(t, result.err)
		require.NotNil(t, result.certificate)

		if first == nil {
			first = result.certificate
		} else {
			assert.Same(t, first, result.certificate)
		}
	}
}

func TestGetTLSCertificateRegeneratesAfterExpiry(t *testing.T) {
	t.Parallel()

	certificateCache := mustNewInMemory(t, 2)

	ca := newTestAuthority(t, WithCache(certificateCache), WithCacheMaxAge(time.Minute))

	first, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	entry, found := certificateCache.Get("example.com")
	require.True(t, found)

	// Backdate the cached entry beyond the maximum cache age.
	certificateCache.Set("example.com", &hqgotlscache.CertificateCacheEntry{
		Certificate: entry.Certificate,
		CreatedAt:   time.Now().Add(-2 * time.Minute),
	})

	second, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	assert.NotSame(t, first, second)
}

func TestGetTLSCertificateRegeneratesWhenLeafExpired(t *testing.T) {
	t.Parallel()

	certificateCache := mustNewInMemory(t, 2)

	ca := newTestAuthority(t, WithCache(certificateCache))

	first, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	entry, found := certificateCache.Get("example.com")
	require.True(t, found)

	// Expire the cached leaf: the entry must not be served even though it is fresh.
	entry.Certificate.Leaf.NotAfter = time.Now().Add(-time.Hour)

	second, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	assert.NotSame(t, first, second)
}

func TestNewTLSConfigDefaults(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	config := ca.NewTLSConfig()
	require.NotNil(t, config)

	assert.Equal(t, uint16(tls.VersionTLS12), config.MinVersion)
	assert.Equal(t, []string{"h2", "http/1.1"}, config.NextProtos)
	require.NotNil(t, config.GetCertificate)

	_, err := config.GetCertificate(nil)
	require.ErrorContains(t, err, "ClientHelloInfo is nil")

	_, err = config.GetCertificate(&tls.ClientHelloInfo{})
	require.ErrorContains(t, err, "missing server name (SNI)")

	certificate, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)
	require.NotNil(t, certificate.Leaf)

	assert.Contains(t, certificate.Leaf.DNSNames, "example.com")
}

func TestNewTLSConfigNextProtosOption(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	config := ca.NewTLSConfig(WithNextProtos("acme/1", "acme/2"))
	require.NotNil(t, config)
	assert.Equal(t, []string{"acme/1", "acme/2"}, config.NextProtos)

	configNoALPN := ca.NewTLSConfig(WithNextProtos())
	require.NotNil(t, configNoALPN)
	assert.Empty(t, configNoALPN.NextProtos)
}

func TestNewTLSConfigWithHostFallback(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	config := ca.NewTLSConfigWithHost("fallback.example.com")
	require.NotNil(t, config)

	certificate, err := config.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, certificate.Leaf)

	assert.Contains(t, certificate.Leaf.DNSNames, "fallback.example.com")

	certificate, err = config.GetCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	require.NoError(t, err)
	require.NotNil(t, certificate.Leaf)

	assert.Contains(t, certificate.Leaf.DNSNames, "other.example.com")
}

func TestTLSConfigNilCA(t *testing.T) {
	t.Parallel()

	var ca *CertificateAuthority

	config := ca.NewTLSConfig()
	require.NotNil(t, config)

	_, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")

	configWithHost := ca.NewTLSConfigWithHost("fallback.example.com")
	require.NotNil(t, configWithHost)

	_, err = configWithHost.GetCertificate(&tls.ClientHelloInfo{})
	require.ErrorContains(t, err, "CertificateAuthority is not initialized")
}

func TestTLSServerHandshake(t *testing.T) {
	t.Parallel()

	for _, kt := range testKeyTypes {
		t.Run(kt.name, func(t *testing.T) {
			t.Parallel()

			caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(kt.keyType))

			ca, err := New(caCertificate, caPrivateKey)
			require.NoError(t, err)

			roots := x509.NewCertPool()
			roots.AddCert(caCertificate)

			t.Run("trusted CA", func(t *testing.T) {
				t.Parallel()

				clientConfig := &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    roots,
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				}

				clientState, serverErr, clientErr := handshakeOverPipe(t, ca.NewTLSConfig(), clientConfig)
				require.NoError(t, clientErr)
				require.NoError(t, serverErr)

				assert.Equal(t, "h2", clientState.NegotiatedProtocol)
				require.NotEmpty(t, clientState.PeerCertificates)
				assert.Contains(t, clientState.PeerCertificates[0].DNSNames, "example.com")
				assert.NotEmpty(t, clientState.VerifiedChains)
			})

			t.Run("untrusted CA", func(t *testing.T) {
				t.Parallel()

				clientConfig := &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    x509.NewCertPool(),
					ServerName: "example.com",
				}

				_, serverErr, clientErr := handshakeOverPipe(t, ca.NewTLSConfig(), clientConfig)
				require.Error(t, clientErr)
				require.Error(t, serverErr)
			})
		})
	}
}

func TestTLSServerHandshakeWithHostFallback(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeECDSAP256))

	ca, err := New(caCertificate, caPrivateKey)
	require.NoError(t, err)

	serverConfig := ca.NewTLSConfigWithHost("fallback.example.com")
	clientConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // G402: verification is disabled on purpose to exercise the handshake without SNI
	}

	clientState, serverErr, clientErr := handshakeOverPipe(t, serverConfig, clientConfig)
	require.NoError(t, clientErr)
	require.NoError(t, serverErr)

	require.NotEmpty(t, clientState.PeerCertificates)
	assert.Contains(t, clientState.PeerCertificates[0].DNSNames, "fallback.example.com")
}

func TestGenerateCACertificatePrivateKeyDefaults(t *testing.T) {
	t.Parallel()

	_, _, err := GenerateCACertificatePrivateKey()
	require.ErrorContains(t, err, "CommonName is empty")

	before := time.Now()

	certificate, privateKey, err := GenerateCACertificatePrivateKey(WithCACommonName("Test CA"))
	require.NoError(t, err)
	require.NotNil(t, certificate)
	require.NotNil(t, privateKey)

	assert.IsType(t, &rsa.PrivateKey{}, privateKey)
	assert.True(t, certificate.IsCA)
	assert.True(t, certificate.BasicConstraintsValid)
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, certificate.KeyUsage)
	assert.Empty(t, certificate.Subject.Organization)
	assert.Positive(t, certificate.SerialNumber.Sign())
	assert.LessOrEqual(t, certificate.SerialNumber.BitLen(), 128)
	assert.Len(t, certificate.SubjectKeyId, 32)

	assert.WithinDuration(t, before.Add(-5*time.Minute), certificate.NotBefore, time.Minute)
	assert.True(t, certificate.NotAfter.Equal(certificate.NotBefore.Add(365*24*time.Hour+5*time.Minute)))

	require.NoError(t, certificate.CheckSignatureFrom(certificate))
}

func TestGenerateCACertificatePrivateKeyKeyTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		keyType           KeyType
		wantPrivateKey    any
		wantSignatureAlgo x509.SignatureAlgorithm
	}{
		{"rsa", KeyTypeRSA2048, &rsa.PrivateKey{}, x509.SHA256WithRSA},
		{"ecdsa", KeyTypeECDSAP256, &ecdsa.PrivateKey{}, x509.ECDSAWithSHA256},
		{"ed25519", KeyTypeED25519, ed25519.PrivateKey{}, x509.PureEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certificate, privateKey, err := GenerateCACertificatePrivateKey(WithCACommonName("Test CA"), WithCAKeyType(tt.keyType))
			require.NoError(t, err)

			assert.IsType(t, tt.wantPrivateKey, privateKey)
			assert.Equal(t, tt.wantSignatureAlgo, certificate.SignatureAlgorithm)

			requirePublicKeysEqual(t, privateKey.Public(), certificate.PublicKey)
			require.NoError(t, certificate.CheckSignatureFrom(certificate))
		})
	}
}

func TestGenerateCACertificatePrivateKeyCustomOptions(t *testing.T) {
	t.Parallel()

	validFrom := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	validFor := 72 * time.Hour

	certificate, _, err := GenerateCACertificatePrivateKey(
		WithCACommonName("Custom CA"),
		WithCAOrganization([]string{"Custom Org"}),
		WithCAValidFrom(validFrom),
		WithCAValidFor(validFor),
	)
	require.NoError(t, err)

	assert.Equal(t, "Custom CA", certificate.Subject.CommonName)
	assert.Equal(t, []string{"Custom Org"}, certificate.Subject.Organization)
	assert.True(t, certificate.NotBefore.Equal(validFrom.Add(-5*time.Minute)))
	assert.True(t, certificate.NotAfter.Equal(validFrom.Add(validFor)))
}

func TestGenerateCACertificatePrivateKeyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ofs         []CAOption
		errContains string
	}{
		{"missing common name", nil, "CommonName is empty"},
		{"empty common name", []CAOption{WithCACommonName("")}, "CommonName is empty"},
		{"zero validity duration", []CAOption{WithCACommonName("Test CA"), WithCAValidFor(0)}, "ValidFor duration must be positive"},
		{"negative validity duration", []CAOption{WithCACommonName("Test CA"), WithCAValidFor(-time.Hour)}, "ValidFor duration must be positive"},
		{"unsupported key type", []CAOption{WithCACommonName("Test CA"), WithCAKeyType(KeyType(99))}, "unsupported CA key type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := GenerateCACertificatePrivateKey(tt.ofs...)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGenerateTLSCertificateValidation(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	tests := []struct {
		name        string
		ca          *CertificateAuthority
		hosts       []string
		ofs         []TLSOption
		errContains string
	}{
		{"nil authority", nil, []string{"example.com"}, nil, "CertificateAuthority is nil"},
		{"uninitialized authority", &CertificateAuthority{}, []string{"example.com"}, nil, "CertificateAuthority is not initialized"},
		{"empty hosts list", ca, nil, nil, "hosts list is empty"},
		{"empty hostname in hosts list", ca, []string{""}, nil, "empty hostname in hosts list"},
		{"empty common name", ca, []string{"example.com"}, []TLSOption{WithTLSCommonName("")}, "CommonName is empty"},
		{"non-positive validity duration", ca, []string{"example.com"}, []TLSOption{WithTLSValidFor(0)}, "ValidFor duration must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := tt.ca.GenerateTLSCertificate(tt.hosts, tt.ofs...)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGenerateTLSCertificateSuccess(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	before := time.Now()

	certificate, privateKey, err := ca.GenerateTLSCertificate([]string{"example.com"})
	require.NoError(t, err)
	require.NotNil(t, certificate)
	require.NotNil(t, privateKey)

	assert.Equal(t, "example.com", certificate.Subject.CommonName)
	assert.Empty(t, certificate.Subject.Organization)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, certificate.ExtKeyUsage)
	assert.Equal(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, certificate.KeyUsage)
	assert.Positive(t, certificate.SerialNumber.Sign())
	assert.LessOrEqual(t, certificate.SerialNumber.BitLen(), 128)
	assert.Len(t, certificate.SubjectKeyId, 32)

	assert.WithinDuration(t, before.Add(-5*time.Minute), certificate.NotBefore, time.Minute)

	caCertificate := ca.CACertificate()
	require.NotNil(t, caCertificate)

	assert.True(t, certificate.NotAfter.Equal(caCertificate.NotAfter))
	assert.WithinDuration(t, time.Now().Add(365*24*time.Hour), certificate.NotAfter, time.Minute)

	require.NoError(t, certificate.CheckSignatureFrom(caCertificate))

	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	_, err = certificate.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots})
	require.NoError(t, err)

	_, err = certificate.Verify(x509.VerifyOptions{DNSName: "wrong.example.com", Roots: roots})
	require.Error(t, err)
}

func TestGenerateTLSCertificateLeafKeyMatchesCAKeyType(t *testing.T) {
	t.Parallel()

	for _, kt := range testKeyTypes {
		t.Run(kt.name, func(t *testing.T) {
			t.Parallel()

			caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(kt.keyType))

			ca, err := New(caCertificate, caPrivateKey)
			require.NoError(t, err)

			certificate, privateKey, err := ca.GenerateTLSCertificate([]string{"example.com"})
			require.NoError(t, err)

			switch kt.keyType {
			case KeyTypeRSA2048:
				leafKey, ok := privateKey.(*rsa.PrivateKey)
				require.True(t, ok)

				caKey, ok := caPrivateKey.(*rsa.PrivateKey)
				require.True(t, ok)

				assert.Equal(t, caKey.N.BitLen(), leafKey.N.BitLen())
			case KeyTypeECDSAP256:
				leafKey, ok := privateKey.(*ecdsa.PrivateKey)
				require.True(t, ok)

				caKey, ok := caPrivateKey.(*ecdsa.PrivateKey)
				require.True(t, ok)

				assert.Equal(t, caKey.Curve.Params().Name, leafKey.Curve.Params().Name)
			case KeyTypeED25519:
				assert.IsType(t, ed25519.PrivateKey{}, privateKey)
			default:
				require.FailNow(t, "unhandled key type in test")
			}

			requirePublicKeysEqual(t, privateKey.Public(), certificate.PublicKey)
		})
	}
}

func TestGenerateTLSCertificateRSALeafInheritsCAKeySize(t *testing.T) {
	t.Parallel()

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	caCertificate := newSelfSignedCACertificate(t, caPrivateKey, nil)

	ca, err := New(caCertificate, caPrivateKey)
	require.NoError(t, err)

	certificate, privateKey, err := ca.GenerateTLSCertificate([]string{"example.com"})
	require.NoError(t, err)

	leafPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, 4096, leafPrivateKey.N.BitLen())

	leafPublicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, 4096, leafPublicKey.N.BitLen())
}

func TestGenerateTLSCertificateHostClassification(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	tests := []struct {
		name       string
		hosts      []string
		dnsNames   []string
		ipStrings  []string
		emails     []string
		uriStrings []string
	}{
		{"ipv4 address", []string{"192.0.2.1"}, nil, []string{"192.0.2.1"}, nil, nil},
		{"ipv6 address", []string{"2001:db8::1"}, nil, []string{"2001:db8::1"}, nil, nil},
		{"email address", []string{"user@example.com"}, nil, nil, []string{"user@example.com"}, nil},
		{"uri with scheme and host", []string{"https://example.com/path"}, nil, nil, nil, []string{"https://example.com/path"}},
		{"plain dns name", []string{"example.com"}, []string{"example.com"}, nil, nil, nil},
		{"wildcard dns name", []string{"*.example.com"}, []string{"*.example.com"}, nil, nil, nil},
		{
			"mixed hosts",
			[]string{"example.com", "192.0.2.1", "2001:db8::1", "user@example.com", "https://example.com/path"},
			[]string{"example.com"},
			[]string{"192.0.2.1", "2001:db8::1"},
			[]string{"user@example.com"},
			[]string{"https://example.com/path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certificate, _, err := ca.GenerateTLSCertificate(tt.hosts)
			require.NoError(t, err)

			assert.Equal(t, tt.dnsNames, certificate.DNSNames)
			assert.Equal(t, tt.emails, certificate.EmailAddresses)

			require.Len(t, certificate.IPAddresses, len(tt.ipStrings))

			for i, ip := range certificate.IPAddresses {
				assert.Equal(t, tt.ipStrings[i], ip.String())
			}

			require.Len(t, certificate.URIs, len(tt.uriStrings))

			for i, uri := range certificate.URIs {
				assert.Equal(t, tt.uriStrings[i], uri.String())
			}
		})
	}
}

func TestGenerateTLSCertificateCustomOptions(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	t.Run("custom subject validity and single extended key usage", func(t *testing.T) {
		t.Parallel()

		validFrom := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
		validFor := 4 * time.Hour

		certificate, _, err := ca.GenerateTLSCertificate(
			[]string{"example.com"},
			WithTLSCommonName("custom.example.com"),
			WithTLSOrganization([]string{"Custom Org"}),
			WithTLSValidFrom(validFrom),
			WithTLSValidFor(validFor),
			WithTLSExtKeyUsage(x509.ExtKeyUsageClientAuth),
		)
		require.NoError(t, err)

		assert.Equal(t, "custom.example.com", certificate.Subject.CommonName)
		assert.Equal(t, []string{"Custom Org"}, certificate.Subject.Organization)
		assert.True(t, certificate.NotBefore.Equal(validFrom.Add(-5*time.Minute)))
		assert.True(t, certificate.NotAfter.Equal(validFrom.Add(validFor)))
		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, certificate.ExtKeyUsage)
	})

	t.Run("multiple extended key usages", func(t *testing.T) {
		t.Parallel()

		certificate, _, err := ca.GenerateTLSCertificate(
			[]string{"example.com"},
			WithTLSExtKeyUsage(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth),
		)
		require.NoError(t, err)

		assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, certificate.ExtKeyUsage)
	})
}

func TestGenerateTLSCertificateClampsValidityToCAExpiry(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAValidFor(time.Hour))

	ca, err := New(caCertificate, caPrivateKey)
	require.NoError(t, err)

	certificate, _, err := ca.GenerateTLSCertificate([]string{"example.com"}, WithTLSValidFor(365*24*time.Hour))
	require.NoError(t, err)

	assert.True(t, certificate.NotAfter.Equal(caCertificate.NotAfter))
}

func TestSignCSRValidation(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	validCSR := newTestCSR(t, "client.example.com", []string{"client.example.com"})

	tamperedCSR := newTestCSR(t, "client.example.com", nil)
	tamperedCSR.Signature[0] ^= 0xFF

	emptyCNCSR := newTestCSR(t, "", nil)

	tests := []struct {
		name        string
		ca          *CertificateAuthority
		csr         *x509.CertificateRequest
		ofs         []TLSOption
		errContains string
	}{
		{"nil authority", nil, validCSR, nil, "CertificateAuthority is nil"},
		{"uninitialized authority", &CertificateAuthority{}, validCSR, nil, "CertificateAuthority is not initialized"},
		{"nil CSR", ca, nil, nil, "CSR is nil"},
		{"tampered CSR signature", ca, tamperedCSR, nil, "verifying CSR signature"},
		{"empty common name", ca, emptyCNCSR, nil, "CommonName is empty"},
		{"non-positive validity duration", ca, validCSR, []TLSOption{WithTLSValidFor(0)}, "ValidFor duration must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := tt.ca.SignCSR(tt.csr, tt.ofs...)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestSignCSRSuccess(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	uri, err := url.Parse("https://client.example.com/path")
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames:       []string{"client.example.com", "www.client.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.10")},
		EmailAddresses: []string{"client@example.com"},
		URIs:           []*url.URL{uri},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	certificate, err := ca.SignCSR(csr)
	require.NoError(t, err)

	assert.Equal(t, "client.example.com", certificate.Subject.CommonName)
	assert.Equal(t, []string{"Test Org"}, certificate.Subject.Organization)
	assert.Equal(t, []string{"client.example.com", "www.client.example.com"}, certificate.DNSNames)
	assert.Equal(t, []string{"client@example.com"}, certificate.EmailAddresses)
	require.Len(t, certificate.IPAddresses, 1)
	assert.Equal(t, "192.0.2.10", certificate.IPAddresses[0].String())
	require.Len(t, certificate.URIs, 1)
	assert.Equal(t, "https://client.example.com/path", certificate.URIs[0].String())
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, certificate.ExtKeyUsage)
	assert.Equal(t, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, certificate.KeyUsage)

	expectedSKI, err := generateSubjectKeyID(csr.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, expectedSKI, certificate.SubjectKeyId)

	caCertificate := ca.CACertificate()
	require.NotNil(t, caCertificate)
	require.NoError(t, certificate.CheckSignatureFrom(caCertificate))

	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)

	_, err = certificate.Verify(x509.VerifyOptions{
		DNSName:   "client.example.com",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)
}

func TestSignCSRSubjectOverrides(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	csr := newTestCSR(t, "client.example.com", []string{"client.example.com"})

	certificate, err := ca.SignCSR(csr,
		WithTLSCommonName("override.example.com"),
		WithTLSOrganization([]string{"Override Org"}),
	)
	require.NoError(t, err)

	assert.Equal(t, "override.example.com", certificate.Subject.CommonName)
	assert.Equal(t, []string{"Override Org"}, certificate.Subject.Organization)
}

func TestSignCSRClampsValidityToCAExpiry(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAValidFor(time.Hour))

	ca, err := New(caCertificate, caPrivateKey)
	require.NoError(t, err)

	csr := newTestCSR(t, "client.example.com", nil)

	certificate, err := ca.SignCSR(csr)
	require.NoError(t, err)

	assert.True(t, certificate.NotAfter.Equal(caCertificate.NotAfter))
}

type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey {
	return nil
}

func (fakeSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fakeSigner does not sign")
}

func TestCertificateToPEM(t *testing.T) {
	t.Parallel()

	caCertificate, _ := newTestCACertificatePrivateKey(t)

	raw, err := CertificateToPEM(caCertificate)
	require.NoError(t, err)

	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Equal(t, caCertificate.Raw, parsed.Raw)

	tests := []struct {
		name        string
		certificate *x509.Certificate
		errContains string
	}{
		{"nil certificate", nil, "certificate is nil"},
		{"empty raw data", &x509.Certificate{}, "certificate raw data is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := CertificateToPEM(tt.certificate)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestPrivateKeyToPEMBlockTypes(t *testing.T) {
	t.Parallel()

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name          string
		privateKey    crypto.Signer
		wantBlockType string
	}{
		{"rsa", rsaPrivateKey, "RSA PRIVATE KEY"},
		{"ecdsa", ecdsaPrivateKey, "EC PRIVATE KEY"},
		{"ed25519", ed25519PrivateKey, "PRIVATE KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, err := PrivateKeyToPEM(tt.privateKey)
			require.NoError(t, err)

			block, _ := pem.Decode(raw)
			require.NotNil(t, block)
			assert.Equal(t, tt.wantBlockType, block.Type)
		})
	}
}

func TestPrivateKeyToPEMRoundTrip(t *testing.T) {
	t.Parallel()

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name       string
		privateKey crypto.Signer
		parse      func(t *testing.T, der []byte) crypto.Signer
		equal      func(t *testing.T, expected, actual crypto.Signer)
	}{
		{
			name:       "rsa",
			privateKey: rsaPrivateKey,
			parse: func(t *testing.T, der []byte) crypto.Signer {
				t.Helper()

				key, err := x509.ParsePKCS1PrivateKey(der)
				require.NoError(t, err)

				return key
			},
			equal: func(t *testing.T, expected, actual crypto.Signer) {
				t.Helper()

				expectedKey, ok := expected.(*rsa.PrivateKey)
				require.True(t, ok)

				actualKey, ok := actual.(*rsa.PrivateKey)
				require.True(t, ok)

				assert.Zero(t, expectedKey.D.Cmp(actualKey.D))
				assert.Zero(t, expectedKey.N.Cmp(actualKey.N))
				assert.Equal(t, expectedKey.E, actualKey.E)
				requirePublicKeysEqual(t, expectedKey.Public(), actualKey.Public())
			},
		},
		{
			name:       "ecdsa",
			privateKey: ecdsaPrivateKey,
			parse: func(t *testing.T, der []byte) crypto.Signer {
				t.Helper()

				key, err := x509.ParseECPrivateKey(der)
				require.NoError(t, err)

				return key
			},
			equal: func(t *testing.T, expected, actual crypto.Signer) {
				t.Helper()

				expectedKey, ok := expected.(*ecdsa.PrivateKey)
				require.True(t, ok)

				actualKey, ok := actual.(*ecdsa.PrivateKey)
				require.True(t, ok)

				expectedBytes, err := expectedKey.Bytes()
				require.NoError(t, err)

				actualBytes, err := actualKey.Bytes()
				require.NoError(t, err)

				assert.Equal(t, expectedBytes, actualBytes)
				requirePublicKeysEqual(t, expectedKey.Public(), actualKey.Public())
			},
		},
		{
			name:       "ed25519",
			privateKey: ed25519PrivateKey,
			parse: func(t *testing.T, der []byte) crypto.Signer {
				t.Helper()

				key, err := x509.ParsePKCS8PrivateKey(der)
				require.NoError(t, err)

				signer, ok := key.(crypto.Signer)
				require.True(t, ok)

				return signer
			},
			equal: func(t *testing.T, expected, actual crypto.Signer) {
				t.Helper()

				expectedKey, ok := expected.(ed25519.PrivateKey)
				require.True(t, ok)

				actualKey, ok := actual.(ed25519.PrivateKey)
				require.True(t, ok)

				assert.Equal(t, expectedKey, actualKey)
				requirePublicKeysEqual(t, expectedKey.Public(), actualKey.Public())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, err := PrivateKeyToPEM(tt.privateKey)
			require.NoError(t, err)

			block, _ := pem.Decode(raw)
			require.NotNil(t, block)

			parsed := tt.parse(t, block.Bytes)

			tt.equal(t, tt.privateKey, parsed)
		})
	}
}

func TestPrivateKeyToPEMValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		privateKey  crypto.Signer
		errContains string
	}{
		{"nil private key", nil, "private key is nil"},
		{"unsupported private key type", fakeSigner{}, "unsupported private key type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := PrivateKeyToPEM(tt.privateKey)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestGenerateCACertificatePrivateKeyPEM(t *testing.T) {
	t.Parallel()

	certificatePEM, privateKeyPEM, err := GenerateCACertificatePrivateKeyPEM(WithCACommonName("Test CA"))
	require.NoError(t, err)

	certificateBlock, _ := pem.Decode(certificatePEM)
	require.NotNil(t, certificateBlock)
	assert.Equal(t, "CERTIFICATE", certificateBlock.Type)

	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	require.NotNil(t, privateKeyBlock)
	assert.Equal(t, "RSA PRIVATE KEY", privateKeyBlock.Type)

	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", certificate.Subject.CommonName)

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	require.NoError(t, err)

	requirePublicKeysEqual(t, privateKey.Public(), certificate.PublicKey)

	_, _, err = GenerateCACertificatePrivateKeyPEM()
	require.ErrorContains(t, err, "CommonName is empty")
}

func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want string
	}{
		{"plain hostname", "example.com", "example.com"},
		{"hostname with port", "example.com:443", "example.com"},
		{"uppercase hostname", "EXAMPLE.COM", "example.com"},
		{"uppercase hostname with port", "EXAMPLE.COM:443", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"trailing dot with port", "example.com.:443", "example.com"},
		{"NFD folded to NFC", "café.com", "café.com"},
		{"NFD with port", "café.com:443", "café.com"},
		{"ipv6 address with port", "[::1]:443", "::1"},
		{"empty hostname", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, normalizeHost(tt.host))
		})
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 100)

	for range 100 {
		serialNumber, err := generateSerialNumber()
		require.NoError(t, err)
		require.NotNil(t, serialNumber)

		assert.Positive(t, serialNumber.Sign())
		assert.LessOrEqual(t, serialNumber.BitLen(), 128)

		key := serialNumber.String()

		_, exists := seen[key]
		require.False(t, exists, "duplicate serial number %s", key)

		seen[key] = struct{}{}
	}
}

func TestGenerateSubjectKeyID(t *testing.T) {
	t.Parallel()

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name      string
		publicKey crypto.PublicKey
	}{
		{"rsa", rsaPrivateKey.Public()},
		{"ecdsa", ecdsaPrivateKey.Public()},
		{"ed25519", ed25519PrivateKey.Public()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkixDER, err := x509.MarshalPKIXPublicKey(tt.publicKey)
			require.NoError(t, err)

			expected := sha256.Sum256(pkixDER)

			ski, err := generateSubjectKeyID(tt.publicKey)
			require.NoError(t, err)
			assert.Equal(t, expected[:], ski)

			again, err := generateSubjectKeyID(tt.publicKey)
			require.NoError(t, err)
			assert.Equal(t, ski, again)
		})
	}

	t.Run("nil public key", func(t *testing.T) {
		t.Parallel()

		_, err := generateSubjectKeyID(nil)
		require.ErrorContains(t, err, "public key is nil")
	})
}

func TestIsCacheEntryValid(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	now := time.Now()

	tests := []struct {
		name  string
		entry *hqgotlscache.CertificateCacheEntry
		want  bool
	}{
		{"nil certificate", &hqgotlscache.CertificateCacheEntry{Certificate: nil, CreatedAt: now}, false},
		{"nil leaf", &hqgotlscache.CertificateCacheEntry{Certificate: &tls.Certificate{}, CreatedAt: now}, false},
		{"fresh entry", &hqgotlscache.CertificateCacheEntry{Certificate: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(time.Hour)}}, CreatedAt: now}, true},
		{"entry older than max age", &hqgotlscache.CertificateCacheEntry{Certificate: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(time.Hour)}}, CreatedAt: now.Add(-2 * time.Hour)}, false},
		{"expired leaf", &hqgotlscache.CertificateCacheEntry{Certificate: &tls.Certificate{Leaf: &x509.Certificate{NotAfter: now.Add(-time.Hour)}}, CreatedAt: now}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, ca.isCacheEntryValid(tt.entry))
		})
	}
}

func TestTLSCertificateRegeneratesWithoutCache(t *testing.T) {
	t.Parallel()

	ca := newTestAuthority(t)

	first, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	second, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	assert.NotSame(t, first, second)
}

func TestTLSCertificateServesFromCustomCache(t *testing.T) {
	t.Parallel()

	certificateCache := &recordingCertificateCache{entries: make(map[string]*hqgotlscache.CertificateCacheEntry)}

	ca := newTestAuthority(t, WithCache(certificateCache))

	first, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	second, err := ca.TLSCertificate("example.com")
	require.NoError(t, err)

	assert.Same(t, first, second)

	certificateCache.mutex.Lock()
	defer certificateCache.mutex.Unlock()

	assert.Equal(t, 2, certificateCache.gets)
	assert.Equal(t, 1, certificateCache.sets)
}
