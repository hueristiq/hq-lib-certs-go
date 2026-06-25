package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCACertificatePrivateKeyDefaults(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.True(t, cert.IsCA)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCertSign)
	assert.NotZero(t, cert.KeyUsage&x509.KeyUsageCRLSign)
	assert.Equal(t, "Acme CA", cert.Subject.CommonName)
	assert.Equal(t, []string{"Acme Co"}, cert.Subject.Organization)
	assert.Len(t, cert.SubjectKeyId, sha256.Size)
	assert.Equal(t, 1, cert.SerialNumber.Sign())
	assert.IsType(t, &rsa.PrivateKey{}, key)
}

func TestGenerateCACertificatePrivateKeyKeyTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		keyType KeyType
		want    any
	}{
		{"rsa", KeyTypeRSA2048, &rsa.PrivateKey{}},
		{"ecdsa", KeyTypeECDSAP256, &ecdsa.PrivateKey{}},
		{"ed25519", KeyTypeED25519, ed25519.PrivateKey{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cert, key, err := GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithKeyType(tc.keyType))
			require.NoError(t, err)

			assert.IsType(t, tc.want, key)
			assert.True(t, cert.IsCA)
		})
	}
}

func TestGenerateCACertificatePrivateKeyCustomOptions(t *testing.T) {
	t.Parallel()

	validFrom := time.Now().Add(time.Hour).Truncate(time.Second)

	cert, _, err := GenerateCACertificatePrivateKey(
		CACertificatePrivateKeyWithCommonName("My Root CA"),
		CACertificatePrivateKeyWithOrganization([]string{"My Org"}),
		CACertificatePrivateKeyWithValidFrom(validFrom),
		CACertificatePrivateKeyWithValidFor(24*time.Hour),
	)
	require.NoError(t, err)

	assert.Equal(t, "My Root CA", cert.Subject.CommonName)
	assert.Equal(t, []string{"My Org"}, cert.Subject.Organization)
	assert.WithinDuration(t, validFrom.Add(-5*time.Minute), cert.NotBefore, time.Second)
	assert.WithinDuration(t, validFrom.Add(24*time.Hour), cert.NotAfter, time.Second)
}

func TestGenerateCACertificatePrivateKeyValidation(t *testing.T) {
	t.Parallel()

	_, _, err := GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithCommonName(""))
	require.ErrorContains(t, err, "CommonName is empty")

	_, _, err = GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithValidFor(0))
	require.ErrorContains(t, err, "ValidFor")

	_, _, err = GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithValidFor(-time.Hour))
	require.ErrorContains(t, err, "ValidFor")

	_, _, err = GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithKeyType(KeyType(99)))
	require.ErrorContains(t, err, "unsupported CA key type")
}

func TestGenerateTLSCertificateSuccess(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	validFrom := time.Now().Add(time.Hour).Truncate(time.Second)

	cert, key, err := ca.GenerateTLSCertificate(
		[]string{"example.com"},
		TLSCertificatePrivateKeyWithCommonName("example.com"),
		TLSCertificatePrivateKeyWithOrganization([]string{"My Org"}),
		TLSCertificatePrivateKeyWithValidFrom(validFrom),
		TLSCertificatePrivateKeyWithValidFor(48*time.Hour),
	)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.IsType(t, &ecdsa.PrivateKey{}, key)

	assert.Equal(t, "example.com", cert.Subject.CommonName)
	assert.False(t, cert.IsCA)
	assert.WithinDuration(t, validFrom.Add(-5*time.Minute), cert.NotBefore, time.Second)
	assert.WithinDuration(t, validFrom.Add(48*time.Hour), cert.NotAfter, time.Second)
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// The leaf must be signed by the CA.
	require.NoError(t, cert.CheckSignatureFrom(ca.GetCACertificate()))
}

func TestGenerateTLSCertificateHostClassification(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeRSA2048)

	cert, _, err := ca.GenerateTLSCertificate([]string{
		"example.com",
		"192.168.1.1",
		"user@example.com",
		"https://example.com/path",
	})
	require.NoError(t, err)

	assert.Contains(t, cert.DNSNames, "example.com")
	assert.Len(t, cert.IPAddresses, 1)
	assert.Equal(t, "192.168.1.1", cert.IPAddresses[0].String())
	assert.Contains(t, cert.EmailAddresses, "user@example.com")
	assert.Len(t, cert.URIs, 1)
	assert.Equal(t, "https://example.com/path", cert.URIs[0].String())
}

func TestGenerateTLSCertificateLeafKeyMatchesCAKeyType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		keyType KeyType
		want    any
	}{
		{"rsa", KeyTypeRSA2048, &rsa.PrivateKey{}},
		{"ecdsa", KeyTypeECDSAP256, &ecdsa.PrivateKey{}},
		{"ed25519", KeyTypeED25519, ed25519.PrivateKey{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newTestCA(t, tc.keyType)

			_, key, err := ca.GenerateTLSCertificate([]string{"example.com"})
			require.NoError(t, err)

			assert.IsType(t, tc.want, key)
		})
	}
}

func TestGenerateTLSCertificateCustomExtKeyUsage(t *testing.T) {
	t.Parallel()

	ca := newTestCA(t, KeyTypeECDSAP256)

	cert, _, err := ca.GenerateTLSCertificate(
		[]string{"client.example.com"},
		TLSCertificatePrivateKeyWithExtKeyUsage(x509.ExtKeyUsageClientAuth),
	)
	require.NoError(t, err)

	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.NotContains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestGenerateTLSCertificateValidation(t *testing.T) {
	t.Parallel()

	var nilCA *CertificateAuthority

	_, _, err := nilCA.GenerateTLSCertificate([]string{"example.com"})
	require.ErrorContains(t, err, "CertificateAuthority is nil")

	ca := newTestCA(t, KeyTypeECDSAP256)

	_, _, err = ca.GenerateTLSCertificate(nil)
	require.ErrorContains(t, err, "hosts list is empty")

	_, _, err = ca.GenerateTLSCertificate([]string{"example.com"}, TLSCertificatePrivateKeyWithCommonName(""))
	require.ErrorContains(t, err, "CommonName is empty")

	_, _, err = ca.GenerateTLSCertificate([]string{"example.com"}, TLSCertificatePrivateKeyWithValidFor(0))
	require.ErrorContains(t, err, "ValidFor")

	_, _, err = ca.GenerateTLSCertificate([]string{""})
	require.ErrorContains(t, err, "empty hostname")
}
