package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateToPEM(t *testing.T) {
	t.Parallel()

	cert, _, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	raw, err := CertificateToPEM(cert)
	require.NoError(t, err)

	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, parsed.Raw)
}

func TestCertificateToPEMValidation(t *testing.T) {
	t.Parallel()

	_, err := CertificateToPEM(nil)
	require.ErrorContains(t, err, "certificate is nil")

	_, err = CertificateToPEM(&x509.Certificate{})
	require.ErrorContains(t, err, "raw data is empty")
}

func TestPrivateKeyToPEMBlockTypes(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name      string
		key       crypto.Signer
		blockType string
	}{
		{"rsa", rsaKey, "RSA PRIVATE KEY"},
		{"ecdsa", ecKey, "EC PRIVATE KEY"},
		{"ed25519", edKey, "PRIVATE KEY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := PrivateKeyToPEM(tc.key)
			require.NoError(t, err)

			block, _ := pem.Decode(raw)
			require.NotNil(t, block)
			assert.Equal(t, tc.blockType, block.Type)
		})
	}
}

func TestPrivateKeyToPEMValidation(t *testing.T) {
	t.Parallel()

	_, err := PrivateKeyToPEM(nil)
	require.ErrorContains(t, err, "private key is nil")

	_, err = PrivateKeyToPEM(fakeSigner{})
	require.ErrorContains(t, err, "unsupported private key type")
}

func TestGenerateCACertificatePrivateKeyBytes(t *testing.T) {
	t.Parallel()

	certBytes, keyBytes, err := GenerateCACertificatePrivateKeyBytes()
	require.NoError(t, err)

	certBlock, _ := pem.Decode(certBytes)
	require.NotNil(t, certBlock)
	assert.Equal(t, "CERTIFICATE", certBlock.Type)

	keyBlock, _ := pem.Decode(keyBytes)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)
}

func TestNewWithBytesCertificatePrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		keyType KeyType
	}{
		{"rsa", KeyTypeRSA2048},
		{"ecdsa", KeyTypeECDSAP256},
		{"ed25519", KeyTypeED25519},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			certBytes, keyBytes, err := GenerateCACertificatePrivateKeyBytes(CACertificatePrivateKeyWithKeyType(tc.keyType))
			require.NoError(t, err)

			ca, err := NewWithBytesCertificatePrivateKey(certBytes, keyBytes)
			require.NoError(t, err)

			_, _, err = ca.GenerateTLSCertificate([]string{"example.com"})
			require.NoError(t, err)
		})
	}
}

func TestNewWithBytesCertificatePrivateKeyForwardsOptions(t *testing.T) {
	t.Parallel()

	certBytes, keyBytes, err := GenerateCACertificatePrivateKeyBytes()
	require.NoError(t, err)

	ca, err := NewWithBytesCertificatePrivateKey(certBytes, keyBytes, CertificateAuthorityWithCacheMaxSize(7))
	require.NoError(t, err)

	assert.Equal(t, 7, ca.cacheMaxSize)
}

func TestNewWithBytesCertificatePrivateKeyValidation(t *testing.T) {
	t.Parallel()

	certBytes, keyBytes, err := GenerateCACertificatePrivateKeyBytes()
	require.NoError(t, err)

	t.Run("empty cert bytes", func(t *testing.T) {
		t.Parallel()

		_, err := NewWithBytesCertificatePrivateKey(nil, keyBytes)
		require.ErrorContains(t, err, "CA certificate bytes are empty")
	})

	t.Run("empty key bytes", func(t *testing.T) {
		t.Parallel()

		_, err := NewWithBytesCertificatePrivateKey(certBytes, nil)
		require.ErrorContains(t, err, "CA private key bytes are empty")
	})

	t.Run("malformed cert pem", func(t *testing.T) {
		t.Parallel()

		_, err := NewWithBytesCertificatePrivateKey([]byte("not a pem"), keyBytes)
		require.ErrorContains(t, err, "decoding PEM block for CA certificate")
	})

	t.Run("wrong cert block type", func(t *testing.T) {
		t.Parallel()

		_, err := NewWithBytesCertificatePrivateKey(keyBytes, keyBytes)
		require.ErrorContains(t, err, "invalid PEM block type for CA certificate")
	})

	t.Run("unparseable cert bytes", func(t *testing.T) {
		t.Parallel()

		garbage := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})

		_, err := NewWithBytesCertificatePrivateKey(garbage, keyBytes)
		require.ErrorContains(t, err, "parsing X.509 certificate")
	})

	t.Run("malformed key pem", func(t *testing.T) {
		t.Parallel()

		_, err := NewWithBytesCertificatePrivateKey(certBytes, []byte("not a pem"))
		require.ErrorContains(t, err, "decoding PEM block for private key")
	})

	t.Run("unsupported key block type", func(t *testing.T) {
		t.Parallel()

		badKey := pem.EncodeToMemory(&pem.Block{Type: "FOO PRIVATE KEY", Bytes: []byte("x")})

		_, err := NewWithBytesCertificatePrivateKey(certBytes, badKey)
		require.ErrorContains(t, err, "unsupported PEM block type for private key")
	})
}
