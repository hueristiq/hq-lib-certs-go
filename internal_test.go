package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSerialNumber(t *testing.T) {
	t.Parallel()

	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	for range 100 {
		serial, err := generateSerialNumber()
		require.NoError(t, err)

		assert.Equal(t, 1, serial.Sign(), "serial number must be positive")
		assert.Negative(t, serial.Cmp(limit), "serial number must be below 2^128")
	}
}

func TestGenerateSubjectKeyID(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ski, err := generateSubjectKeyID(key.Public())
	require.NoError(t, err)
	assert.Len(t, ski, sha256.Size)

	// The SKI is deterministic for a given public key.
	again, err := generateSubjectKeyID(key.Public())
	require.NoError(t, err)
	assert.Equal(t, ski, again)
}

func TestGenerateSubjectKeyIDNil(t *testing.T) {
	t.Parallel()

	_, err := generateSubjectKeyID(nil)
	require.ErrorContains(t, err, "public key is nil")
}

func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	// nfd is the decomposed form: 'e' + U+0301 combining acute accent.
	// nfc is the precomposed single codepoint U+00E9 ("é").
	const (
		nfd = "\u0065\u0301xample.com"
		nfc = "\u00e9xample.com"
	)

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "example.com", "example.com"},
		{"with port", "example.com:443", "example.com"},
		{"nfd normalizes to nfc", nfd, nfc},
		{"nfd with port", nfd + ":8443", nfc},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, normalizeHost(tc.input))
		})
	}
}

func TestClearOldCacheEntries(t *testing.T) {
	t.Parallel()

	now := time.Now()

	ca := &CertificateAuthority{
		cache: map[string]*_TLSCertificateCacheEntry{
			"old.example.com":    {certificate: &tls.Certificate{}, createdAt: now.Add(-2 * time.Hour)},
			"newer.example.com":  {certificate: &tls.Certificate{}, createdAt: now.Add(-time.Hour)},
			"newest.example.com": {certificate: &tls.Certificate{}, createdAt: now},
		},
	}

	ca.clearOldCacheEntries()

	assert.NotContains(t, ca.cache, "old.example.com")
	assert.Contains(t, ca.cache, "newer.example.com")
	assert.Contains(t, ca.cache, "newest.example.com")
}
