package certs

import (
	"crypto"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakePublicKey is a public key whose type is none of RSA, ECDSA, or Ed25519.
// It is used to exercise the "unsupported key type" branches.
type fakePublicKey struct{}

// fakeSigner is a crypto.Signer whose concrete type is unsupported by the package.
type fakeSigner struct{}

// Public returns a public key of an unsupported type.
func (fakeSigner) Public() crypto.PublicKey {
	return fakePublicKey{}
}

// Sign is never expected to be called in tests; it returns an error to satisfy the linter.
func (fakeSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	err = errors.New("fakeSigner: Sign not implemented")

	return
}

// newTestCA builds a CertificateAuthority from a freshly generated CA of the given key type.
func newTestCA(t *testing.T, keyType KeyType, ofs ...CertificateAuthorityOptionFunc) *CertificateAuthority {
	t.Helper()

	cert, key, err := GenerateCACertificatePrivateKey(CACertificatePrivateKeyWithKeyType(keyType))
	require.NoError(t, err)

	ca, err := New(cert, key, ofs...)
	require.NoError(t, err)

	return ca
}
