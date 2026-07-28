package certs

import (
	"crypto"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectedWritePerm returns the permission bits writeToFile leaves on a newly
// created file. Windows only models the read-only bit, so a 0600 write reports
// 0666 there.
func expectedWritePerm() os.FileMode {
	if runtime.GOOS == "windows" {
		return 0o666
	}

	return 0o600
}

func TestSaveAndLoadCertificatePrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()

	for _, kt := range testKeyTypes {
		t.Run(kt.name, func(t *testing.T) {
			t.Parallel()

			caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(kt.keyType))

			certificateFilePath := filepath.Join(t.TempDir(), "nested", "certs", "ca.crt")
			privateKeyFilePath := filepath.Join(t.TempDir(), "nested", "keys", "ca.key")

			require.NoError(t, SaveCertificatePrivateKeyToFiles(caCertificate, caPrivateKey, certificateFilePath, privateKeyFilePath))

			for _, path := range []string{certificateFilePath, privateKeyFilePath} {
				info, err := os.Stat(path)
				require.NoError(t, err)
				assert.Equal(t, expectedWritePerm(), info.Mode().Perm())
			}

			loadedCertificate, loadedPrivateKey, err := LoadCertificatePrivateKeyFromFiles(certificateFilePath, privateKeyFilePath)
			require.NoError(t, err)

			assert.Equal(t, caCertificate.Raw, loadedCertificate.Raw)
			assert.IsType(t, caPrivateKey, loadedPrivateKey)
		})
	}
}

func TestSaveCertificatePrivateKeyToFilesSeparateDirectories(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeED25519))

	certificateFilePath := filepath.Join(t.TempDir(), "certs", "ca.crt")
	privateKeyFilePath := filepath.Join(t.TempDir(), "keys", "ca.key")

	require.NoError(t, SaveCertificatePrivateKeyToFiles(caCertificate, caPrivateKey, certificateFilePath, privateKeyFilePath))

	for _, path := range []string{certificateFilePath, privateKeyFilePath} {
		_, err := os.Stat(path)
		require.NoError(t, err)
	}

	loadedCertificate, _, err := LoadCertificatePrivateKeyFromFiles(certificateFilePath, privateKeyFilePath)
	require.NoError(t, err)

	assert.Equal(t, caCertificate.Raw, loadedCertificate.Raw)
}

func TestSaveCertificatePrivateKeyToFilesValidation(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeED25519))

	dir := t.TempDir()
	certificateFilePath := filepath.Join(dir, "ca.crt")
	privateKeyFilePath := filepath.Join(dir, "ca.key")

	tests := []struct {
		name                string
		certificate         *x509.Certificate
		privateKey          crypto.Signer
		certificateFilePath string
		privateKeyFilePath  string
		errContains         string
	}{
		{"nil certificate", nil, caPrivateKey, certificateFilePath, privateKeyFilePath, "certificate is nil"},
		{"nil private key", caCertificate, nil, certificateFilePath, privateKeyFilePath, "private key is nil"},
		{"empty certificate file path", caCertificate, caPrivateKey, "", privateKeyFilePath, "certificate file path or private key file path is empty"},
		{"empty private key file path", caCertificate, caPrivateKey, certificateFilePath, "", "certificate file path or private key file path is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := SaveCertificatePrivateKeyToFiles(tt.certificate, tt.privateKey, tt.certificateFilePath, tt.privateKeyFilePath)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestLoadCertificatePrivateKeyFromFilesValidation(t *testing.T) {
	t.Parallel()

	caCertificate, caPrivateKey := newTestCACertificatePrivateKey(t, WithCAKeyType(KeyTypeED25519))

	certificatePEM, err := CertificateToPEM(caCertificate)
	require.NoError(t, err)

	privateKeyPEM, err := PrivateKeyToPEM(caPrivateKey)
	require.NoError(t, err)

	writeFile := func(t *testing.T, path string, content []byte) {
		t.Helper()

		require.NoError(t, os.WriteFile(path, content, 0o600))
	}

	tests := []struct {
		name        string
		setup       func(t *testing.T, dir string) (certificateFilePath, privateKeyFilePath string)
		errContains string
	}{
		{
			name: "empty file paths",
			setup: func(t *testing.T, _ string) (string, string) {
				t.Helper()

				return "", ""
			},
			errContains: "certificate file path or private key file path is empty",
		},
		{
			name: "missing files",
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				return filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")
			},
			errContains: "loading certificate and private key from files",
		},
		{
			name: "certificate file is not PEM",
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				certificateFilePath := filepath.Join(dir, "ca.crt")
				privateKeyFilePath := filepath.Join(dir, "ca.key")

				writeFile(t, certificateFilePath, []byte("not pem"))
				writeFile(t, privateKeyFilePath, privateKeyPEM)

				return certificateFilePath, privateKeyFilePath
			},
			errContains: "loading certificate and private key from files",
		},
		{
			name: "private key file has wrong block type",
			setup: func(t *testing.T, dir string) (string, string) {
				t.Helper()

				certificateFilePath := filepath.Join(dir, "ca.crt")
				privateKeyFilePath := filepath.Join(dir, "ca.key")

				writeFile(t, certificateFilePath, certificatePEM)
				writeFile(t, privateKeyFilePath, certificatePEM)

				return certificateFilePath, privateKeyFilePath
			},
			errContains: "loading certificate and private key from files",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certificateFilePath, privateKeyFilePath := tt.setup(t, t.TempDir())

			_, _, err := LoadCertificatePrivateKeyFromFiles(certificateFilePath, privateKeyFilePath)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestMkdir(t *testing.T) {
	t.Parallel()

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		err := mkdir("")
		require.ErrorContains(t, err, "directory path is empty")
	})

	t.Run("nested creation", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "a", "b", "c")

		require.NoError(t, mkdir(path))

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("idempotent", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "nested", "dir")

		require.NoError(t, mkdir(path))
		require.NoError(t, mkdir(path))
	})

	t.Run("path exists as file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "file")

		require.NoError(t, os.WriteFile(path, []byte("content"), 0o600))

		err := mkdir(path)
		require.ErrorContains(t, err, "creating directory")
	})
}

func TestWriteToFile(t *testing.T) {
	t.Parallel()

	t.Run("content round trip", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "file.txt")
		content := []byte("hello, certs")

		require.NoError(t, writeToFile(content, path))

		read, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, content, read)

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, expectedWritePerm(), info.Mode().Perm())
	})

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		err := writeToFile([]byte("content"), "")
		require.ErrorContains(t, err, "file path is empty")
	})

	t.Run("empty content", func(t *testing.T) {
		t.Parallel()

		err := writeToFile(nil, filepath.Join(t.TempDir(), "file.txt"))
		require.ErrorContains(t, err, "content to write")
	})

	t.Run("missing parent directory", func(t *testing.T) {
		t.Parallel()

		err := writeToFile([]byte("content"), filepath.Join(t.TempDir(), "missing", "file.txt"))
		require.ErrorContains(t, err, "writing content to file")
	})
}
