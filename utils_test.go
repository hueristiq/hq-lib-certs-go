package certs

import (
	"crypto/rsa"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectedWritePerm returns the permission bits a file written by writeToFile is
// expected to have. Windows only models the read-only attribute, so a writable
// file stats as 0666 there instead of the 0600 requested at creation.
func expectedWritePerm() os.FileMode {
	if runtime.GOOS == "windows" {
		return 0o666
	}

	return 0o600
}

func TestSaveAndLoadCertificatePrivateKeyRoundTrip(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	dir := t.TempDir()
	// Nested path exercises directory creation.
	certPath := filepath.Join(dir, "pki", "cert.pem")
	keyPath := filepath.Join(dir, "pki", "key.pem")

	err = SaveCertificatePrivateKeyToFiles(cert, certPath, key, keyPath)
	require.NoError(t, err)

	certInfo, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, expectedWritePerm(), certInfo.Mode().Perm())

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, expectedWritePerm(), keyInfo.Mode().Perm())

	loadedCert, loadedKey, err := LoadCertificatePrivateKeyFromFiles(certPath, keyPath)
	require.NoError(t, err)

	assert.Equal(t, cert.Raw, loadedCert.Raw)
	assert.IsType(t, &rsa.PrivateKey{}, loadedKey)
}

func TestSaveCertificatePrivateKeyToFilesSeparateDirectories(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	dir := t.TempDir()
	// Distinct nested paths exercise directory creation for both files.
	certPath := filepath.Join(dir, "certs", "cert.pem")
	keyPath := filepath.Join(dir, "keys", "key.pem")

	err = SaveCertificatePrivateKeyToFiles(cert, certPath, key, keyPath)
	require.NoError(t, err)

	_, err = os.Stat(certPath)
	require.NoError(t, err)

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, expectedWritePerm(), keyInfo.Mode().Perm())

	loadedCert, _, err := LoadCertificatePrivateKeyFromFiles(certPath, keyPath)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, loadedCert.Raw)
}

func TestSaveCertificatePrivateKeyToFilesValidation(t *testing.T) {
	t.Parallel()

	cert, key, err := GenerateCACertificatePrivateKey()
	require.NoError(t, err)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	err = SaveCertificatePrivateKeyToFiles(nil, certPath, key, keyPath)
	require.ErrorContains(t, err, "certificate is nil")

	err = SaveCertificatePrivateKeyToFiles(cert, certPath, nil, keyPath)
	require.ErrorContains(t, err, "private key is nil")

	err = SaveCertificatePrivateKeyToFiles(cert, "", key, keyPath)
	require.ErrorContains(t, err, "file path")
}

func TestLoadCertificatePrivateKeyFromFilesValidation(t *testing.T) {
	t.Parallel()

	_, _, err := LoadCertificatePrivateKeyFromFiles("", "")
	require.ErrorContains(t, err, "file path")

	dir := t.TempDir()

	_, _, err = LoadCertificatePrivateKeyFromFiles(
		filepath.Join(dir, "missing-cert.pem"),
		filepath.Join(dir, "missing-key.pem"),
	)
	require.Error(t, err)
}

func TestMkdir(t *testing.T) {
	t.Parallel()

	err := mkdir("")
	require.ErrorContains(t, err, "directory path is empty")

	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")

	err = mkdir(nested)
	require.NoError(t, err)

	info, err := os.Stat(nested)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Calling again on an existing directory is a no-op.
	err = mkdir(nested)
	require.NoError(t, err)
}

func TestWriteToFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")

	err := writeToFile([]byte("hello"), path)
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), content)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, expectedWritePerm(), info.Mode().Perm())
}

func TestWriteToFileValidation(t *testing.T) {
	t.Parallel()

	err := writeToFile([]byte("data"), "")
	require.ErrorContains(t, err, "file path is empty")

	dir := t.TempDir()

	err = writeToFile(nil, filepath.Join(dir, "empty.bin"))
	require.ErrorContains(t, err, "content")
}
