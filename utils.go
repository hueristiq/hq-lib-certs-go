package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCertificatePrivateKeyFromFiles loads a certificate and private key from the specified PEM-encoded files.
//
// The certificate and private key are loaded using the crypto/tls package. The certificate is parsed to ensure
// it is a valid X.509 certificate, and the private key is verified to implement the crypto.Signer interface
// and to be one of the supported types (RSA, ECDSA, or Ed25519). The function performs input validation and
// provides detailed error messages for debugging purposes.
//
// Parameters:
//   - certificateFilePath (string): The file path to the PEM-encoded certificate.
//   - certificatePrivateKeyFilePath (string): The file path to the PEM-encoded private key.
//
// Returns:
//   - certificate (*x509.Certificate): A pointer to the loaded X.509 certificate.
//   - privateKey (crypto.Signer): The loaded private key, implementing the crypto.Signer interface.
//   - err (error): An error if loading, parsing, or type assertion fails; otherwise, nil.
func LoadCertificatePrivateKeyFromFiles(certificateFilePath, certificatePrivateKeyFilePath string) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	if certificateFilePath == "" || certificatePrivateKeyFilePath == "" {
		err = errors.New("invalid input, certificate file path or private key file path is empty")

		return nil, nil, err
	}

	keyPair, err := tls.LoadX509KeyPair(certificateFilePath, certificatePrivateKeyFilePath)
	if err != nil {
		err = fmt.Errorf("loading certificate and private key from files %q and %q: %w", certificateFilePath, certificatePrivateKeyFilePath, err)

		return nil, nil, err
	}

	certificate, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		err = fmt.Errorf("parsing X.509 certificate from file %q: %w", certificateFilePath, err)

		return nil, nil, err
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		err = fmt.Errorf("private key from file %q does not implement crypto.Signer: got type %T", certificatePrivateKeyFilePath, keyPair.PrivateKey)

		return nil, nil, err
	}

	privateKey = signer

	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		err = fmt.Errorf("unsupported private key type in file %q: got %T, expected RSA, ECDSA, or Ed25519", certificatePrivateKeyFilePath, privateKey)

		return nil, nil, err
	}

	return certificate, privateKey, nil
}

// SaveCertificatePrivateKeyToFiles saves a certificate and its private key to the specified files in PEM format.
//
// The certificate and private key are converted to PEM format and written to the provided file paths.
// The directories for both files are created with permissions 0755 if they do not exist. Files are
// written with restrictive permissions (0600) to ensure security for sensitive data. The private key must
// implement the crypto.Signer interface and be one of the supported types (RSA, ECDSA, or Ed25519).
//
// Parameters:
//   - certificate (*x509.Certificate): A pointer to the X.509 certificate to save.
//   - certificateFilePath (string): The file path where the certificate will be saved in PEM format.
//   - privateKey (crypto.Signer): The private key to save, implementing the crypto.Signer interface.
//   - privateKeyFilePath (string): The file path where the private key will be saved in PEM format.
//
// Returns:
//   - err (error): An error if directory creation, PEM conversion, or file writing fails; otherwise, nil.
func SaveCertificatePrivateKeyToFiles(certificate *x509.Certificate, certificateFilePath string, privateKey crypto.Signer, privateKeyFilePath string) (err error) {
	if certificate == nil {
		err = errors.New("invalid input, certificate is nil")

		return err
	}

	if privateKey == nil {
		err = errors.New("invalid input, private key is nil")

		return err
	}

	if certificateFilePath == "" || privateKeyFilePath == "" {
		err = errors.New("invalid input, certificate file path or private key file path is empty")

		return err
	}

	certificateFilePathDirectory := filepath.Dir(certificateFilePath)

	if err = mkdir(certificateFilePathDirectory); err != nil {
		err = fmt.Errorf("creating directory %q for certificate: %w", certificateFilePathDirectory, err)

		return err
	}

	privateKeyFilePathDirectory := filepath.Dir(privateKeyFilePath)

	if err = mkdir(privateKeyFilePathDirectory); err != nil {
		err = fmt.Errorf("creating directory %q for private key: %w", privateKeyFilePathDirectory, err)

		return err
	}

	certificateBytes, err := CertificateToPEM(certificate)
	if err != nil {
		err = fmt.Errorf("converting certificate to PEM format: %w", err)

		return err
	}

	if err = writeToFile(certificateBytes, certificateFilePath); err != nil {
		err = fmt.Errorf("writing certificate to file %q: %w", certificateFilePath, err)

		return err
	}

	keyBytes, err := PrivateKeyToPEM(privateKey)
	if err != nil {
		err = fmt.Errorf("converting private key to PEM format (type %T): %w", privateKey, err)

		return err
	}

	if err = writeToFile(keyBytes, privateKeyFilePath); err != nil {
		err = fmt.Errorf("writing private key to file %q: %w", privateKeyFilePath, err)

		return err
	}

	return nil
}

// mkdir creates a directory at the specified path if it does not exist.
//
// The directory is created with permissions 0755 (rwxr-xr-x), suitable for directories containing
// certificate files. If the directory already exists, no action is taken.
//
// Parameters:
//   - path (string): The file system path for the directory to create.
//
// Returns:
//   - err (error): An error if directory creation fails; otherwise, nil.
func mkdir(path string) (err error) {
	if path == "" {
		err = errors.New("invalid input, directory path is empty")

		return err
	}

	if err = os.MkdirAll(path, 0o755); err != nil {
		err = fmt.Errorf("creating directory %q with permissions 0755: %w", path, err)

		return err
	}

	return nil
}

// writeToFile writes the content of a byte slice to a file with restrictive permissions.
//
// The file is written with permissions 0600 (rw-------) to ensure security for sensitive data like
// certificates and private keys. Note that the permissions apply only when the file is created;
// an existing file keeps its current permissions.
//
// Parameters:
//   - content ([]byte): A byte slice containing the data to write.
//   - path (string): The file path where the content will be written.
//
// Returns:
//   - err (error): An error if file writing fails; otherwise, nil.
func writeToFile(content []byte, path string) (err error) {
	if path == "" {
		err = errors.New("invalid input, file path is empty")

		return err
	}

	if len(content) == 0 {
		err = fmt.Errorf("invalid input, content to write to file %q is empty", path)

		return err
	}

	if err = os.WriteFile(path, content, 0o600); err != nil {
		err = fmt.Errorf("writing content to file %q with permissions 0600: %w", path, err)

		return err
	}

	return nil
}
