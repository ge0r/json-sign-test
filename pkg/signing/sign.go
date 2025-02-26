package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
)

// SavePublicKey saves an RSA public key to a PEM file.
func SavePublicKey(filename string, pubkey *rsa.PublicKey) error {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return os.WriteFile(filename, pubPEM, 0644)
}

// SavePrivateKey saves the private key to a file.
func SavePrivateKey(fileName string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	return os.WriteFile(fileName, keyPEM, 0600)
}

// LoadPrivateKey loads the private key from a file.
func LoadPrivateKey(fileName string) (*rsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// SignData signs the data using the private key.
func SignData(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
}

// VerifySignature verifies the signature using the public key.
func VerifySignature(publicKey *rsa.PublicKey, data []byte, signature string) error {
	hashed := sha256.Sum256(data)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sigBytes)
}

// LoadPublicKey loads the public key from a file.
func LoadPublicKey(fileName string) (*rsa.PublicKey, error) {
	keyPEM, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}
