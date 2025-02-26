package lib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// GenerateKeyPair generates public-private key pairs as Base64 encoded strings
func GenerateKeyPair(algo string) (string, string, error) {
	switch algo {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return generateRSAKeyPair(algo)
	case "ES256":
		return generateECDSAKeyPair(elliptic.P256())
	case "ES384":
		return generateECDSAKeyPair(elliptic.P384())
	case "ES512":
		return generateECDSAKeyPair(elliptic.P521())
	default:
		return "", "", errors.New(fmt.Sprintf("unsupported algorithm %s", algo))
	}
}

// Generate RSA/PS key pair and return as Base64
func generateRSAKeyPair(algo string) (string, string, error) {
	keySize := 2048 // Minimum RSA key size

	if algo == "RS512" || algo == "PS512" {
		keySize = 4096 // Stronger key
	}

	// Generate Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Encode Private Key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePEM := string(pem.EncodeToMemory(privatePemBlock))

	// Encode Public Key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal RSA public key: %v", err)
	}
	publicPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPEM := string(pem.EncodeToMemory(publicPemBlock))

	return privatePEM, publicPEM, nil
}

// Generate ECDSA key pair and return as Base64
func generateECDSAKeyPair(curve elliptic.Curve) (string, string, error) {

	// Generate ECDSA Private Key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Convert Private Key to DER format
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode ECDSA private key: %w", err)
	}

	// Convert Public Key to DER format
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode ECDSA public key: %w", err)
	}

	// Encode Private Key to PEM
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateDER,
	})

	// Encode Public Key to PEM
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicDER,
	})

	return string(privatePEM), string(publicPEM), nil
}
