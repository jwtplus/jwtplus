package lib

import (
	"crypto/elliptic"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestGenerateKeyPair(t *testing.T) {
	privatePEM, publicPEM, err := GenerateKeyPair("RS256")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

// Test RSA Key Generation
func TestGenerateRSAKeyPairRS256(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("RS256")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateRSAKeyPairRS256(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateRSAKeyPair("RS256")
	}
}

func TestGenerateRSAKeyPairRS384(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("RS384")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS384, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateRSAKeyPairRS384(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateRSAKeyPair("RS384")
	}
}

func TestGenerateRSAKeyPairRS512(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("RS512")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateRSAKeyPairRS512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateRSAKeyPair("RS512")
	}
}

// Test RSA-PS Key Generation
func TestGenerateRSAPSKeyPairPS256(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("PS256")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodPS256, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSAPSS)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateRSAKeyPairPS256(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateRSAKeyPair("PS256")
	}
}

func TestGenerateRSAPSKeyPairPS384(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("PS384")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodPS384, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSAPSS)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateRSAKeyPairPS384(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateRSAKeyPair("PS384")
	}
}

func TestGenerateRSAPSKeyPairPS512(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("PS512")
	assert.NoError(t, err, "RSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END RSA PRIVATE KEY-----\n"), "RSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "RSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "RSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "RSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "RSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodPS512, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "RSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSAPSS)
		assert.True(t, ok, "RSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateRSAKeyPairPS512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateRSAKeyPair("PS512")
	}
}

// Test ECDSA Key Generation
func TestGenerateECDSAKeyPairES256(t *testing.T) {
	privatePEM, publicPEM, err := generateECDSAKeyPair(elliptic.P256())
	assert.NoError(t, err, "ECDSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN EC PRIVATE KEY-----"), "ECDSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END EC PRIVATE KEY-----\n"), "ECDSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "ECDSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "ECDSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "ECDSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "ECDSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "ECDSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		assert.True(t, ok, "ECDSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateECDSAKeyPairES256(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateECDSAKeyPair(elliptic.P256())
	}
}

func TestGenerateECDSAKeyPairES384(t *testing.T) {
	privatePEM, publicPEM, err := generateECDSAKeyPair(elliptic.P384())
	assert.NoError(t, err, "ECDSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN EC PRIVATE KEY-----"), "ECDSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END EC PRIVATE KEY-----\n"), "ECDSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "ECDSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "ECDSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "ECDSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "ECDSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES384, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "ECDSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		assert.True(t, ok, "ECDSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateECDSAKeyPairES384(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateECDSAKeyPair(elliptic.P384())
	}
}

func TestGenerateECDSAKeyPairES512(t *testing.T) {
	privatePEM, publicPEM, err := generateECDSAKeyPair(elliptic.P521())
	assert.NoError(t, err, "ECDSA key generation should not return an error")

	// Assert Private Key Format
	assert.True(t, strings.HasPrefix(privatePEM, "-----BEGIN EC PRIVATE KEY-----"), "ECDSA Private Key should start with PEM header")
	assert.True(t, strings.HasSuffix(privatePEM, "-----END EC PRIVATE KEY-----\n"), "ECDSA Private Key should end with PEM footer")

	// Assert Public Key Format
	assert.True(t, strings.HasPrefix(publicPEM, "-----BEGIN PUBLIC KEY-----"), "ECDSA Public Key should start with PEM header")
	assert.True(t, strings.HasSuffix(publicPEM, "-----END PUBLIC KEY-----\n"), "ECDSA Public Key should end with PEM footer")

	// Parse Private Key
	privateKey, err := jwt.ParseECPrivateKeyFromPEM([]byte(privatePEM))
	assert.NoError(t, err, "ECDSA Failed to parse private key")

	// Parse Public Key
	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicPEM))
	assert.NoError(t, err, "ECDSA Failed to parse public key")

	// Sign JWT
	token := jwt.NewWithClaims(jwt.SigningMethodES512, jwt.MapClaims{
		"sub": "testuser",                       // Subject (user identifier)
		"iss": "test-app",                       // Issuer
		"exp": time.Now().Add(time.Hour).Unix(), // Expiration time
		"iat": time.Now().Unix(),                // Issued at
	})
	tokenString, err := token.SignedString(privateKey)
	assert.NoError(t, err, "ECDSA Error in signing JWT")

	// Verify JWT
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodECDSA)
		assert.True(t, ok, "ECDSA - Should return true")
		return publicKey, nil
	})
	assert.NoError(t, err, "JWT verification failed")
	assert.True(t, parsedToken.Valid, "JWT verification failed")
}

func BenchmarkGenerateECDSAKeyPairES512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		generateECDSAKeyPair(elliptic.P521())
	}
}
