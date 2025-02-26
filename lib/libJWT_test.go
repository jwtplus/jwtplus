package lib

import (
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestJWTPayload_sign_verify_renew_RS256(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("RS256")
	assert.NoError(t, err, "RSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	//Fail the singing by sending invalid algo
	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	//Fail the singing by sending invalid private key
	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_RS256(b *testing.B) {
	privatePEM, publicPEM, _ := generateRSAKeyPair("RS256")
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_RS384(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("RS384")
	assert.NoError(t, err, "RSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS384",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_RS384(b *testing.B) {
	privatePEM, publicPEM, _ := generateRSAKeyPair("RS384")
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_RS512(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("RS512")
	assert.NoError(t, err, "RSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS512",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_RS512(b *testing.B) {
	privatePEM, publicPEM, _ := generateRSAKeyPair("RS512")
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_PS256(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("PS256")
	assert.NoError(t, err, "RSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "PS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_PS256(b *testing.B) {
	privatePEM, publicPEM, _ := generateRSAKeyPair("PS256")
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_PS384(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("PS384")
	assert.NoError(t, err, "RSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "PS384",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_PS384(b *testing.B) {
	privatePEM, publicPEM, _ := generateRSAKeyPair("PS384")
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_PS512(t *testing.T) {
	privatePEM, publicPEM, err := generateRSAKeyPair("PS512")
	assert.NoError(t, err, "RSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "PS512",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_PS512(b *testing.B) {
	privatePEM, publicPEM, _ := generateRSAKeyPair("PS512")
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "RS256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_ES256(t *testing.T) {
	privatePEM, publicPEM, err := generateECDSAKeyPair(elliptic.P256())
	assert.NoError(t, err, "ECDSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "ES256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_ES256(b *testing.B) {
	privatePEM, publicPEM, _ := generateECDSAKeyPair(elliptic.P256())
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "ES256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_ES384(t *testing.T) {
	privatePEM, publicPEM, err := generateECDSAKeyPair(elliptic.P384())
	assert.NoError(t, err, "ECDSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "ES384",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_ES384(b *testing.B) {
	privatePEM, publicPEM, _ := generateECDSAKeyPair(elliptic.P384())
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "ES256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}

func TestJWTPayload_sign_verify_renew_ES512(t *testing.T) {
	privatePEM, publicPEM, err := generateECDSAKeyPair(elliptic.P521())
	assert.NoError(t, err, "ECDSA key generation should not return an error")
	assert.NotEmpty(t, privatePEM, "should have a private key")
	assert.NotEmpty(t, publicPEM, "should have a public key")

	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "ES512",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	authToken, refreshToken, err := jwtPayload.Sign()
	assert.NoError(t, err)
	assert.NotEmpty(t, authToken, "Auth token should not be empty")
	assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtSignedPayload := JWTSignedPayload{
		Jid:       jwtPayload.Jid,
		Kid:       jwtPayload.Kid,
		AppID:     jwtPayload.AppID,
		Algo:      jwtPayload.Algo,
		Token:     authToken,
		PublicKey: jwtPayload.PublicKey,
	}

	// Verify Auth Token
	valid, err := jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify Refresh Token
	jwtSignedPayload.Token = refreshToken
	valid, err = jwtSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	//setup payload for the auth token and refresh token renew
	jwtRenewPayload := JWTRenewPayload{
		PrivateKey:    jwtPayload.PrivateKey,
		PublicKey:     jwtPayload.PublicKey,
		TokenIssue:    jwtPayload.TokenIssue,
		TokenExpiry:   jwtPayload.TokenExpiry,
		TokenNbf:      jwtPayload.TokenNbf,
		RefreshIssue:  jwtPayload.RefreshIssue,
		RefreshExpiry: jwtPayload.RefreshExpiry,
		RefreshNbf:    jwtPayload.RefreshNbf,
		Algo:          jwtPayload.Algo,
		AuthToken:     authToken,
		RefreshToken:  refreshToken,
		AppID:         jwtPayload.AppID,
		AppName:       jwtPayload.AppName,
		Jid:           jwtPayload.Jid,
		Kid:           jwtPayload.Kid,
	}

	//test the token renew - it should pass
	newAuthToken, newRefreshToken, err := jwtRenewPayload.Renew()
	assert.NoError(t, err)
	assert.NotEmpty(t, newAuthToken, "New Auth token should not be empty")
	assert.NotEmpty(t, newRefreshToken, "New Refresh token should not be empty")

	//Prepare payload for JWT verification
	jwtNewSignedPayload := JWTSignedPayload{
		Jid:       jwtRenewPayload.Jid,
		Kid:       jwtRenewPayload.Kid,
		AppID:     jwtRenewPayload.AppID,
		Algo:      jwtRenewPayload.Algo,
		Token:     newAuthToken,
		PublicKey: jwtRenewPayload.PublicKey,
	}

	// Verify new Auth Token
	validNew, err := jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, validNew)

	// Verify new Refresh Token
	jwtNewSignedPayload.Token = newRefreshToken
	valid, err = jwtNewSignedPayload.Verify()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and correct public key
	jwtSignedPayload.Token = "INVALID-AUTH-TOKEN"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the invalid JWT Token and invalid public key
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	// Fail the auth token verification by sending the valid JWT Token but invalid public key
	jwtSignedPayload.Token = authToken
	jwtSignedPayload.PublicKey = "INVALID-PUBLIC-KEY"
	valid, err = jwtSignedPayload.Verify()
	assert.Error(t, err)
	assert.False(t, valid)

	jwtPayload.Algo = "INVALID-ALGO"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid algorithm")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid algorithm")

	jwtPayload.PrivateKey = "INVALID-PRIVATE-KEY"
	authToken, refreshToken, err = jwtPayload.Sign()
	assert.Error(t, err)
	assert.Empty(t, authToken, "Auth token should be empty for invalid private key")
	assert.Empty(t, refreshToken, "Refresh token should be empty for invalid private key")
}

func BenchmarkPayload_sign_ES512(b *testing.B) {
	privatePEM, publicPEM, _ := generateECDSAKeyPair(elliptic.P521())
	jwtPayload := JWTPayload{
		PrivateKey:    privatePEM,
		PublicKey:     publicPEM,
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Hour).Unix(),
		TokenNbf:      time.Now().Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Hour).Unix(),
		RefreshNbf:    time.Now().Unix(),
		Algo:          "ES256",
		Body:          []byte(`{"sub":"test"}`),
		AppID:         GenUlid(),
		AppName:       "test",
		Jid:           GenUlid(),
		Kid:           GenUlid(),
	}

	for n := 0; n < b.N; n++ {
		b.ReportAllocs()
		jwtPayload.Sign()
	}
}
