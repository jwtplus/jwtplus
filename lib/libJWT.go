package lib

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type JWTPayload struct {
	PrivateKey    string
	PublicKey     string
	TokenIssue    int64
	TokenExpiry   int64
	TokenNbf      int64
	RefreshIssue  int64
	RefreshExpiry int64
	RefreshNbf    int64
	Algo          string
	Body          []byte
	AppID         string
	AppName       string
	Jid           string
	Kid           string
}

type JWTSignedPayload struct {
	Jid        string
	Kid        string
	AppID      string
	Algo       string
	Token      string
	PublicKey  string
	PrivateKey string
}

type JWTRenewPayload struct {
	PrivateKey    string
	PublicKey     string
	TokenIssue    int64
	TokenExpiry   int64
	TokenNbf      int64
	RefreshIssue  int64
	RefreshExpiry int64
	RefreshNbf    int64
	Algo          string
	AuthToken     string
	RefreshToken  string
	AppID         string
	AppName       string
	Jid           string
	Kid           string
}

func getSigningMethod(algo string) (jwt.SigningMethod, error) {
	signMethods := map[string]jwt.SigningMethod{
		"RS256": jwt.SigningMethodRS256, "RS384": jwt.SigningMethodRS384, "RS512": jwt.SigningMethodRS512,
		"PS256": jwt.SigningMethodPS256, "PS384": jwt.SigningMethodPS384, "PS512": jwt.SigningMethodPS512,
		"ES256": jwt.SigningMethodES256, "ES384": jwt.SigningMethodES384, "ES512": jwt.SigningMethodES512,
	}

	if method, exists := signMethods[algo]; exists {
		return method, nil
	}

	return nil, fmt.Errorf("invalid algorithm: %s", algo)
}

func getParsePrivateKey(algo string, privateKey string) (interface{}, error) {
	switch algo {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))

	case "ES256", "ES384", "ES512":
		return jwt.ParseECPrivateKeyFromPEM([]byte(privateKey))
	default:
		return nil, fmt.Errorf("invalid algorithm: %s", algo)
	}
}

func getParsePublicKey(algo string, publicKey string) (interface{}, error) {
	switch algo {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

	case "ES256", "ES384", "ES512":
		return jwt.ParseECPublicKeyFromPEM([]byte(publicKey))
	default:
		return nil, fmt.Errorf("invalid algorithm: %s", algo)
	}
}

func (j *JWTPayload) compileClaims() (jwt.MapClaims, jwt.MapClaims, error) {
	var jsonBody map[string]interface{}
	err := json.Unmarshal(j.Body, &jsonBody)
	if err != nil {
		return jwt.MapClaims{}, jwt.MapClaims{}, err
	}

	var authClaims jwt.MapClaims = make(jwt.MapClaims)
	authClaims["jid"] = j.Jid
	authClaims["iat"] = j.TokenIssue
	authClaims["nbf"] = j.TokenNbf
	authClaims["exp"] = j.TokenExpiry
	authClaims["iss"] = j.AppName
	for key, value := range jsonBody {
		authClaims[key] = value
	}

	var refreshClaims jwt.MapClaims = make(jwt.MapClaims)
	refreshClaims["jid"] = j.Jid
	refreshClaims["iat"] = j.RefreshIssue
	refreshClaims["nbf"] = j.RefreshNbf
	refreshClaims["exp"] = j.RefreshExpiry
	refreshClaims["iss"] = j.AppName
	refreshClaims["type"] = "refresh"

	return authClaims, refreshClaims, nil
}

func (j *JWTPayload) Sign() (string, string, error) {
	var signMethod jwt.SigningMethod
	var privateKey interface{}
	var err error

	if signMethod, err = getSigningMethod(j.Algo); err != nil {
		return "", "", err
	}

	if privateKey, err = getParsePrivateKey(j.Algo, j.PrivateKey); err != nil {
		return "", "", err
	}

	authClaims, refreshClaims, err := j.compileClaims()
	if err != nil {
		return "", "", err
	}

	authToken := jwt.NewWithClaims(signMethod, authClaims)
	authToken.Header["kid"] = j.Kid
	authTokenSigned, err := authToken.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	refreshToken := jwt.NewWithClaims(signMethod, refreshClaims)
	refreshToken.Header["kid"] = j.Kid
	refreshTokenSigned, err := refreshToken.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	return authTokenSigned, refreshTokenSigned, nil
}

func (j *JWTSignedPayload) Verify() (bool, error) {
	var publicKey interface{}
	var err error

	if publicKey, err = getParsePublicKey(j.Algo, j.PublicKey); err != nil {
		return false, err
	}

	parsedToken, err := jwt.Parse(j.Token, func(token *jwt.Token) (interface{}, error) {

		switch j.Algo {
		case "RS256", "RS384", "RS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		case "PS256", "PS384", "PS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		case "ES256", "ES384", "ES512":
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		default:
			return false, errors.New(fmt.Sprintf("invalid algo at %s", j.Algo))
		}

		return publicKey, nil
	})

	if err != nil {
		return false, err
	}

	if parsedToken.Valid {
		return true, nil
	}

	return false, nil
}

func (j *JWTRenewPayload) compileRenewClaims(oldClaims jwt.MapClaims) (jwt.MapClaims, jwt.MapClaims, error) {

	var authClaims jwt.MapClaims = oldClaims
	authClaims["jid"] = j.Jid
	authClaims["iat"] = j.TokenIssue
	authClaims["nbf"] = j.TokenNbf
	authClaims["exp"] = j.TokenExpiry
	authClaims["iss"] = j.AppName

	var refreshClaims jwt.MapClaims = make(jwt.MapClaims)
	refreshClaims["jid"] = j.Jid
	refreshClaims["iat"] = j.RefreshIssue
	refreshClaims["nbf"] = j.RefreshNbf
	refreshClaims["exp"] = j.RefreshExpiry
	refreshClaims["iss"] = j.AppName
	refreshClaims["type"] = "refresh"

	return authClaims, refreshClaims, nil
}

func (j *JWTRenewPayload) Renew() (string, string, error) {
	var signMethod jwt.SigningMethod
	var privateKey interface{}
	var publicKey interface{}
	var err error

	if signMethod, err = getSigningMethod(j.Algo); err != nil {
		return "", "", err
	}

	if privateKey, err = getParsePrivateKey(j.Algo, j.PrivateKey); err != nil {
		return "", "", err
	}

	if publicKey, err = getParsePublicKey(j.Algo, j.PublicKey); err != nil {
		return "", "", err
	}

	parsedAuthToken, errRefresh := jwt.Parse(j.RefreshToken, func(token *jwt.Token) (interface{}, error) {

		switch j.Algo {
		case "RS256", "RS384", "RS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		case "PS256", "PS384", "PS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		case "ES256", "ES384", "ES512":
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		default:
			return false, errors.New(fmt.Sprintf("invalid algo at %s", j.Algo))
		}

		return publicKey, nil
	})

	if errRefresh != nil {
		return "", "", errRefresh
	}

	if !parsedAuthToken.Valid {
		return "", "", errors.New("refresh token is no longer valid or its too early to renew")
	}

	claimsRefresh := parsedAuthToken.Claims.(jwt.MapClaims)
	if claimsRefresh["type"] != "refresh" {
		return "", "", errors.New("submitted token is not a refresh jwt token")
	}

	parsedAuthToken, errAuth := jwt.Parse(j.AuthToken, func(token *jwt.Token) (interface{}, error) {

		switch j.Algo {
		case "RS256", "RS384", "RS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		case "PS256", "PS384", "PS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		case "ES256", "ES384", "ES512":
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return false, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		default:
			return false, errors.New(fmt.Sprintf("invalid algo at %s", j.Algo))
		}

		return publicKey, nil
	})

	if errAuth != nil {
		return "", "", err
	}

	claimsAuth := parsedAuthToken.Claims.(jwt.MapClaims)

	authClaims, refreshClaims, err := j.compileRenewClaims(claimsAuth)
	if err != nil {
		return "", "", err
	}

	authToken := jwt.NewWithClaims(signMethod, authClaims)
	authToken.Header["kid"] = j.Kid
	authTokenSigned, err := authToken.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	refreshToken := jwt.NewWithClaims(signMethod, refreshClaims)
	refreshToken.Header["kid"] = j.Kid
	refreshTokenSigned, err := refreshToken.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}
	return authTokenSigned, refreshTokenSigned, err
}
