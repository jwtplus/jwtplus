package controllers

import (
	"bytes"
	"context"
	"errors"
	"io"
	db "jwtplus/db/sqlc"
	"jwtplus/lib"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func AppGetInfo(c *gin.Context) {
	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "get-app-info").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)
	appInfo, err := q.GetAppByID(context.Background(), c.GetString("app-id"))
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "get-app-info").
			Str("component", "fetch record").
			Msg("error in select query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	type appCleaned struct {
		Id             string         `json:"id"`
		Name           string         `json:"name"`
		Desc           string         `json:"description"`
		TokenExpiry    int32          `json:"token_expiry"`
		TokenNbf       int32          `json:"token_notbefore"`
		RefreshExpiry  int32          `json:"refresh_expiry"`
		RefreshNbf     int32          `json:"refresh_notbefore"`
		KeyType        db.AppsKeyType `json:"key_type"`
		Algo           db.AppsAlgo    `json:"algo"`
		RotationPeriod int64          `json:"rotation_period"`
		AddTime        int64          `json:"add_time"`
		UpdateTime     int64          `json:"update_time"`
		KeyRotateTime  int64          `json:"last_key_rotate"`
	}

	var d string = ""
	if appInfo.AppDescription.Valid {
		d = appInfo.AppDescription.String
	}

	var u int64 = 0
	if appInfo.UpdateTime.Valid {
		u = appInfo.UpdateTime.Int64
	}

	var r int64 = 0
	if appInfo.LastRotateTime.Valid {
		r = appInfo.LastRotateTime.Int64
	}

	appTransformed := appCleaned{
		Id:             appInfo.AppID,
		Name:           appInfo.AppName,
		Desc:           d,
		TokenExpiry:    appInfo.TokenExpiry,
		TokenNbf:       appInfo.TokenNbf,
		RefreshExpiry:  appInfo.RefreshExpiry,
		RefreshNbf:     appInfo.RefreshNbf,
		KeyType:        appInfo.KeyType,
		Algo:           appInfo.Algo,
		RotationPeriod: appInfo.RotationPeriod,
		AddTime:        appInfo.AddTime,
		UpdateTime:     u,
		KeyRotateTime:  r,
	}

	c.JSON(http.StatusOK, gin.H{
		"app": appTransformed,
	})
}

func AppGetPublicKeys(c *gin.Context) {
	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "app-jwks").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)
	keys, err := q.GetPublicKeysByAppId(context.Background(), c.GetString("app-id"))
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "app-jwks").
			Str("component", "fetch-keys").
			Msg("error in fetch query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}

func AppJWTSign(c *gin.Context) {

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "get-body").
			Msg("error in reading submitted data")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	// Reset request body for future use
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	var postParams struct {
		Sub       string `json:"sub" binding:"required"`
		Aud       string `json:"aud" binding:"required"`
		Ip        string `json:"ip" binding:"required,ip"`
		UserAgent string `json:"useragent" binding:"required"`
	}

	if err := c.ShouldBindJSON(&postParams); err != nil {

		// Check if no body is submitted
		if errors.Is(err, io.EOF) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "empty request body"})
			return
		}

		// Check if the submitted json is decodeable
		parseError := lib.PayloadParsingError(err)
		if len(parseError.Message) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": parseError})
			return
		}

		// Check if all the required fields are present & validated
		errors := lib.RestErrors(err)
		if len(errors) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": errors})
			return
		}
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	appKeyPair, err := q.GetAppForSigning(context.Background(), c.GetString("app-id"))

	if err != nil {
		log.Error().
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "fetch-record").
			Err(err).
			Msg("failed to query database")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	JWTPayload := lib.JWTPayload{
		PublicKey:     lib.DecodeB64(appKeyPair.PublicKey.String),
		PrivateKey:    lib.DecodeB64(appKeyPair.PrivateKey.String),
		Algo:          string(appKeyPair.Algo),
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Second * time.Duration(appKeyPair.TokenExpiry)).Unix(),
		TokenNbf:      time.Now().Add(time.Second * time.Duration(appKeyPair.TokenNbf)).Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Second * time.Duration(appKeyPair.RefreshExpiry)).Unix(),
		RefreshNbf:    time.Now().Add(time.Second * time.Duration(appKeyPair.RefreshNbf)).Unix(),
		AppID:         appKeyPair.AppID,
		AppName:       appKeyPair.AppName,
		Jid:           lib.GenUlid(),
		Kid:           appKeyPair.KeyID.String,
		Body:          body,
	}

	authToken, refreshToken, jErr := JWTPayload.Sign()
	if jErr != nil {
		log.Error().
			Err(jErr).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "sign-jwt").
			Msg("error in signing jwt")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	tokeInsertErr := q.InsertToken(context.Background(), db.InsertTokenParams{
		TokenID:          JWTPayload.Jid,
		AppsID:           JWTPayload.AppID,
		KeyID:            JWTPayload.Kid,
		Sub:              lib.GetSHA512Hash(postParams.Sub),
		AuthToken:        authToken,
		AuthTokenHash:    lib.GetSHA512Hash(authToken),
		AuthTokenIat:     JWTPayload.TokenIssue,
		AuthTokenNbf:     JWTPayload.TokenNbf,
		AuthTokenExp:     JWTPayload.TokenExpiry,
		RefreshToken:     refreshToken,
		RefreshTokenHash: lib.GetSHA512Hash(refreshToken),
		RefreshTokenIat:  JWTPayload.RefreshIssue,
		RefreshTokenNbf:  JWTPayload.RefreshNbf,
		RefreshTokenExp:  JWTPayload.RefreshExpiry,
		IpAddress:        postParams.Ip,
		UserAgent:        postParams.UserAgent,
	})

	if tokeInsertErr != nil {
		log.Error().
			Err(tokeInsertErr).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "insert-token").
			Msg("error in insert query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"key_id":        JWTPayload.Kid,
		"public_key":    lib.EncodeB64(JWTPayload.PublicKey),
		"auth_token":    authToken,
		"refresh_token": refreshToken,
	})
}

func AppJWTVerify(c *gin.Context) {
	var postParams struct {
		Token string `json:"token" binding:"required,jwt"`
	}

	if err := c.ShouldBindJSON(&postParams); err != nil {

		// Check if no body is submitted
		if errors.Is(err, io.EOF) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "empty request body"})
			return
		}

		// Check if the submitted json is decodeable
		parseError := lib.PayloadParsingError(err)
		if len(parseError.Message) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": parseError})
			return
		}

		// Check if all the required fields are present & validated
		errors := lib.RestErrors(err)
		if len(errors) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": errors})
			return
		}
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "verify-jwt").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	result, err := q.GetTokenByAuthHash(context.Background(), db.GetTokenByAuthHashParams{
		AppsID:        c.GetString("app-id"),
		AuthTokenHash: lib.GetSHA512Hash(postParams.Token),
		AuthTokenExp:  time.Now().Unix(),
		AuthTokenNbf:  time.Now().Unix(),
	})

	if err != nil && err.Error() != "sql: no rows in result set" {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "verify-jwt").
			Str("component", "fetch-records").
			Msg("error in fetch query")
		c.JSON(http.StatusOK, gin.H{
			"verified": false,
		})
		return
	}

	signedPayload := lib.JWTSignedPayload{
		AppID:     result.AppsID,
		Jid:       result.TokenID,
		Kid:       result.KeyID,
		Algo:      string(result.KeyAlgo.AppKeysKeyAlgo),
		Token:     postParams.Token,
		PublicKey: lib.DecodeB64(result.PublicKey.String),
	}

	isValid, err := signedPayload.Verify()
	if err != nil || !isValid {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "verify-jwt").
			Str("component", "verify-jwt").
			Msg("error in signature verification")
		c.JSON(http.StatusOK, gin.H{
			"verified": false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"verified": true,
	})
	return
}

func AppJwtRenew(c *gin.Context) {
	var postParams struct {
		RefreshToken string `json:"refresh_token" binding:"required,jwt"`
		Ip           string `json:"ip" binding:"required,ip"`
		UserAgent    string `json:"useragent" binding:"required"`
	}

	if err := c.ShouldBindJSON(&postParams); err != nil {

		// Check if no body is submitted
		if errors.Is(err, io.EOF) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "empty request body"})
			return
		}

		// Check if the submitted json is decodeable
		parseError := lib.PayloadParsingError(err)
		if len(parseError.Message) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": parseError})
			return
		}

		// Check if all the required fields are present & validated
		errors := lib.RestErrors(err)
		if len(errors) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": errors})
			return
		}
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "renew-jwt").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	tx, txErr := dbConnection.Begin()
	if txErr != nil {
		log.Error().
			Err(txErr).
			Str("system", "app-controller").
			Str("sub-system", "renew-jwt").
			Str("component", "txn begin").
			Msg("error in starting txn")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer tx.Rollback()

	qtx := q.WithTx(tx)

	getRefreshTokenDetails, err := qtx.GetTokenByRefreshHash(context.Background(), db.GetTokenByRefreshHashParams{
		AppsID:           c.GetString("app-id"),
		RefreshTokenHash: lib.GetSHA512Hash(postParams.RefreshToken),
		RefreshTokenExp:  time.Now().Unix(),
		RefreshTokenNbf:  time.Now().Unix(),
	})

	if err != nil && err.Error() != "sql: no rows in result set" {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "renew-jwt").
			Str("component", "fetch-records").
			Msg("error in fetch query")
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"message": "error",
		})
		return
	}

	if err != nil && err.Error() == "sql: no rows in result set" {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"message": "invalid refresh token",
		})
		return
	}

	signedPayload := lib.JWTSignedPayload{
		AppID:     getRefreshTokenDetails.AppsID,
		Jid:       getRefreshTokenDetails.TokenID,
		Kid:       getRefreshTokenDetails.KeyID,
		Algo:      string(getRefreshTokenDetails.KeyAlgo.AppKeysKeyAlgo),
		Token:     postParams.RefreshToken,
		PublicKey: lib.DecodeB64(getRefreshTokenDetails.PublicKey.String),
	}

	isValid, err := signedPayload.Verify()
	if err != nil || !isValid {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "renew-jwt").
			Str("component", "verify-refresh-token").
			Msg("error in signature verification")
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"message": "invalid refresh token",
		})
		return
	}

	getActiveKey, err := qtx.GetAppForSigning(context.Background(), c.GetString("app-id"))
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "renew-jwt").
			Str("component", "fetch-active-key").
			Msg("error in fetching active key query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	renewPayload := lib.JWTRenewPayload{
		PublicKey:     lib.DecodeB64(getActiveKey.PublicKey.String),
		PrivateKey:    lib.DecodeB64(getActiveKey.PrivateKey.String),
		Algo:          string(getActiveKey.Algo),
		TokenIssue:    time.Now().Unix(),
		TokenExpiry:   time.Now().Add(time.Second * time.Duration(getActiveKey.TokenExpiry)).Unix(),
		TokenNbf:      time.Now().Add(time.Second * time.Duration(getActiveKey.TokenNbf)).Unix(),
		RefreshIssue:  time.Now().Unix(),
		RefreshExpiry: time.Now().Add(time.Second * time.Duration(getActiveKey.RefreshExpiry)).Unix(),
		RefreshNbf:    time.Now().Add(time.Second * time.Duration(getActiveKey.RefreshNbf)).Unix(),
		AppID:         getActiveKey.AppID,
		AppName:       getActiveKey.AppName,
		Jid:           lib.GenUlid(),
		Kid:           getActiveKey.KeyID.String,
		AuthToken:     getRefreshTokenDetails.AuthToken,
		RefreshToken:  postParams.RefreshToken,
	}

	authToken, refreshToken, jErr := renewPayload.Renew()
	if jErr != nil {
		log.Error().
			Err(jErr).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "sign-jwt").
			Msg("error in signing jwt")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	tokeInsertErr := qtx.InsertToken(context.Background(), db.InsertTokenParams{
		TokenID:          renewPayload.Jid,
		AppsID:           renewPayload.AppID,
		KeyID:            renewPayload.Kid,
		Sub:              getRefreshTokenDetails.Sub,
		AuthToken:        authToken,
		AuthTokenHash:    lib.GetSHA512Hash(authToken),
		AuthTokenIat:     renewPayload.TokenIssue,
		AuthTokenNbf:     renewPayload.TokenNbf,
		AuthTokenExp:     renewPayload.TokenExpiry,
		RefreshToken:     refreshToken,
		RefreshTokenHash: lib.GetSHA512Hash(refreshToken),
		RefreshTokenIat:  renewPayload.RefreshIssue,
		RefreshTokenNbf:  renewPayload.RefreshNbf,
		RefreshTokenExp:  renewPayload.RefreshExpiry,
		IpAddress:        postParams.Ip,
		UserAgent:        postParams.UserAgent,
	})

	if tokeInsertErr != nil {
		log.Error().
			Err(tokeInsertErr).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "insert-new-token").
			Msg("error in insert query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	deleteOldTokenErr := qtx.DeleteTokenByTokenId(context.Background(), db.DeleteTokenByTokenIdParams{
		AppsID:  c.GetString("app-id"),
		TokenID: getRefreshTokenDetails.TokenID,
	})

	if deleteOldTokenErr != nil {
		log.Error().
			Err(deleteOldTokenErr).
			Str("system", "app-controller").
			Str("sub-system", "sign-jwt").
			Str("component", "delete-old-token").
			Msg("error in delete query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{
		"key_id":        renewPayload.Kid,
		"public_key":    lib.EncodeB64(renewPayload.PublicKey),
		"auth_token":    authToken,
		"refresh_token": refreshToken,
	})
}

func AppGetActiveSessions(c *gin.Context) {
	var postParams struct {
		Sub string `json:"sub" binding:"required"`
	}

	if err := c.ShouldBindJSON(&postParams); err != nil {

		// Check if no body is submitted
		if errors.Is(err, io.EOF) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "empty request body"})
			return
		}

		// Check if the submitted json is decodeable
		parseError := lib.PayloadParsingError(err)
		if len(parseError.Message) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": parseError})
			return
		}

		// Check if all the required fields are present & validated
		errors := lib.RestErrors(err)
		if len(errors) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": errors})
			return
		}
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "get-session").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	sessions, err := q.GetActiveSessionAgainstSubject(context.Background(), db.GetActiveSessionAgainstSubjectParams{
		AppsID:       c.GetString("app-id"),
		Sub:          lib.GetSHA512Hash(postParams.Sub),
		AuthTokenExp: time.Now().Unix(),
		AuthTokenNbf: time.Now().Unix(),
	})

	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "get-session").
			Str("component", "fetch-record").
			Msg("error in fetch query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": sessions,
	})
}

func AppDoLogout(c *gin.Context) {

	var postParams struct {
		Token string `json:"token" binding:"required,jwt"`
	}

	if err := c.ShouldBindJSON(&postParams); err != nil {

		// Check if no body is submitted
		if errors.Is(err, io.EOF) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "empty request body"})
			return
		}

		// Check if the submitted json is decodeable
		parseError := lib.PayloadParsingError(err)
		if len(parseError.Message) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": parseError})
			return
		}

		// Check if all the required fields are present & validated
		errors := lib.RestErrors(err)
		if len(errors) > 0 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": errors})
			return
		}
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "app-controller").
			Str("sub-system", "logout").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	deleteStatus := q.DeleteTokenByAuthTokenHash(context.Background(), db.DeleteTokenByAuthTokenHashParams{
		AppsID:        c.GetString("app-id"),
		AuthTokenHash: lib.GetSHA512Hash(postParams.Token),
	})

	if deleteStatus != nil {
		log.Error().
			Err(deleteStatus).
			Str("system", "app-controller").
			Str("sub-system", "logout").
			Str("component", "delete-query").
			Msg("error in delete query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
	return
}
