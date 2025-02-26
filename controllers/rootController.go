package controllers

import (
	"context"
	"database/sql"
	"errors"
	"io"
	db "jwtplus/db/sqlc"
	"jwtplus/lib"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func RotateRootKey(c *gin.Context) {
	key, err := lib.GenRandomString(128)
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "rotate-root-key").
			Str("component", "get-random").
			Msg("error in root key creation")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	keyHash := lib.GetSHA512Hash(key)

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Str("system", "root-controller").
			Str("sub-system", "rotate-root-key").
			Str("component", "connect").
			Err(err).
			Msg("db connection error")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()
	q := db.New(dbConnection)

	sqlErr := q.UpdateSettingByKey(context.Background(), db.UpdateSettingByKeyParams{
		SettingKey:   "ROOT-KEY",
		SettingValue: keyHash,
	})

	if sqlErr != nil {
		log.Error().
			Str("system", "root-controller").
			Str("sub-system", "rotate-root-key").
			Str("component", "update-table").
			Err(err).
			Msg("sql error")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"new-key": key,
	})

	return
}

func GetAllApps(c *gin.Context) {
	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "get-all-app").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)
	apps, err := q.GetAllApp(context.Background())
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "get-all-app").
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

	appsTransformed := make([]appCleaned, len(apps))
	for i, j := range apps {
		var d string = ""
		if j.AppDescription.Valid {
			d = j.AppDescription.String
		}

		var u int64 = 0
		if j.UpdateTime.Valid {
			u = j.UpdateTime.Int64
		}

		var r int64 = 0
		if j.LastRotateTime.Valid {
			r = j.LastRotateTime.Int64
		}
		appsTransformed[i] = appCleaned{
			Id:             j.AppID,
			Name:           j.AppName,
			Desc:           d,
			TokenExpiry:    j.TokenExpiry,
			TokenNbf:       j.TokenNbf,
			RefreshExpiry:  j.RefreshExpiry,
			RefreshNbf:     j.RefreshNbf,
			KeyType:        j.KeyType,
			Algo:           j.Algo,
			RotationPeriod: j.RotationPeriod,
			AddTime:        j.AddTime,
			UpdateTime:     u,
			KeyRotateTime:  r,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"apps": appsTransformed,
	})
}

func CreateApp(c *gin.Context) {
	var postParams struct {
		AppName        string `json:"name" binding:"required,alphawithspace"`
		AppDesc        string `json:"description" binding:"omitempty,alphawithspace"`
		TokenExp       int    `json:"token_expire" binding:"required,number,min=60,max=31536000"`
		TokenNbf       int    `json:"token_notbefore" binding:"omitempty,number,min=0,max=31536000"`
		RefreshExp     int    `json:"refresh_expire" binding:"required,number,min=60,max=31536000"`
		RefreshNbf     int    `json:"refresh_notbefore" binding:"required,number,min=60,max=31536000"`
		KeyType        string `json:"key_type" binding:"required,oneof=RSA ECDSA"`
		Algo           string `json:"algo" binding:"required,oneof=RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512"`
		RotationPeriod int    `json:"rotation_period" binding:"required,number,min=60,max=31536000"`
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

	if postParams.Algo == "RSA" && (postParams.KeyType == "ES256" || postParams.KeyType == "ES384" || postParams.KeyType == "ES512") {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "for RSA, please select from RS256, RS384, RS512, PS256, PS384, PS512 only"})
		return
	}

	if postParams.Algo == "ECDSA" && (postParams.KeyType == "RS256" || postParams.KeyType == "RS384" || postParams.KeyType == "RS512" || postParams.KeyType == "PS256" || postParams.KeyType == "PS384" || postParams.KeyType == "PS512") {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "for ECDSA, please select from ES256, ES384, ES512 only"})
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	appId := lib.GenUlid()
	appKey, randomErr := lib.GenRandomString(128)
	if randomErr != nil {
		log.Error().
			Err(randomErr).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "generate app key").
			Msg("error in generating app key")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	privateKey, publicKey, keyError := lib.GenerateKeyPair(postParams.Algo)
	if keyError != nil {
		log.Error().
			Err(keyError).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "public-private key").
			Msg("error in generating public-private key pair")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	var appDesc = sql.NullString{
		String: "",
		Valid:  false,
	}

	if len(postParams.AppDesc) > 0 {
		appDesc = sql.NullString{
			String: postParams.AppDesc,
			Valid:  true,
		}
	}

	tx, txErr := dbConnection.Begin()
	if txErr != nil {
		log.Error().
			Err(txErr).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "txn").
			Msg("error in starting txn")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer tx.Rollback()

	qtx := q.WithTx(tx)
	insertAppErr := qtx.InsertApp(context.Background(), db.InsertAppParams{
		AppID:          appId,
		AppName:        postParams.AppName,
		AppDescription: appDesc,
		AppKey:         lib.GetSHA512Hash(appKey),
		TokenExpiry:    int32(postParams.TokenExp),
		TokenNbf:       int32(postParams.TokenNbf),
		RefreshExpiry:  int32(postParams.RefreshExp),
		RefreshNbf:     int32(postParams.RefreshNbf),
		KeyType:        db.AppsKeyType(postParams.KeyType),
		Algo:           db.AppsAlgo(postParams.Algo),
		RotationPeriod: int64(postParams.RotationPeriod),
		AddTime:        int64(time.Now().Unix()),
	})

	if insertAppErr != nil {
		log.Error().
			Err(insertAppErr).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "insert-app").
			Msg("error in insert app query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	insertKeyErr := qtx.InsertKey(context.Background(), db.InsertKeyParams{
		KeyID:      lib.GenUlid(),
		AppID:      appId,
		PublicKey:  lib.EncodeB64(publicKey),
		PrivateKey: lib.EncodeB64(privateKey),
		KeyType:    db.AppKeysKeyType(postParams.KeyType),
		KeyAlgo:    db.AppKeysKeyAlgo(postParams.Algo),
		ExpTime:    time.Now().Add(time.Second * time.Duration(postParams.RotationPeriod)).Unix(),
		AddTime:    time.Now().Unix(),
	})
	if insertKeyErr != nil {
		log.Error().
			Err(insertKeyErr).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "insert-key").
			Msg("error in insert key query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	tx.Commit()

	c.JSON(http.StatusOK, gin.H{
		"app_id":     appId,
		"app_key":    appKey,
		"public_key": lib.EncodeB64(publicKey),
		"algo":       postParams.Algo,
	})
	return
}

func UpdateApp(c *gin.Context) {

	var paramURI struct {
		AppId string `uri:"app_id" binding:"required,ulid"`
	}

	if err := c.ShouldBindUri(&paramURI); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "invalid app id"})
		return
	}

	var postParams struct {
		AppName        string `json:"name" binding:"required,alphawithspace"`
		AppDesc        string `json:"description" binding:"omitempty,alphawithspace"`
		TokenExp       int    `json:"token_expire" binding:"required,number,min=60,max=31536000"`
		TokenNbf       int    `json:"token_notbefore" binding:"omitempty,number,min=0,max=31536000"`
		RefreshExp     int    `json:"refresh_expire" binding:"required,number,min=60,max=31536000"`
		RefreshNbf     int    `json:"refresh_notbefore" binding:"required,number,min=60,max=31536000"`
		RotationPeriod int    `json:"rotation_period" binding:"required,number,min=60,max=31536000"`
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
			Str("system", "root-controller").
			Str("sub-system", "update-app").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	var appDesc = sql.NullString{
		String: "",
		Valid:  false,
	}

	if len(postParams.AppDesc) > 0 {
		appDesc = sql.NullString{
			String: postParams.AppDesc,
			Valid:  true,
		}
	}

	resultErr := q.UpdateAppById(context.Background(), db.UpdateAppByIdParams{
		AppName:        postParams.AppName,
		AppDescription: appDesc,
		TokenExpiry:    int32(postParams.TokenExp),
		TokenNbf:       int32(postParams.TokenNbf),
		RefreshExpiry:  int32(postParams.RefreshExp),
		RefreshNbf:     int32(postParams.RefreshNbf),
		UpdateTime: sql.NullInt64{
			Int64: int64(time.Now().Unix()),
			Valid: true,
		},
		RotationPeriod: int64(postParams.RotationPeriod),
		AppID:          paramURI.AppId,
	})

	if resultErr != nil {
		log.Error().
			Err(resultErr).
			Str("system", "root-controller").
			Str("sub-system", "update-app").
			Str("component", "update").
			Msg("error in update query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
	return
}

func DeleteApp(c *gin.Context) {
	var paramURI struct {
		AppId string `uri:"app_id" binding:"required,ulid"`
	}

	if err := c.ShouldBindUri(&paramURI); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "invalid app id"})
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "delete-app").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)
	resultErr := q.DeleteAppById(context.Background(), paramURI.AppId)
	if resultErr != nil {
		log.Error().
			Err(resultErr).
			Str("system", "root-controller").
			Str("sub-system", "delete-app").
			Str("component", "delete").
			Msg("error in delete query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
	return
}

func RotateAppKey(c *gin.Context) {
	var paramURI struct {
		AppId string `uri:"app_id" binding:"required,ulid"`
	}

	if err := c.ShouldBindUri(&paramURI); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "invalid app id"})
		return
	}

	appKey, randomErr := lib.GenRandomString(128)
	if randomErr != nil {
		log.Error().
			Err(randomErr).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-key").
			Str("component", "generate new app key").
			Msg("error in generating new app key")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-key").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	resultErr := q.RotateAppKeyById(context.Background(), db.RotateAppKeyByIdParams{
		AppKey: lib.GetSHA512Hash(appKey),
		UpdateTime: sql.NullInt64{
			Int64: int64(time.Now().Unix()),
			Valid: true,
		},
		AppID: paramURI.AppId,
	})
	if resultErr != nil {
		log.Error().
			Err(resultErr).
			Str("system", "root-controller").
			Str("sub-system", "create-app").
			Str("component", "insert").
			Msg("error in insert query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"app_id":  paramURI.AppId,
		"app_key": appKey,
	})
	return
}

func RotateAppPKI(c *gin.Context) {

	var paramURI struct {
		AppId string `uri:"app_id" binding:"required,ulid"`
	}

	if err := c.ShouldBindUri(&paramURI); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "invalid app id"})
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	appInfo, err := q.GetAppByID(context.Background(), paramURI.AppId)
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "reading app details").
			Msg("error in select query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	privateKey, publicKey, keyError := lib.GenerateKeyPair(string(appInfo.Algo))
	if keyError != nil {
		log.Error().
			Err(keyError).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "public-private key").
			Msg("error in generating public-private key pair")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	tx, txErr := dbConnection.Begin()
	if txErr != nil {
		log.Error().
			Err(txErr).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "txn").
			Msg("error in starting txn")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer tx.Rollback()

	qtx := q.WithTx(tx)
	updateErr := qtx.UpdatePKIRotationTime(context.Background(), db.UpdatePKIRotationTimeParams{
		LastRotateTime: sql.NullInt64{
			Int64: int64(time.Now().Unix()),
			Valid: true,
		},
		AppID: appInfo.AppID,
	})

	if updateErr != nil {
		log.Error().
			Err(updateErr).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "update-app").
			Msg("error in update app query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	deactiveKeyErr := qtx.ExpireActiveKey(context.Background(), db.ExpireActiveKeyParams{
		AppID:     appInfo.AppID,
		IsExpired: db.AppKeysIsExpired("yes"),
	})
	if deactiveKeyErr != nil {
		log.Error().
			Err(deactiveKeyErr).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "expire-active-key").
			Msg("error in expire key query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	insertKeyErr := qtx.InsertKey(context.Background(), db.InsertKeyParams{
		KeyID:      lib.GenUlid(),
		AppID:      appInfo.AppID,
		PublicKey:  lib.EncodeB64(publicKey),
		PrivateKey: lib.EncodeB64(privateKey),
		KeyType:    db.AppKeysKeyType(appInfo.KeyType),
		KeyAlgo:    db.AppKeysKeyAlgo(appInfo.Algo),
		ExpTime:    time.Now().Add(time.Second * time.Duration(appInfo.RotationPeriod)).Unix(),
		AddTime:    time.Now().Unix(),
	})
	if insertKeyErr != nil {
		log.Error().
			Err(insertKeyErr).
			Str("system", "root-controller").
			Str("sub-system", "rotate-app-pki").
			Str("component", "insert-new-key").
			Msg("error in insert key query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	tx.Commit()

	c.JSON(http.StatusOK, gin.H{
		"app_id":         appInfo.AppID,
		"new_public_key": lib.EncodeB64(publicKey),
		"algo":           appInfo.Algo,
	})
	return
}

func RevokeAppPKI(c *gin.Context) {
	var paramURI struct {
		AppId string `uri:"app_id" binding:"required,ulid"`
		KeyId string `uri:"key_id" binding:"required,ulid"`
	}

	if err := c.ShouldBindUri(&paramURI); err != nil {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"errors": "invalid app or key id",
		})
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
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
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "txn begin").
			Msg("error in starting txn")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer tx.Rollback()

	qtx := q.WithTx(tx)

	keyRevokeStatus := qtx.RevokeKeyById(context.Background(), db.RevokeKeyByIdParams{
		IsRevoked: db.AppKeysIsRevokedYes,
		AppID:     paramURI.AppId,
		KeyID:     paramURI.KeyId,
	})
	if keyRevokeStatus != nil {
		log.Error().
			Err(keyRevokeStatus).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "query-revoke-key").
			Msg("error in revoking key")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	deleteRevokedTokens :=
		qtx.DeleteAllTokenByKeyId(context.Background(), db.DeleteAllTokenByKeyIdParams{
			AppsID: paramURI.AppId,
			KeyID:  paramURI.KeyId,
		})
	if deleteRevokedTokens != nil {
		log.Error().
			Err(deleteRevokedTokens).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "delete-revoked-tokens").
			Msg("error in deleting revoked tokens")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	appInfo, err := qtx.GetAppByID(context.Background(), paramURI.AppId)
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "reading app details").
			Msg("error in select query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	privateKey, publicKey, keyError := lib.GenerateKeyPair(string(appInfo.Algo))
	if keyError != nil {
		log.Error().
			Err(keyError).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "public-private key").
			Msg("error in generating public-private key pair")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	updateErr := qtx.UpdatePKIRotationTime(context.Background(), db.UpdatePKIRotationTimeParams{
		LastRotateTime: sql.NullInt64{
			Int64: time.Now().Unix(),
			Valid: true,
		},
		AppID: appInfo.AppID,
	})

	if updateErr != nil {
		log.Error().
			Err(updateErr).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "update-app-key-rotation").
			Msg("error in update app query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	insertKeyErr := qtx.InsertKey(context.Background(), db.InsertKeyParams{
		KeyID:      lib.GenUlid(),
		AppID:      appInfo.AppID,
		PublicKey:  lib.EncodeB64(publicKey),
		PrivateKey: lib.EncodeB64(privateKey),
		KeyType:    db.AppKeysKeyType(appInfo.KeyType),
		KeyAlgo:    db.AppKeysKeyAlgo(appInfo.Algo),
		ExpTime:    time.Now().Add(time.Second * time.Duration(appInfo.RotationPeriod)).Unix(),
		AddTime:    time.Now().Unix(),
	})
	if insertKeyErr != nil {
		log.Error().
			Err(insertKeyErr).
			Str("system", "root-controller").
			Str("sub-system", "revoke-pki").
			Str("component", "insert-new-key").
			Msg("error in insert key query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	tx.Commit()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
	return
}

func FlushTokens(c *gin.Context) {
	var paramURI struct {
		AppId string `uri:"app_id" binding:"required,ulid"`
	}

	if err := c.ShouldBindUri(&paramURI); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"errors": "invalid app id"})
		return
	}

	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Err(err).
			Str("system", "root-controller").
			Str("sub-system", "flush-tokens").
			Str("component", "db connect").
			Msg("error in db connection")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)
	resultErr := q.DeleteAllTokensByAppId(context.Background(), paramURI.AppId)
	if resultErr != nil {
		log.Error().
			Err(resultErr).
			Str("system", "root-controller").
			Str("sub-system", "flush-tokens").
			Str("component", "delete").
			Msg("error in delete query")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
	return
}
