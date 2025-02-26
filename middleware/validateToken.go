package middleware

import (
	"context"
	db "jwtplus/db/sqlc"
	"jwtplus/lib"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type authHeader struct {
	Token string `header:"Authorization"`
}

func ValidateRootToken() gin.HandlerFunc {
	return func(c *gin.Context) {

		h := authHeader{}
		// bind Authorization Header to h and check for validation errors
		if err := c.ShouldBindHeader(&h); err != nil {
			log.Error().
				Str("system", "middleware").
				Str("sub-system", "validate-root-token").
				Str("component", "header-binding").
				Err(err)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid root token",
			})
			return
		}

		if len(h.Token) != 128 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid root token",
			})
			return
		}

		found, err := checkRootTokenInDB(h.Token)
		if err != nil || found != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid root key",
			})
			return
		}

		c.Next()
	}
}

func checkRootTokenInDB(token string) (int64, error) {
	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Fatal().
			Str("system", "middleware").
			Str("sub-system", "validate-root-token").
			Str("component", "connect").
			Err(err).
			Msg("failed to connect database")
		return 0, err
	}

	defer dbConnection.Close()

	q := db.New(dbConnection)
	result, err := q.CountSettingByKeyAndValue(context.Background(), db.CountSettingByKeyAndValueParams{
		SettingKey:   "ROOT-KEY",
		SettingValue: lib.GetSHA512Hash(token),
	})

	if err != nil {
		log.Error().
			Str("system", "middleware").
			Str("sub-system", "validate-root-token").
			Str("component", "fetch-record").
			Err(err).
			Msg("failed to query database")
		return 0, err
	}

	return result, nil
}

func ValidateAppToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := authHeader{}
		// bind Authorization Header to h and check for validation errors
		if err := c.ShouldBindHeader(&h); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid app token",
			})
			return
		}

		hashedToken := lib.GetSHA512Hash(h.Token)
		if len(hashedToken) != 128 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid app token",
			})
			return
		}

		//bind uri and validate for the ulid based app id
		var paramURI struct {
			AppId string `uri:"app_id" binding:"required,ulid"`
		}

		if err := c.ShouldBindUri(&paramURI); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid app id",
			})
			return
		}

		appDetails, err := checkAppTokenInDB(paramURI.AppId, hashedToken)
		if err != nil || appDetails != 1 {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"errors": "invalid app key or id",
			})
			return
		}
		c.Set("app-id", paramURI.AppId)
		c.Next()
	}
}

func checkAppTokenInDB(app string, token string) (int64, error) {
	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Fatal().
			Str("system", "middleware").
			Str("sub-system", "validate-app-token").
			Str("component", "connect").
			Err(err).
			Msg("failed to connect database")
		return 0, err
	}

	defer dbConnection.Close()

	q := db.New(dbConnection)
	result, err := q.VerifyAppToken(context.Background(), db.VerifyAppTokenParams{
		AppID:  app,
		AppKey: token,
	})

	if err != nil {
		log.Error().
			Str("system", "middleware").
			Str("sub-system", "validate-app-token").
			Str("component", "fetch-record").
			Err(err).
			Msg("failed to query database")
		return 0, err
	}

	return result, nil
}
