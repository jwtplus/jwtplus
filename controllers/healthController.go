package controllers

import (
	"jwtplus/lib"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func HealthController(c *gin.Context) {
	dbConnection, err := lib.DBConnect()
	if err != nil {
		log.Error().
			Str("system", "health-controller").
			Str("sub-system", "health").
			Str("component", "connect").
			Err(err).
			Msg("db connection error")
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"message": "db-down",
		})
		return
	}
	defer dbConnection.Close()

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
	})
	return
}
