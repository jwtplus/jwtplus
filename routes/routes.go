package routes

import (
	"jwtplus/controllers"
	"jwtplus/lib"
	"jwtplus/middleware"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func setCrossOrigin() gin.HandlerFunc {
	//Default - accept from all origin
	origins := []string{"*"}

	if lib.Config.IsSet("origins") {
		origins = lib.Config.GetStringSlice("origins")
	}

	return cors.New(cors.Config{
		AllowOrigins:  origins,
		AllowMethods:  []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:  []string{"Origin"},
		ExposeHeaders: []string{"Content-Length"},
	})
}

func SetupRouter() *gin.Engine {

	if lib.Config.GetBool("debug") == false {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
	engine.SetTrustedProxies(nil)
	engine.Use(gin.Recovery())

	//CORS settings
	engine.Use(setCrossOrigin())
	engine.Use(middleware.DefaultStructuredLogger())

	//Load custom form validation rules
	lib.RegisterCustomValidators()

	engine.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	engine.GET("/health", controllers.HealthController)

	root := engine.Group("/root")
	root.Use(middleware.ValidateRootToken())
	{
		// GET /root/list -> get info about all onboarded app
		root.GET("/list", controllers.GetAllApps)

		// GET /root/rotate -> rotate root key
		root.GET("/rotate", controllers.RotateRootKey)

		// POST /root/create -> create new app
		root.POST("/create", controllers.CreateApp)

		// PATCH /root/{{app_id}} -> update app
		root.PATCH("/:app_id", controllers.UpdateApp)

		// GET /root/{{app_id}}/rotate/key -> rotate app keys
		root.GET("/:app_id/rotate/key", controllers.RotateAppKey)

		// GET /root/{{app_id}}/rotate/pki -> rotate public/private key
		root.GET("/:app_id/rotate/pki", controllers.RotateAppPKI)

		// DELETE /app/{{app_id}}/revoke/{{kid}} -> revoke any active key id
		root.DELETE("/:app_id/revoke/:key_id", controllers.RevokeAppPKI)

		// DELETE /root/{{ID}}/flush -> invalidate all issued JWT tokens including refresh tokens
		root.DELETE("/:app_id/flush", controllers.FlushTokens)

		// DELETE /root/{{app_id}} -> delete app
		root.DELETE("/:app_id", controllers.DeleteApp)
	}

	app := engine.Group("/app")
	app.Use(middleware.ValidateAppToken())
	{
		// GET /app/{{app_id}} -> get info / stats about the app
		app.GET("/:app_id", controllers.AppGetInfo)

		// GET /app/{{app_id}}/pub-keys
		app.GET("/:app_id/pub-keys", controllers.AppGetPublicKeys)

		// POST /app/{{app_id}}/sign -> create new JWT token based on the submitted JSON data
		app.POST("/:app_id/sign", controllers.AppJWTSign)

		// POST /app/{{app_id}}/verify -> verify submitted jwt token
		app.POST("/:app_id/verify", controllers.AppJWTVerify)

		// POST /app/{{app_id}}/renew -> renew existing jwt token
		app.POST("/:app_id/renew", controllers.AppJwtRenew)

		// POST /app/{{app_id}}/get-session -> get login sessions details of the given sub
		app.POST("/:app_id/get-session", controllers.AppGetActiveSessions)

		// POST /app/{{app_id}}/logout -> delete jwt token of the given subject
		app.POST("/:app_id/logout", controllers.AppDoLogout)
	}

	return engine
}
