package main

import (
	"fmt"
	"jwtplus/db"
	"jwtplus/lib"
	"jwtplus/routes"
	"os"

	"github.com/gin-gonic/autotls"
	"github.com/rs/zerolog/log"
)

var AppVersion string = "1.0"

func init() {
	lib.PerformInit()
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal().
			Msg("please provide run option. acceptable values are run, install, upgrade, clean, rotate")
	}

	switch os.Args[1] {
	case "run":
		//Verify installed version
		versionErr := lib.VerifyAppVersion(AppVersion)
		if versionErr != nil {
			log.Fatal().
				Str("system", "version-check").
				Err(versionErr).
				Msg("version conflict, both version should match")
		}
		log.Info().Msgf("App Version: %s", AppVersion)

		//prepare the routes
		engine := routes.SetupRouter()

		//Check if the setting is on the IP Address than start the server on ip:port
		if lib.Config.IsSet("server.ip") && lib.Config.IsSet("server.port") {
			log.Info().Msgf("server started at %s:%d",
				lib.Config.GetString("server.ip"),
				lib.Config.GetInt("server.port"))
			engine.Run(
				fmt.Sprintf("%s:%d",
					lib.Config.GetString("server.ip"),
					lib.Config.GetInt("server.port")))
		}

		//Check if the setting is on the domain than start the server on the domain:443
		if lib.Config.IsSet("server.domain") {
			log.Info().Msgf("server started at https://%s",
				lib.Config.GetString("server.doamin"))
			log.Fatal().
				Err(autotls.Run(engine, lib.Config.GetString("server.doamin"))).
				Str("system", "startup").
				Msg("failed to acquire the ssl certificate from letsencrypt")
		}

	case "install":
		db.MigrateSQL()
		lib.CheckRootKey(AppVersion)

	case "upgrade":
		db.MigrateSQL()
		upgradeErr := lib.UpgradeAppVersion(AppVersion)
		if upgradeErr != nil {
			log.Fatal().
				Str("system", "upgrade").
				Err(upgradeErr).
				Msg("error in version number update, please check your database")
		}

		log.Info().
			Str("system", "upgrade").
			Msgf("System upgraded successfully, App Version: %s", AppVersion)

	case "clean":
		lib.CronCleanExpiredTokens()

	case "rotate":
		lib.CronAutoRotateKeys()

	default:
		log.Fatal().
			Msg("please provide run option. acceptable values are run, install, upgrade, clean, rotate")
	}
}
