package lib

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func PerformInit() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Info().Msg("Starting up the JWTPlus server")

	log.Info().Msg("loading config")
	if err := LoadConfig(); err != nil {
		log.Fatal().Err(err).Msg("fail to load the config")
	}
	log.Info().Msg("config file found, loading completed")

	log.Info().Msg("validating config")
	if err := VerifyConfig(); err != nil {
		log.Fatal().Err(err).Msg("failed to validate the config")
	}
	log.Info().Msg("config validated, OK")

	log.Info().Msg("Checking database connection")
	if _, err := DBConnect(); err != nil {
		log.Fatal().Err(err).Msg("failed to connect database")
	}
	log.Info().Msg("database connected successfully")
}
