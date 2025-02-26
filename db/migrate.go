package db

import (
	"embed"
	"fmt"
	"jwtplus/lib"
	"net/url"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/rs/zerolog/log"
)

// Include every sql file inside the binary build
//
//go:embed migrations/*.sql
var MigrationFiles embed.FS

func MigrateSQL() error {

	log.Info().Msg("Starting db migration")
	dsn := fmt.Sprintf("mysql://%s:%s@tcp(%s:%s)/%s",
		url.QueryEscape(lib.Config.GetString("db.username")),
		url.QueryEscape(lib.Config.GetString("db.password")),
		url.QueryEscape(lib.Config.GetString("db.location")),
		lib.Config.GetString("db.port"),
		url.QueryEscape(lib.Config.GetString("db.dbname")),
	)

	d, err := iofs.New(MigrationFiles, "migrations")
	if err != nil {
		log.Fatal().
			Err(err).
			Str("system", "init").
			Str("sub-system", "migration").
			Str("component", "fs").
			Msg("db migration failed")
		return err
	}
	m, err := migrate.NewWithSourceInstance("iofs", d, dsn)
	if err != nil {
		log.Fatal().
			Str("system", "init").
			Str("sub-system", "migration").
			Str("component", "iofs").
			Err(err).
			Msg("db migration failed")
		return err
	}
	defer func() {
		sourceErr, dbErr := m.Close()
		if sourceErr != nil {
			log.Fatal().
				Str("system", "init").
				Str("sub-system", "migration").
				Str("component", "defer").
				Err(err).
				Msg("db migration failed")
		}
		if dbErr != nil {
			log.Fatal().
				Str("system", "init").
				Str("sub-system", "migration").
				Str("component", "defer").
				Err(err).
				Msg("db migration failed")
		}
	}()
	err = m.Up()
	if err != nil && err.Error() != "no change" {
		log.Fatal().
			Str("system", "init").
			Str("sub-system", "migration").
			Str("component", "up").
			Err(err).
			Msg("db migration failed")
		return err
	}
	log.Info().Msg("db migration completed")
	return nil
}
