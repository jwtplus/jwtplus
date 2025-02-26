package lib

import (
	"context"
	"fmt"
	db "jwtplus/db/sqlc"

	"github.com/rs/zerolog/log"
)

func CheckRootKey(AppVersion string) error {
	dbConnection, err := DBConnect()
	if err != nil {
		log.Fatal().
			Str("system", "lib").
			Str("sub-system", "install").
			Str("component", "connect").
			Err(err).
			Msg("failed to connect database")
		return err
	}

	defer dbConnection.Close()

	q := db.New(dbConnection)

	result, err := q.CountSettingByKey(context.Background(), "ROOT-KEY")
	if err != nil {
		log.Error().
			Str("system", "init").
			Str("sub-system", "root-key").
			Str("component", "fetch").
			Err(err).Msg("sql error")
		return err
	}

	if result == 0 {
		keyHash, err := setupRootKey()
		if err != nil {
			log.Fatal().
				Err(err).
				Str("system", "init").
				Str("sub-system", "root-key").
				Str("component", "gen-random").
				Msg("error in random generation")
			return err
		}

		tx, txErr := dbConnection.Begin()
		if txErr != nil {
			log.Error().
				Err(txErr).
				Str("system", "init").
				Str("sub-system", "root-key").
				Str("component", "txn-begin").
				Msg("error in starting txn")
			return txErr
		}
		defer tx.Rollback()

		qtx := q.WithTx(tx)

		writeRootKeyError := qtx.InsertSetting(context.Background(), db.InsertSettingParams{
			SettingKey:   "ROOT-KEY",
			SettingValue: keyHash,
		})

		if writeRootKeyError != nil {
			log.Fatal().
				Err(writeRootKeyError).
				Str("system", "init").
				Str("sub-system", "root-key").
				Str("component", "write-hash").
				Msg("failed to store root key hash in db")
			return writeRootKeyError
		}

		writeAppVersionError := qtx.InsertSetting(context.Background(), db.InsertSettingParams{
			SettingKey:   "APP-VERSION",
			SettingValue: AppVersion,
		})

		if writeAppVersionError != nil {
			log.Fatal().
				Err(writeRootKeyError).
				Str("system", "init").
				Str("sub-system", "root-key").
				Str("component", "write-app").
				Msg("failed to store app-version in db")
			return writeRootKeyError
		}
		tx.Commit()
	}

	return nil

}

func setupRootKey() (string, error) {
	log.Info().
		Str("system", "init").
		Str("sub-system", "root-key").
		Str("component", "create").
		Msg("Creating root key")

	key, err := GenRandomString(128)
	if err != nil {
		return "", err
	}

	keyHash := GetSHA512Hash(key)

	// Stylish console output
	// Stylish console output with border
	fmt.Println("*****************************************************")
	fmt.Println("*                                                   *")
	fmt.Println("*    Below is your root key, please keep it safe    *")
	fmt.Println("*    and this will not be shown again.              *")
	fmt.Println("*    Do not share it with anyone. If someone gains  *")
	fmt.Println("*    access to this key, they may gain full access  *")
	fmt.Println("*    to your system. Treat it like a password!      *")
	fmt.Println("*                                                   *")
	fmt.Println("*****************************************************")
	fmt.Println("")

	// Display the root key
	fmt.Println("*****************************************************")
	fmt.Printf("ROOT KEY: %s\n", key)
	fmt.Println("*****************************************************")
	fmt.Println("")

	return keyHash, nil
}
