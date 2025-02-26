package lib

import (
	"context"
	"database/sql"
	db "jwtplus/db/sqlc"
	"time"

	"github.com/rs/zerolog/log"
)

func CronCleanExpiredTokens() {
	dbConnection, err := DBConnect()
	if err != nil {
		log.Error().
			Str("system", "CRON").
			Str("sub-system", "clean-expire-tokens").
			Str("component", "connect").
			Err(err).
			Msg("db connection error")
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	err = q.DeleteExpiredTokens(context.Background(), time.Now().Unix())
	if err != nil {
		log.Error().
			Str("system", "CRON").
			Str("sub-system", "clean-expire-tokens").
			Str("component", "delete-query").
			Err(err).
			Msg("error in delete query")
		return
	}
	log.Info().
		Str("system", "CRON").
		Str("sub-system", "clean-expire-tokens").
		Str("component", "complete").
		Msg("successfully completed the task")
}

func CronAutoRotateKeys() {
	dbConnection, err := DBConnect()
	if err != nil {
		log.Error().
			Str("system", "CRON").
			Str("sub-system", "auto-rotate-keys").
			Str("component", "connect").
			Err(err).
			Msg("db connection error")
		return
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	//Get keys with expiry time within less than or equal to 1 minute
	expiredKeys, errExpiredKeys := q.GetAppKeyReadyForRotation(context.Background(), time.Now().Add(time.Minute).Unix())

	if errExpiredKeys != nil {
		log.Error().
			Str("system", "CRON").
			Str("sub-system", "auto-rotate-keys").
			Str("component", "get-expired-keys").
			Err(err).
			Msg("error in fetch query")
		return
	}

	for _, ek := range expiredKeys {
		log.Info().
			Str("system", "CRON").
			Str("sub-system", "auto-rotate-keys").
			Str("component", "start").
			Str("app-id", ek.AppID).
			Str("key-id", ek.KeyID).
			Str("key-type", string(ek.KeyType.AppsKeyType)).
			Str("algo", string(ek.Algo.AppsAlgo)).
			Msg("started key rotation process")

		privateKey, publicKey, keyError := GenerateKeyPair(string(ek.Algo.AppsAlgo))
		if keyError != nil {
			log.Error().
				Err(keyError).
				Str("system", "CRON").
				Str("sub-system", "auto-rotate-keys").
				Str("component", "public-private key").
				Str("app-id", ek.AppID).
				Str("key-id", ek.KeyID).
				Str("key-type", string(ek.KeyType.AppsKeyType)).
				Str("algo", string(ek.Algo.AppsAlgo)).
				Msg("error in generating public-private key pair")
			continue
		}

		tx, txErr := dbConnection.Begin()
		if txErr != nil {
			log.Error().
				Err(txErr).
				Str("system", "CRON").
				Str("sub-system", "auto-rotate-keys").
				Str("component", "txn-begin").
				Msg("error in starting txn")
			return
		}

		qtx := q.WithTx(tx)
		updateErr := qtx.UpdatePKIRotationTime(context.Background(), db.UpdatePKIRotationTimeParams{
			LastRotateTime: sql.NullInt64{
				Int64: int64(time.Now().Unix()),
				Valid: true,
			},
			AppID: ek.AppID,
		})

		if updateErr != nil {
			log.Error().
				Err(updateErr).
				Str("system", "CRON").
				Str("sub-system", "auto-rotate-keys").
				Str("component", "update-app").
				Str("app-id", ek.AppID).
				Str("key-id", ek.KeyID).
				Str("key-type", string(ek.KeyType.AppsKeyType)).
				Str("algo", string(ek.Algo.AppsAlgo)).
				Msg("error in update app query")
			tx.Rollback()
			continue
		}

		deactiveKeyErr := qtx.ExpireActiveKeyById(context.Background(), db.ExpireActiveKeyByIdParams{
			AppID:     ek.AppID,
			KeyID:     ek.KeyID,
			IsExpired: db.AppKeysIsExpired("yes"),
		})
		if deactiveKeyErr != nil {
			log.Error().
				Err(deactiveKeyErr).
				Str("system", "CRON").
				Str("sub-system", "auto-rotate-keys").
				Str("component", "expire-active-key").
				Str("app-id", ek.AppID).
				Str("key-id", ek.KeyID).
				Str("key-type", string(ek.KeyType.AppsKeyType)).
				Str("algo", string(ek.Algo.AppsAlgo)).
				Msg("error in expire key query")
			tx.Rollback()
			continue
		}

		insertKeyErr := qtx.InsertKey(context.Background(), db.InsertKeyParams{
			KeyID:      GenUlid(),
			AppID:      ek.AppID,
			PublicKey:  EncodeB64(publicKey),
			PrivateKey: EncodeB64(privateKey),
			KeyType:    db.AppKeysKeyType(ek.KeyType.AppsKeyType),
			KeyAlgo:    db.AppKeysKeyAlgo(ek.Algo.AppsAlgo),
			ExpTime:    time.Now().Add(time.Second * time.Duration(ek.RotationPeriod.Int64)).Unix(),
			AddTime:    time.Now().Unix(),
		})
		if insertKeyErr != nil {
			log.Error().
				Err(insertKeyErr).
				Str("system", "CRON").
				Str("sub-system", "auto-rotate-keys").
				Str("component", "insert-new-key").
				Str("app-id", ek.AppID).
				Str("key-id", ek.KeyID).
				Str("key-type", string(ek.KeyType.AppsKeyType)).
				Str("algo", string(ek.Algo.AppsAlgo)).
				Msg("error in insert key query")
			tx.Rollback()
			continue
		}
		tx.Commit()
		log.Info().
			Str("system", "CRON").
			Str("sub-system", "auto-rotate-keys").
			Str("component", "completed").
			Str("app-id", ek.AppID).
			Str("key-id", ek.KeyID).
			Str("key-type", string(ek.KeyType.AppsKeyType)).
			Str("algo", string(ek.Algo.AppsAlgo)).
			Msg("started key rotation process")
	}

	log.Info().
		Str("system", "CRON").
		Str("sub-system", "auto-rotate-keys").
		Int("keys-rotated", len(expiredKeys)).
		Str("component", "complete").
		Msg("successfully completed the task")
}
