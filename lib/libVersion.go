package lib

import (
	"context"
	"fmt"
	db "jwtplus/db/sqlc"
)

func VerifyAppVersion(appVersion string) error {
	dbConnection, err := DBConnect()
	if err != nil {
		return err
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	appVersionCheck, err := q.GetSettingByKey(context.Background(), "APP-VERSION")
	if err != nil {
		return err
	}
	if appVersionCheck != appVersion {
		return fmt.Errorf("app binary version %s, db version %s", appVersion, appVersionCheck)
	}

	return nil
}

func UpgradeAppVersion(appVersion string) error {
	dbConnection, err := DBConnect()
	if err != nil {
		return err
	}
	defer dbConnection.Close()

	q := db.New(dbConnection)

	return q.UpdateSettingByKey(context.Background(), db.UpdateSettingByKeyParams{
		SettingKey:   "APP-VERSION",
		SettingValue: appVersion,
	})
}
