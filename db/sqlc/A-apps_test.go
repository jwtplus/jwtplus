package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var dbTestingApps = InsertAppParams{
	AppID:   GenUlid(),
	AppName: "TEST-APP",
	AppDescription: sql.NullString{
		Valid:  true,
		String: "TEST-DESCRIPTION",
	},
	AppKey:         GetSHA512Hash(GenUlid()),
	TokenExpiry:    3600,
	TokenNbf:       0,
	RefreshExpiry:  7200,
	RefreshNbf:     0,
	KeyType:        AppsKeyTypeRSA,
	Algo:           AppsAlgoRS256,
	RotationPeriod: 7200,
	AddTime:        time.Now().Unix(),
}

var dbTestingAppsUpdate = UpdateAppByIdParams{
	AppName: "TEST-APP-UPDATED",
	AppDescription: sql.NullString{
		Valid:  true,
		String: "TEST-DESCRIPTION-UPDATED",
	},
	TokenExpiry:   4800,
	TokenNbf:      0,
	RefreshExpiry: 9600,
	RefreshNbf:    0,
	UpdateTime: sql.NullInt64{
		Valid: true,
		Int64: int64(time.Now().Unix()),
	},
	RotationPeriod: 6000,
	AppID:          dbTestingApps.AppID,
}
var dbTestingAppsNewAppKey = GetSHA512Hash(GenUlid())

func TestInsertApp(t *testing.T) {
	sql1 := testQueries.InsertApp(context.Background(), dbTestingApps)
	assert.NoError(t, sql1)
}

func TestVerifyAppToken(t *testing.T) {
	sql1, err1 := testQueries.VerifyAppToken(context.Background(), VerifyAppTokenParams{
		AppID:  dbTestingApps.AppID,
		AppKey: dbTestingApps.AppKey,
	})

	assert.NoError(t, err1)
	assert.Equal(t, int64(1), sql1)
}

func TestGetAllApp(t *testing.T) {
	sql1, err1 := testQueries.GetAllApp(context.Background())
	assert.NoError(t, err1)
	assert.GreaterOrEqual(t, len(sql1), int(1))
}

func TestUpdateAppById(t *testing.T) {
	err1 := testQueries.UpdateAppById(context.Background(), dbTestingAppsUpdate)
	assert.NoError(t, err1)
}

func TestUpdatePKIRotationTime(t *testing.T) {
	err1 := testQueries.UpdatePKIRotationTime(context.Background(), UpdatePKIRotationTimeParams{
		LastRotateTime: sql.NullInt64{
			Valid: true,
			Int64: int64(time.Now().Unix()),
		},
		AppID: dbTestingApps.AppID,
	})
	assert.NoError(t, err1)
}

func TestRotateAppKeyById(t *testing.T) {
	err1 := testQueries.RotateAppKeyById(context.Background(), RotateAppKeyByIdParams{
		AppKey: dbTestingAppsNewAppKey,
		UpdateTime: sql.NullInt64{
			Valid: true,
			Int64: int64(time.Now().Unix()),
		},
		AppID: dbTestingApps.AppID,
	})
	assert.NoError(t, err1)
}

func TestGetAppByID(t *testing.T) {
	sql1, err1 := testQueries.GetAppByID(context.Background(), dbTestingApps.AppID)
	assert.NoError(t, err1)
	assert.Equal(t, dbTestingAppsUpdate.AppName, sql1.AppName)
	assert.NotEqual(t, dbTestingApps.AppName, sql1.AppName)
}
