package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var dbTestingAppKeysInsert = InsertKeyParams{
	KeyID:      GenUlid(),
	AppID:      dbTestingApps.AppID,
	PublicKey:  "pub-key",
	PrivateKey: "private-key",
	KeyType:    AppKeysKeyTypeRSA,
	KeyAlgo:    AppKeysKeyAlgoRS256,
	ExpTime:    time.Now().Add(time.Hour).Unix(),
	AddTime:    time.Now().Unix(),
}

var dbTestingAppKeysInsert2 = InsertKeyParams{
	KeyID:      GenUlid(),
	AppID:      dbTestingApps.AppID,
	PublicKey:  "pub-key",
	PrivateKey: "private-key",
	KeyType:    AppKeysKeyTypeRSA,
	KeyAlgo:    AppKeysKeyAlgoRS256,
	ExpTime:    time.Now().Add(time.Hour).Unix(),
	AddTime:    time.Now().Unix(),
}

func TestInsertKey(t *testing.T) {
	sql1 := testQueries.InsertKey(context.Background(), dbTestingAppKeysInsert)
	assert.NoError(t, sql1)

	sql2 := testQueries.InsertKey(context.Background(), dbTestingAppKeysInsert2)
	assert.NoError(t, sql2)
}
func TestGetAppKeyReadyForRotation(t *testing.T) {
	sql, err := testQueries.GetAppKeyReadyForRotation(context.Background(), time.Now().Unix())
	assert.NoError(t, err)
	assert.Equal(t, int(0), len(sql))

	sql1, err1 := testQueries.GetAppKeyReadyForRotation(context.Background(), time.Now().Add(70*time.Minute).Unix())
	assert.NoError(t, err1)
	assert.Equal(t, int(2), len(sql1))
	assert.Equal(t, dbTestingAppKeysInsert.KeyID, sql1[0].KeyID)
}

func TestExpireActiveKey(t *testing.T) {
	sql1 := testQueries.ExpireActiveKey(context.Background(), ExpireActiveKeyParams{
		IsExpired: AppKeysIsExpiredYes,
		AppID:     dbTestingApps.AppID,
	})
	assert.NoError(t, sql1)

	sql2 := testQueries.ExpireActiveKey(context.Background(), ExpireActiveKeyParams{
		IsExpired: AppKeysIsExpiredYes,
		AppID:     "INVALID-APP-ID",
	})
	assert.NoError(t, sql2)
}

func TestRevokeKeyById(t *testing.T) {
	sql1 := testQueries.RevokeKeyById(context.Background(), RevokeKeyByIdParams{
		IsRevoked: AppKeysIsRevokedYes,
		AppID:     dbTestingApps.AppID,
		KeyID:     dbTestingAppKeysInsert.KeyID,
	})
	assert.NoError(t, sql1)
}

func TestGetPublicKeysByAppId(t *testing.T) {
	sql1, err1 := testQueries.GetPublicKeysByAppId(context.Background(), dbTestingApps.AppID)
	assert.NoError(t, err1)
	assert.Equal(t, int(2), len(sql1))
	assert.Equal(t, AppKeysIsRevokedYes, sql1[0].IsRevoked)

	sql2, err2 := testQueries.GetPublicKeysByAppId(context.Background(), GenUlid())
	assert.NoError(t, err2)
	assert.Equal(t, int(0), len(sql2))
}

func TestExpireActiveKeyById(t *testing.T) {
	err1 := testQueries.ExpireActiveKeyById(context.Background(), ExpireActiveKeyByIdParams{
		IsExpired: AppKeysIsExpiredYes,
		AppID:     dbTestingAppKeysInsert2.AppID,
		KeyID:     dbTestingAppKeysInsert2.KeyID,
	})
	assert.NoError(t, err1)
}
