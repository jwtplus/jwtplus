package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var dbTestingTokenInsert = InsertTokenParams{
	TokenID:          GenUlid(),
	AppsID:           dbTestingApps.AppID,
	KeyID:            dbTestingAppKeysInsert.KeyID,
	Sub:              GetSHA512Hash("test-user"),
	AuthToken:        "auth-token",
	AuthTokenHash:    GetSHA512Hash("auth-token"),
	AuthTokenIat:     time.Now().Unix(),
	AuthTokenNbf:     time.Now().Unix(),
	AuthTokenExp:     time.Now().Add(time.Hour).Unix(),
	RefreshToken:     "refresh-token",
	RefreshTokenHash: GetSHA512Hash("refresh-token"),
	RefreshTokenIat:  time.Now().Unix(),
	RefreshTokenNbf:  time.Now().Unix(),
	RefreshTokenExp:  time.Now().Add(time.Hour).Unix(),
	IpAddress:        "1.1.1.1",
	UserAgent:        "test-user-agent",
}

func TestInsertToken(t *testing.T) {
	err1 := testQueries.InsertToken(context.Background(), dbTestingTokenInsert)
	assert.NoError(t, err1)
}

func TestGetTokenByAuthHash(t *testing.T) {
	sql1, err := testQueries.GetTokenByAuthHash(context.Background(), GetTokenByAuthHashParams{
		AppsID:        dbTestingApps.AppID,
		AuthTokenHash: dbTestingTokenInsert.AuthTokenHash,
		AuthTokenExp:  time.Now().Unix(),
		AuthTokenNbf:  int64(time.Now().Add(time.Minute).Unix()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dbTestingTokenInsert.TokenID, sql1.TokenID)
	assert.Equal(t, dbTestingAppKeysInsert.KeyID, sql1.KeyID)
}

func TestGetTokenByRefreshHash(t *testing.T) {
	sql1, err := testQueries.GetTokenByRefreshHash(context.Background(), GetTokenByRefreshHashParams{
		AppsID:           dbTestingApps.AppID,
		RefreshTokenHash: dbTestingTokenInsert.RefreshTokenHash,
		RefreshTokenExp:  time.Now().Unix(),
		RefreshTokenNbf:  int64(time.Now().Add(time.Minute).Unix()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dbTestingTokenInsert.TokenID, sql1.TokenID)
	assert.Equal(t, dbTestingAppKeysInsert.KeyID, sql1.KeyID)
}

func TestGetActiveSessionAgainstSubject(t *testing.T) {
	sql1, err := testQueries.GetActiveSessionAgainstSubject(context.Background(), GetActiveSessionAgainstSubjectParams{
		AppsID:       dbTestingApps.AppID,
		Sub:          dbTestingTokenInsert.Sub,
		AuthTokenExp: time.Now().Unix(),
		AuthTokenNbf: int64(time.Now().Add(time.Minute).Unix()),
	})
	assert.NoError(t, err)
	assert.Equal(t, dbTestingTokenInsert.TokenID, sql1[0].TokenID)
	assert.Equal(t, dbTestingAppKeysInsert.KeyID, sql1[0].KeyID)
}

func TestDeleteTokenByAuthTokenHash(t *testing.T) {
	i1 := dbTestingTokenInsert
	i1.TokenID = GenUlid()
	i1.Sub = "SUB-2"
	i1.AuthTokenHash = GetSHA512Hash("SUB-2")

	err1 := testQueries.InsertToken(context.Background(), i1)
	assert.NoError(t, err1)

	err2 := testQueries.DeleteTokenByAuthTokenHash(context.Background(), DeleteTokenByAuthTokenHashParams{
		AppsID:        i1.AppsID,
		AuthTokenHash: i1.AuthTokenHash,
	})
	assert.NoError(t, err2)
}

func TestDeleteTokenByTokenId(t *testing.T) {
	i2 := dbTestingTokenInsert
	i2.TokenID = GenUlid()
	i2.Sub = "SUB-3"
	i2.AuthTokenHash = GetSHA512Hash("SUB-3")

	err1 := testQueries.InsertToken(context.Background(), i2)
	assert.NoError(t, err1)

	err2 := testQueries.DeleteTokenByTokenId(context.Background(), DeleteTokenByTokenIdParams{
		TokenID: i2.TokenID,
		AppsID:  i2.AppsID,
	})
	assert.NoError(t, err2)
}

func TestDeleteAllTokenByKeyId(t *testing.T) {
	i3 := dbTestingTokenInsert
	i3.TokenID = GenUlid()
	i3.Sub = "SUB-3"
	i3.AuthTokenHash = GetSHA512Hash("SUB-3")

	err1 := testQueries.InsertToken(context.Background(), i3)
	assert.NoError(t, err1)

	err2 := testQueries.DeleteAllTokenByKeyId(context.Background(), DeleteAllTokenByKeyIdParams{
		AppsID: i3.AppsID,
		KeyID:  i3.KeyID,
	})
	assert.NoError(t, err2)
}

func TestDeleteAllTokensByAppId(t *testing.T) {
	i4 := dbTestingTokenInsert
	i4.TokenID = GenUlid()
	i4.Sub = "SUB-4"
	i4.AuthTokenHash = GetSHA512Hash("SUB-4")

	err1 := testQueries.InsertToken(context.Background(), i4)
	assert.NoError(t, err1)

	err2 := testQueries.DeleteAllTokensByAppId(context.Background(), i4.AppsID)
	assert.NoError(t, err2)
}

func TestDeleteExpiredTokens(t *testing.T) {
	err1 := testQueries.DeleteExpiredTokens(context.Background(), time.Now().Add(24*time.Hour).Unix())
	assert.NoError(t, err1)

	_, err2 := testQueries.GetTokenByAuthHash(context.Background(), GetTokenByAuthHashParams{
		AppsID:        dbTestingApps.AppID,
		AuthTokenHash: dbTestingTokenInsert.AuthTokenHash,
		AuthTokenExp:  time.Now().Unix(),
		AuthTokenNbf:  int64(time.Now().Add(time.Minute).Unix()),
	})
	assert.Error(t, err2)
}
