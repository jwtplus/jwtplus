package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

var dbTestingSettings = InsertSettingParams{
	SettingKey:   "TEST-KEY",
	SettingValue: "TEST-VALUE",
}

var dbTestingSettingsUpdated = InsertSettingParams{
	SettingKey:   "TEST-KEY",
	SettingValue: "TEST-UPDATED-VALUE",
}

func TestInsertSetting(t *testing.T) {
	settingInsert := testQueries.InsertSetting(context.Background(), dbTestingSettings)
	assert.NoError(t, settingInsert)
}

func TestUpdateSettingByKey(t *testing.T) {
	err1 := testQueries.UpdateSettingByKey(context.Background(), UpdateSettingByKeyParams{
		SettingValue: dbTestingSettingsUpdated.SettingValue,
		SettingKey:   dbTestingSettings.SettingKey,
	})
	assert.NoError(t, err1)

	err2 := testQueries.UpdateSettingByKey(context.Background(), UpdateSettingByKeyParams{
		SettingValue: dbTestingSettingsUpdated.SettingValue,
		SettingKey:   "INVALID-MISSING-KEY",
	})
	assert.NoError(t, err2)
}

func TestGetSettingByKey(t *testing.T) {
	row, err := testQueries.GetSettingByKey(context.Background(), dbTestingSettings.SettingKey)
	assert.NoError(t, err)
	assert.Equal(t, dbTestingSettingsUpdated.SettingValue, row)

	row2, err := testQueries.GetSettingByKey(context.Background(), "INVALID-MISSING-KEY")
	assert.Error(t, err)
	assert.Empty(t, row2)
}

func TestCountSettingByKey(t *testing.T) {
	c, err := testQueries.CountSettingByKey(context.Background(), dbTestingSettings.SettingKey)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), c)

	c2, err := testQueries.CountSettingByKey(context.Background(), "INVALID-MISSING-KEY")
	assert.NoError(t, err)
	assert.Equal(t, int64(0), c2)
}

func TestCountSettingByKeyAndValue(t *testing.T) {
	c1, err := testQueries.CountSettingByKeyAndValue(context.Background(), CountSettingByKeyAndValueParams{
		SettingKey:   dbTestingSettings.SettingKey,
		SettingValue: dbTestingSettings.SettingValue,
	})
	assert.NoError(t, err)
	assert.Equal(t, int64(0), c1)

	c2, err := testQueries.CountSettingByKeyAndValue(context.Background(), CountSettingByKeyAndValueParams{
		SettingKey:   dbTestingSettings.SettingKey,
		SettingValue: dbTestingSettingsUpdated.SettingValue,
	})
	assert.NoError(t, err)
	assert.Equal(t, int64(1), c2)

	c3, err := testQueries.CountSettingByKeyAndValue(context.Background(), CountSettingByKeyAndValueParams{
		SettingKey:   "INVALID-MISSING-KEY",
		SettingValue: "INVALID-MISSING-VALUE",
	})
	assert.NoError(t, err)
	assert.Equal(t, int64(0), c3)
}

func TestDeleteSettingByKey(t *testing.T) {
	sql1 := testQueries.DeleteSettingByKey(context.Background(), dbTestingSettings.SettingKey)
	assert.NoError(t, sql1)

	sql2 := testQueries.DeleteSettingByKey(context.Background(), "INVALID-MISSING-KEY")
	assert.NoError(t, sql2)
}
