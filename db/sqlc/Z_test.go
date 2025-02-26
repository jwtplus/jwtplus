package db

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDBCleanup(t *testing.T) {
	sql1 := testQueries.DeleteAppById(context.Background(), dbTestingApps.AppID)
	assert.NoError(t, sql1)

	sql2 := testQueries.DeleteAllApp(context.Background())
	assert.NoError(t, sql2)
}
