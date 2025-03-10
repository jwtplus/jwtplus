// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: apps.sql

package db

import (
	"context"
	"database/sql"
)

const deleteAllApp = `-- name: DeleteAllApp :exec
DELETE FROM apps
`

func (q *Queries) DeleteAllApp(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllApp)
	return err
}

const deleteAppById = `-- name: DeleteAppById :exec
DELETE FROM apps WHERE app_id = ? LIMIT 1
`

func (q *Queries) DeleteAppById(ctx context.Context, appID string) error {
	_, err := q.db.ExecContext(ctx, deleteAppById, appID)
	return err
}

const getAllApp = `-- name: GetAllApp :many
SELECT app_id, app_name, app_description, token_expiry, 
token_nbf, refresh_expiry, refresh_nbf, key_type, algo, 
rotation_period, add_time, update_time, last_rotate_time 
FROM apps
`

type GetAllAppRow struct {
	AppID          string         `json:"app_id"`
	AppName        string         `json:"app_name"`
	AppDescription sql.NullString `json:"app_description"`
	TokenExpiry    int32          `json:"token_expiry"`
	TokenNbf       int32          `json:"token_nbf"`
	RefreshExpiry  int32          `json:"refresh_expiry"`
	RefreshNbf     int32          `json:"refresh_nbf"`
	KeyType        AppsKeyType    `json:"key_type"`
	Algo           AppsAlgo       `json:"algo"`
	RotationPeriod int64          `json:"rotation_period"`
	AddTime        int64          `json:"add_time"`
	UpdateTime     sql.NullInt64  `json:"update_time"`
	LastRotateTime sql.NullInt64  `json:"last_rotate_time"`
}

func (q *Queries) GetAllApp(ctx context.Context) ([]GetAllAppRow, error) {
	rows, err := q.db.QueryContext(ctx, getAllApp)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []GetAllAppRow
	for rows.Next() {
		var i GetAllAppRow
		if err := rows.Scan(
			&i.AppID,
			&i.AppName,
			&i.AppDescription,
			&i.TokenExpiry,
			&i.TokenNbf,
			&i.RefreshExpiry,
			&i.RefreshNbf,
			&i.KeyType,
			&i.Algo,
			&i.RotationPeriod,
			&i.AddTime,
			&i.UpdateTime,
			&i.LastRotateTime,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getAppByID = `-- name: GetAppByID :one
SELECT app_id, app_name, app_description, 
token_expiry, token_nbf, refresh_expiry, 
refresh_nbf, key_type, algo, rotation_period, add_time, 
update_time, last_rotate_time 
FROM apps
WHERE app_id = ?
LIMIT 1
`

type GetAppByIDRow struct {
	AppID          string         `json:"app_id"`
	AppName        string         `json:"app_name"`
	AppDescription sql.NullString `json:"app_description"`
	TokenExpiry    int32          `json:"token_expiry"`
	TokenNbf       int32          `json:"token_nbf"`
	RefreshExpiry  int32          `json:"refresh_expiry"`
	RefreshNbf     int32          `json:"refresh_nbf"`
	KeyType        AppsKeyType    `json:"key_type"`
	Algo           AppsAlgo       `json:"algo"`
	RotationPeriod int64          `json:"rotation_period"`
	AddTime        int64          `json:"add_time"`
	UpdateTime     sql.NullInt64  `json:"update_time"`
	LastRotateTime sql.NullInt64  `json:"last_rotate_time"`
}

func (q *Queries) GetAppByID(ctx context.Context, appID string) (GetAppByIDRow, error) {
	row := q.db.QueryRowContext(ctx, getAppByID, appID)
	var i GetAppByIDRow
	err := row.Scan(
		&i.AppID,
		&i.AppName,
		&i.AppDescription,
		&i.TokenExpiry,
		&i.TokenNbf,
		&i.RefreshExpiry,
		&i.RefreshNbf,
		&i.KeyType,
		&i.Algo,
		&i.RotationPeriod,
		&i.AddTime,
		&i.UpdateTime,
		&i.LastRotateTime,
	)
	return i, err
}

const getAppForSigning = `-- name: GetAppForSigning :one
SELECT a.app_id, a.app_name, a.token_expiry, a.token_nbf, a.refresh_expiry, 
a.refresh_nbf, a.key_type, a.algo, b.key_id, b.private_key, b.public_key
FROM apps as a
LEFT JOIN app_keys as b on a.app_id = b.app_id
WHERE a.app_id = ? AND b.is_expired = 'no' AND b.is_revoked = 'no'
LIMIT 1
`

type GetAppForSigningRow struct {
	AppID         string         `json:"app_id"`
	AppName       string         `json:"app_name"`
	TokenExpiry   int32          `json:"token_expiry"`
	TokenNbf      int32          `json:"token_nbf"`
	RefreshExpiry int32          `json:"refresh_expiry"`
	RefreshNbf    int32          `json:"refresh_nbf"`
	KeyType       AppsKeyType    `json:"key_type"`
	Algo          AppsAlgo       `json:"algo"`
	KeyID         sql.NullString `json:"key_id"`
	PrivateKey    sql.NullString `json:"private_key"`
	PublicKey     sql.NullString `json:"public_key"`
}

func (q *Queries) GetAppForSigning(ctx context.Context, appID string) (GetAppForSigningRow, error) {
	row := q.db.QueryRowContext(ctx, getAppForSigning, appID)
	var i GetAppForSigningRow
	err := row.Scan(
		&i.AppID,
		&i.AppName,
		&i.TokenExpiry,
		&i.TokenNbf,
		&i.RefreshExpiry,
		&i.RefreshNbf,
		&i.KeyType,
		&i.Algo,
		&i.KeyID,
		&i.PrivateKey,
		&i.PublicKey,
	)
	return i, err
}

const insertApp = `-- name: InsertApp :exec
INSERT INTO apps (app_id, app_name, app_description, app_key,
token_expiry, token_nbf, refresh_expiry, 
refresh_nbf, key_type, algo, rotation_period, add_time) 
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
`

type InsertAppParams struct {
	AppID          string         `json:"app_id"`
	AppName        string         `json:"app_name"`
	AppDescription sql.NullString `json:"app_description"`
	AppKey         string         `json:"app_key"`
	TokenExpiry    int32          `json:"token_expiry"`
	TokenNbf       int32          `json:"token_nbf"`
	RefreshExpiry  int32          `json:"refresh_expiry"`
	RefreshNbf     int32          `json:"refresh_nbf"`
	KeyType        AppsKeyType    `json:"key_type"`
	Algo           AppsAlgo       `json:"algo"`
	RotationPeriod int64          `json:"rotation_period"`
	AddTime        int64          `json:"add_time"`
}

func (q *Queries) InsertApp(ctx context.Context, arg InsertAppParams) error {
	_, err := q.db.ExecContext(ctx, insertApp,
		arg.AppID,
		arg.AppName,
		arg.AppDescription,
		arg.AppKey,
		arg.TokenExpiry,
		arg.TokenNbf,
		arg.RefreshExpiry,
		arg.RefreshNbf,
		arg.KeyType,
		arg.Algo,
		arg.RotationPeriod,
		arg.AddTime,
	)
	return err
}

const rotateAppKeyById = `-- name: RotateAppKeyById :exec
UPDATE apps SET app_key = ?, update_time = ?
WHERE app_id = ?
LIMIT 1
`

type RotateAppKeyByIdParams struct {
	AppKey     string        `json:"app_key"`
	UpdateTime sql.NullInt64 `json:"update_time"`
	AppID      string        `json:"app_id"`
}

func (q *Queries) RotateAppKeyById(ctx context.Context, arg RotateAppKeyByIdParams) error {
	_, err := q.db.ExecContext(ctx, rotateAppKeyById, arg.AppKey, arg.UpdateTime, arg.AppID)
	return err
}

const updateAppById = `-- name: UpdateAppById :exec
UPDATE apps SET app_name = ?, app_description = ?, token_expiry = ?, 
token_nbf = ?, refresh_expiry = ?, refresh_nbf = ?, update_time = ?, rotation_period = ?
WHERE app_id = ?
LIMIT 1
`

type UpdateAppByIdParams struct {
	AppName        string         `json:"app_name"`
	AppDescription sql.NullString `json:"app_description"`
	TokenExpiry    int32          `json:"token_expiry"`
	TokenNbf       int32          `json:"token_nbf"`
	RefreshExpiry  int32          `json:"refresh_expiry"`
	RefreshNbf     int32          `json:"refresh_nbf"`
	UpdateTime     sql.NullInt64  `json:"update_time"`
	RotationPeriod int64          `json:"rotation_period"`
	AppID          string         `json:"app_id"`
}

func (q *Queries) UpdateAppById(ctx context.Context, arg UpdateAppByIdParams) error {
	_, err := q.db.ExecContext(ctx, updateAppById,
		arg.AppName,
		arg.AppDescription,
		arg.TokenExpiry,
		arg.TokenNbf,
		arg.RefreshExpiry,
		arg.RefreshNbf,
		arg.UpdateTime,
		arg.RotationPeriod,
		arg.AppID,
	)
	return err
}

const updatePKIRotationTime = `-- name: UpdatePKIRotationTime :exec
UPDATE apps SET last_rotate_time = ?
WHERE app_id = ?
LIMIT 1
`

type UpdatePKIRotationTimeParams struct {
	LastRotateTime sql.NullInt64 `json:"last_rotate_time"`
	AppID          string        `json:"app_id"`
}

func (q *Queries) UpdatePKIRotationTime(ctx context.Context, arg UpdatePKIRotationTimeParams) error {
	_, err := q.db.ExecContext(ctx, updatePKIRotationTime, arg.LastRotateTime, arg.AppID)
	return err
}

const verifyAppToken = `-- name: VerifyAppToken :one
SELECT count(app_id) FROM apps WHERE app_id = ? and app_key = ?
`

type VerifyAppTokenParams struct {
	AppID  string `json:"app_id"`
	AppKey string `json:"app_key"`
}

func (q *Queries) VerifyAppToken(ctx context.Context, arg VerifyAppTokenParams) (int64, error) {
	row := q.db.QueryRowContext(ctx, verifyAppToken, arg.AppID, arg.AppKey)
	var count int64
	err := row.Scan(&count)
	return count, err
}
