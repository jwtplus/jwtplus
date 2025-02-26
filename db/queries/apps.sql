-- name: GetAppByID :one
SELECT app_id, app_name, app_description, 
token_expiry, token_nbf, refresh_expiry, 
refresh_nbf, key_type, algo, rotation_period, add_time, 
update_time, last_rotate_time 
FROM apps
WHERE app_id = ?
LIMIT 1;

-- name: VerifyAppToken :one
SELECT count(app_id) FROM apps WHERE app_id = ? and app_key = ?;

-- name: GetAppForSigning :one
SELECT a.app_id, a.app_name, a.token_expiry, a.token_nbf, a.refresh_expiry, 
a.refresh_nbf, a.key_type, a.algo, b.key_id, b.private_key, b.public_key
FROM apps as a
LEFT JOIN app_keys as b on a.app_id = b.app_id
WHERE a.app_id = ? AND b.is_expired = 'no' AND b.is_revoked = 'no'
LIMIT 1;

-- name: GetAllApp :many
SELECT app_id, app_name, app_description, token_expiry, 
token_nbf, refresh_expiry, refresh_nbf, key_type, algo, 
rotation_period, add_time, update_time, last_rotate_time 
FROM apps;

-- name: InsertApp :exec
INSERT INTO apps (app_id, app_name, app_description, app_key,
token_expiry, token_nbf, refresh_expiry, 
refresh_nbf, key_type, algo, rotation_period, add_time) 
VALUES (?,?,?,?,?,?,?,?,?,?,?,?);

-- name: UpdateAppById :exec
UPDATE apps SET app_name = ?, app_description = ?, token_expiry = ?, 
token_nbf = ?, refresh_expiry = ?, refresh_nbf = ?, update_time = ?, rotation_period = ?
WHERE app_id = ?
LIMIT 1;

-- name: RotateAppKeyById :exec
UPDATE apps SET app_key = ?, update_time = ?
WHERE app_id = ?
LIMIT 1;

-- name: UpdatePKIRotationTime :exec
UPDATE apps SET last_rotate_time = ?
WHERE app_id = ?
LIMIT 1;

-- name: DeleteAppById :exec
DELETE FROM apps WHERE app_id = ? LIMIT 1;

-- name: DeleteAllApp :exec
DELETE FROM apps;
