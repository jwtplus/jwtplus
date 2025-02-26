-- name: InsertKey :exec
INSERT INTO app_keys (key_id, app_id, public_key, private_key, key_type, key_algo, exp_time, add_time)
VALUES (?,?,?,?,?,?,?,?);

-- name: ExpireActiveKey :exec
UPDATE app_keys SET is_expired = ?
WHERE app_id = ? AND is_expired = 'no' AND is_revoked = 'no';

-- name: ExpireActiveKeyById :exec
UPDATE app_keys SET is_expired = ?
WHERE app_id = ? AND key_id = ? LIMIT 1;

-- name: GetPublicKeysByAppId :many
SELECT key_id, public_key, key_type, key_algo, exp_time, is_expired, is_revoked
FROM app_keys
WHERE app_id = ?;

-- name: GetAppKeyReadyForRotation :many
SELECT a.key_id, a.app_id, b.key_type, b.algo, b.rotation_period FROM app_keys as a 
LEFT JOIN apps as b on a.app_id = b.app_id
WHERE a.is_expired = "no" AND a.is_revoked = "no" AND a.exp_time < ?;

-- name: RevokeKeyById :exec
UPDATE app_keys SET is_revoked = ? WHERE app_id = ? AND key_id = ? LIMIT 1;