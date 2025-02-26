-- name: InsertToken :exec
INSERT INTO tokens (token_id, apps_id, key_id, sub,
auth_token, auth_token_hash, auth_token_iat, auth_token_nbf, auth_token_exp, 
refresh_token, refresh_token_hash, refresh_token_iat, refresh_token_nbf, refresh_token_exp, 
ip_address, user_agent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);

-- name: GetTokenByAuthHash :one
SELECT a.token_id, a.apps_id, a.key_id, b.key_type, b.key_algo, b.public_key
FROM tokens as a
LEFT JOIN app_keys as b ON a.apps_id = b.app_id AND a.key_id = b.key_id
WHERE a.apps_id = ? AND a.auth_token_hash = ? AND a.auth_token_exp > ? AND a.auth_token_nbf < ?
LIMIT 1;

-- name: GetTokenByRefreshHash :one
SELECT a.token_id, a.apps_id, a.key_id, a.sub, a.auth_token, b.key_type, b.key_algo, b.public_key
FROM tokens as a
LEFT JOIN app_keys as b ON a.apps_id = b.app_id AND a.key_id = b.key_id
WHERE a.apps_id = ? AND a.refresh_token_hash = ? AND a.refresh_token_exp > ? AND a.refresh_token_nbf < ?
LIMIT 1;

-- name: GetActiveSessionAgainstSubject :many
SELECT token_id, key_id, 
auth_token_iat, auth_token_nbf, auth_token_exp, 
refresh_token_iat, refresh_token_nbf, refresh_token_exp,
ip_address, user_agent
FROM tokens
WHERE apps_id = ? AND sub = ? AND auth_token_exp > ? AND auth_token_nbf < ?;

-- name: DeleteTokenByAuthTokenHash :exec
DELETE FROM tokens WHERE apps_id = ? AND auth_token_hash = ?;

-- name: DeleteTokenByTokenId :exec
DELETE FROM tokens WHERE token_id = ? AND apps_id = ? LIMIT 1;

-- name: DeleteAllTokensByAppId :exec
DELETE FROM tokens WHERE apps_id = ?;

-- name: DeleteAllTokenByKeyId :exec
DELETE FROM tokens WHERE apps_id = ? AND key_id = ?;

-- name: DeleteExpiredTokens :exec
DELETE FROM tokens WHERE refresh_token_exp < ?;
