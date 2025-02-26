-- name: GetSettingByKey :one
SELECT setting_value
FROM settings
WHERE setting_key = ?
LIMIT 1;

-- name: InsertSetting :exec
INSERT INTO settings (setting_key, setting_value) 
VALUES (?, ?);

-- name: DeleteSettingByKey :exec
DELETE FROM settings WHERE setting_key = ? LIMIT 1;

-- name: UpdateSettingByKey :exec
UPDATE settings 
SET setting_value = ? 
WHERE setting_key = ?
LIMIT 1;

-- name: CountSettingByKey :one
SELECT COUNT(*) AS count 
FROM settings 
WHERE setting_key = ?;

-- name: CountSettingByKeyAndValue :one
SELECT COUNT(*) AS count 
FROM settings 
WHERE setting_key = ? AND
setting_value = ?;
