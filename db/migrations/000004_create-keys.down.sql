ALTER TABLE `tokens` DROP FOREIGN KEY `tokens_fk_key_id`;
ALTER TABLE `app_keys` DROP FOREIGN KEY `app_keys_fk_key_id`;
DROP TABLE `app_keys`;