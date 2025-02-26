CREATE TABLE `app_keys` (
    `key_id` VARCHAR(26) NOT NULL ,
    `app_id` VARCHAR(26) NOT NULL ,
    `public_key` TEXT NOT NULL ,
    `private_key` TEXT NOT NULL ,
    `key_type` ENUM('RSA','ECDSA') NOT NULL ,
    `key_algo` ENUM('RS256','RS384','RS512','ES256','ES384','ES512','PS256','PS384','PS512') NOT NULL ,
    `add_time` BIGINT(13) NOT NULL ,
    `exp_time` BIGINT(13) NOT NULL ,
    `is_revoked` ENUM('yes','no') NOT NULL DEFAULT 'no',
    `is_expired` ENUM('yes','no') NOT NULL DEFAULT 'no',
    PRIMARY KEY (`key_id`),
    INDEX (`app_id`)
) ENGINE = InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci; 

ALTER TABLE `app_keys` ADD CONSTRAINT `app_keys_fk_key_id`
    FOREIGN KEY (`app_id`)
    REFERENCES `apps`(`app_id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE; 

ALTER TABLE `tokens` ADD CONSTRAINT `tokens_fk_key_id`
    FOREIGN KEY (`key_id`) 
    REFERENCES `app_keys`(`key_id`) 
    ON DELETE CASCADE 
    ON UPDATE CASCADE; 