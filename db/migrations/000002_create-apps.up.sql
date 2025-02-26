CREATE TABLE `apps` (
    `app_id` VARCHAR(26) NOT NULL , 
    `app_name` VARCHAR(255) NOT NULL , 
    `app_description` TEXT NULL DEFAULT NULL, 
    `app_key` VARCHAR(128) NOT NULL , 
    `token_expiry` INT(9) NOT NULL , 
    `token_nbf` INT(9) NOT NULL DEFAULT 0, 
    `refresh_expiry` INT(9) NOT NULL , 
    `refresh_nbf` INT(9) NOT NULL DEFAULT 300, 
    `key_type` ENUM('RSA','ECDSA') NOT NULL ,
    `algo` ENUM('RS256','RS384','RS512','ES256','ES384','ES512','PS256','PS384','PS512') NOT NULL DEFAULT 'ES256' , 
    `rotation_period` BIGINT(13) NOT NULL,
    `add_time` BIGINT(13) NOT NULL , 
    `update_time` BIGINT(13) NULL DEFAULT NULL , 
    `last_rotate_time` BIGINT(13) NULL DEFAULT NULL, 
    PRIMARY KEY (`app_id`)
) ENGINE = InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;