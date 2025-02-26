CREATE TABLE `tokens` (
    `token_id` VARCHAR(26) NOT NULL ,
    `apps_id` VARCHAR(26) NOT NULL ,
    `key_id` VARCHAR(26) NOT NULL,
    `sub` VARCHAR(128) NOT NULL ,
    `auth_token` TEXT NOT NULL ,
    `auth_token_hash` VARCHAR(128) NOT NULL ,
    `auth_token_iat` BIGINT(13) NOT NULL ,
    `auth_token_nbf` BIGINT(13) NOT NULL ,
    `auth_token_exp` BIGINT(13) NOT NULL ,
    `refresh_token` TEXT NOT NULL ,
    `refresh_token_hash` VARCHAR(128) NOT NULL ,
    `refresh_token_iat` BIGINT(13) NOT NULL ,
    `refresh_token_nbf` BIGINT(13) NOT NULL ,
    `refresh_token_exp` BIGINT(13) NOT NULL ,
    `ip_address` VARCHAR(24) NOT NULL ,
    `user_agent` VARCHAR(255) NOT NULL ,
    PRIMARY KEY (`token_id`),
    INDEX (`apps_id`, `key_id`)
) ENGINE = InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci; 


ALTER TABLE `tokens` 
    ADD FOREIGN KEY (`apps_id`) 
    REFERENCES `apps`(`app_id`) 
    ON DELETE CASCADE 
    ON UPDATE CASCADE; 