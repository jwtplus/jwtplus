CREATE TABLE `settings` (
  `setting_key` VARCHAR(255) NOT NULL PRIMARY KEY,
  `setting_value` LONGTEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
