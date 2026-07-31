SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `password_reset_tokens`;
DROP TABLE IF EXISTS `records`;
DROP TABLE IF EXISTS `users`;

CREATE TABLE `users` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `professor_name` VARCHAR(255) NOT NULL,
    `email` VARCHAR(255) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `city` VARCHAR(120) DEFAULT NULL,
    `role` VARCHAR(50) NOT NULL DEFAULT 'user',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_users_email` (`email`),
    KEY `idx_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `records` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `nome` VARCHAR(255) NOT NULL,
    `turma` VARCHAR(100) NOT NULL,
    `turno` VARCHAR(100) DEFAULT NULL,
    `motivo` VARCHAR(150) DEFAULT NULL,
    `data_entrega` VARCHAR(20) DEFAULT NULL,
    `data_inicio` VARCHAR(20) DEFAULT NULL,
    `hora_inicio` VARCHAR(20) DEFAULT NULL,
    `dia_inicio` VARCHAR(50) DEFAULT NULL,
    `data_termino` VARCHAR(20) DEFAULT NULL,
    `hora_termino` VARCHAR(20) DEFAULT NULL,
    `dia_termino` VARCHAR(50) DEFAULT NULL,
    `created_by` INT DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_records_nome` (`nome`),
    KEY `idx_records_turma` (`turma`),
    KEY `idx_records_turno` (`turno`),
    KEY `idx_records_created_by` (`created_by`),
    CONSTRAINT `fk_records_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `password_reset_tokens` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `user_id` INT NOT NULL,
    `token_hash` VARCHAR(255) NOT NULL,
    `expires_at` VARCHAR(64) NOT NULL,
    `used_at` DATETIME DEFAULT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_reset_tokens_user_id` (`user_id`),
    KEY `idx_reset_tokens_token_hash` (`token_hash`),
    CONSTRAINT `fk_password_reset_tokens_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `users` (`id`, `professor_name`, `email`, `password_hash`, `city`, `role`, `created_at`) VALUES
    (1, 'Administrador', 'admin123@profe.sed.sc.gov.br', '$2a$10$Q4Yzf5vYmjmJ8qzsQIftk.Rzrof4mqqWVGk8EgWXyWvdsnzVQ.RVO', 'Joinville', 'admin', '2026-07-27 19:22:48'),
    (2, 'Maria Helena', 'supervisao@profe.sed.sc.gov.br', '$2a$10$J/DUoYiuCJl.pDzFdh0Yp.9zQIJIdjCHDo4roCJCP/.Td9k1ZZjmC', 'Joinville', 'user', '2026-07-27 19:22:48'),
    (3, 'Ronnan', '375025@profe.sed.sc.gov.br', '$2a$10$KaKQpjK3ATwzaV0gi7HTeurioT.1lVpQrQyAZHVqlKzRaK3XYU/oi', 'Joinville', 'user', '2026-07-27 19:26:26'),
    (4, 'Antonio Dias', '398812@profe.sed.sc.gov.br', '$2a$10$Tevy9/btrSN9FH3Ns44mqO3LKZxewcoPL2FrjRunj7U5baY79dYvu', 'Joinville', 'user', '2026-07-27 20:28:03'),
    (5, 'Roberli', '652976@profe.sed.sc.gov.br', '$2a$10$mLqjX4tP95W9EOlnPDjXqeO8KP2Jlty.mBqnCILeK4Uy3Qm8GHNv2', 'Joinville', 'user', '2026-07-27 21:32:02');

INSERT INTO `records` (`id`, `nome`, `turma`, `turno`, `motivo`, `data_entrega`, `data_inicio`, `hora_inicio`, `dia_inicio`, `data_termino`, `hora_termino`, `dia_termino`, `created_by`, `created_at`) VALUES
    (1, 'Kaua F. de Oliveira', '3MEC2', 'Vespertino', 'Atestado', '13/03/2026', '13/03/2026', '', 'Sexta', '13/03/2026', '', 'Sexta', 1, '2026-07-27 19:37:55'),
    (2, 'Ronaia da S. Vieira', '4ET3', 'Vespertino', 'Atestado', '23/03/2026', '06/03/2026', '', 'Sexta', '06/03/2026', '', 'Sexta', 1, '2026-07-27 19:38:57'),
    (3, 'Kidver J. R. Almao', '4ET1', 'Matutino', 'Atestado', '03/06/2026', '25/05/2026', '', 'Segunda', '25/05/2026', '', 'Segunda', 1, '2026-07-27 19:40:12'),
    (5, 'Valdenesio V. Kreuch', '1ET1', 'Matutino', 'Declaração', '06/03/2026', '05/03/2026', '', 'Quinta', '05/03/2026', '', 'Quinta', 1, '2026-07-27 19:43:27'),
    (6, 'Reginaldo A. Lourenço', '3AUI3', 'Noturno', 'Atestado', '26/03/2026', '23/03/2026', '', 'Segunda', '24/03/2026', '', 'Terca', 1, '2026-07-27 21:00:31'),
    (7, 'Emyer Nicolas M.R.', '4EM3', 'Noturno', 'Atestado', '22/04/2026', '16/04/2026', '', 'Quinta', '17/04/2026', '', 'Sexta', 1, '2026-07-27 23:55:30'),
    (11, 'CAMILLI VITÓRIA DA SILVA', '3SEG', 'Noturno', 'Atestado', '08/04/2026', '08/04/2026', '', 'Quarta', '08/04/2026', '', 'Quarta', 1, '2026-07-28 00:58:32'),
    (12, 'MANUELA VITORIA', '3ADM', 'EMIEP', 'Atestado', '22/05/2026', '14/05/2026', '', 'Quinta', '14/05/2026', '', 'Quinta', 1, '2026-07-28 01:01:02'),
    (13, 'GIOVANA CAROLINA DE MEDEIRO', '3ADM', 'EMIEP', 'Atestado', '03/06/2026', '03/06/2026', '', 'Quarta', '03/06/2026', '', 'Quarta', 1, '2026-07-28 01:02:02'),
    (14, 'MARIA ISABEL DE FRANÇA SALES', '3MKT', 'EMIEP', 'Atestado', '16/03/2026', '10/03/2026', '', 'Terca', '11/03/2026', '', 'Quarta', 1, '2026-07-28 01:14:46'),
    (15, 'THUANNY AGRA PREBIANCA', '3RH2', 'EMIEP', 'Atestado', '10/04/2026', '30/03/2026', '', 'Segunda', '31/03/2026', '', 'Terca', 1, '2026-07-28 13:50:24'),
    (16, 'LETICIA RAISSA RIBEIRO COELHO', '3RH2', 'EMIEP', 'Atestado', '15/06/2026', '12/06/2026', '', 'Sexta', '12/06/2026', '', 'Sexta', 1, '2026-07-28 13:51:48'),
    (17, 'Valeria Eduarda T. Moraes', '1ADM3', 'Noturno', 'Atestado', '18/03/2026', '16/03/2026', '', 'Segunda', '17/03/2026', '', 'Terca', 1, '2026-07-28 14:07:41'),
    (18, 'Viviane L. Neves Marcilio', '3ADM3', 'Noturno', 'Atestado', '11/03/2026', '02/03/2026', '', 'Segunda', '11/03/2026', '', 'Quarta', 1, '2026-07-28 14:23:32');

INSERT INTO `password_reset_tokens` (`id`, `user_id`, `token_hash`, `expires_at`, `used_at`, `created_at`) VALUES
    (1, 4, '443e9cbf18085e008e79c9a2d37508d7901f6723c1702b2b30daeeb73b12c3fb', '2026-07-28T01:59:36.144Z', NULL, '2026-07-28 01:29:36');

SET FOREIGN_KEY_CHECKS = 1;