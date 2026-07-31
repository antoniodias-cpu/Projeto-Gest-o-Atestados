<?php

declare(strict_types=1);

function load_env_file(string $filePath): void {
    if (!is_file($filePath) || !is_readable($filePath)) {
        return;
    }

    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            continue;
        }

        $parts = explode('=', $trimmed, 2);
        if (count($parts) !== 2) {
            continue;
        }

        $name = trim($parts[0]);
        $value = trim($parts[1]);
        if ($name === '' || getenv($name) !== false) {
            continue;
        }

        if (
            (str_starts_with($value, '"') && str_ends_with($value, '"')) ||
            (str_starts_with($value, "'") && str_ends_with($value, "'"))
        ) {
            $value = substr($value, 1, -1);
        }

        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

load_env_file(__DIR__ . '/../.env');

header('Content-Type: application/json; charset=utf-8');

session_name('gestao_php_sid');
session_start();

$dbConnection = strtolower(trim((string)(getenv('DB_CONNECTION') ?: 'sqlite')));

if ($dbConnection === 'mysql') {
    $dbHost = trim((string)(getenv('DB_HOST') ?: 'localhost'));
    $dbPort = trim((string)(getenv('DB_PORT') ?: '3306'));
    $dbName = trim((string)(getenv('DB_DATABASE') ?: ''));
    $dbUser = trim((string)(getenv('DB_USERNAME') ?: ''));
    $dbPass = (string)(getenv('DB_PASSWORD') ?: '');

    if ($dbName === '' || $dbUser === '') {
        http_response_code(500);
        echo json_encode(['ok' => false, 'message' => 'Configuracao MySQL incompleta.']);
        exit;
    }

    $dsn = sprintf('mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4', $dbHost, $dbPort, $dbName);
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} else {
    $dbPath = __DIR__ . '/../../data/auth.db';
    $pdo = new PDO('sqlite:' . $dbPath);
}

$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

if ($dbConnection === 'mysql') {
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS users (
            id INT NOT NULL AUTO_INCREMENT,
            professor_name VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            city VARCHAR(120) DEFAULT NULL,
            role VARCHAR(50) NOT NULL DEFAULT "user",
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uk_users_email (email),
            KEY idx_users_email (email)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS records (
            id INT NOT NULL AUTO_INCREMENT,
            nome VARCHAR(255) NOT NULL,
            turma VARCHAR(100) NOT NULL,
            turno VARCHAR(100) DEFAULT NULL,
            motivo VARCHAR(150) DEFAULT NULL,
            data_entrega VARCHAR(20) DEFAULT NULL,
            data_inicio VARCHAR(20) DEFAULT NULL,
            hora_inicio VARCHAR(20) DEFAULT NULL,
            dia_inicio VARCHAR(50) DEFAULT NULL,
            data_termino VARCHAR(20) DEFAULT NULL,
            hora_termino VARCHAR(20) DEFAULT NULL,
            dia_termino VARCHAR(50) DEFAULT NULL,
            created_by INT DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_records_nome (nome),
            KEY idx_records_turma (turma),
            KEY idx_records_turno (turno),
            KEY idx_records_created_by (created_by),
            CONSTRAINT fk_records_created_by FOREIGN KEY (created_by) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INT NOT NULL AUTO_INCREMENT,
            user_id INT NOT NULL,
            token_hash VARCHAR(255) NOT NULL,
            expires_at VARCHAR(64) NOT NULL,
            used_at DATETIME DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_reset_tokens_user_id (user_id),
            KEY idx_reset_tokens_token_hash (token_hash),
            CONSTRAINT fk_password_reset_tokens_user FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
} else {
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            professor_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            city TEXT,
            role TEXT NOT NULL DEFAULT "user",
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            turma TEXT NOT NULL,
            turno TEXT,
            motivo TEXT,
            data_entrega TEXT,
            data_inicio TEXT,
            hora_inicio TEXT,
            dia_inicio TEXT,
            data_termino TEXT,
            hora_termino TEXT,
            dia_termino TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )'
    );
}

function order_by_professor_name_sql(): string {
    $dbConnection = strtolower(trim((string)(getenv('DB_CONNECTION') ?: 'sqlite')));
    if ($dbConnection === 'mysql') {
        return ' ORDER BY professor_name ASC';
    }
    return ' ORDER BY professor_name COLLATE NOCASE ASC';
}

function normalize_email(string $email): string {
    return strtolower(trim($email));
}

function is_allowed_email(string $email): bool {
    return str_ends_with(normalize_email($email), '@profe.sed.sc.gov.br');
}

function json_input(): array {
    $raw = file_get_contents('php://input');
    if (!$raw) {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function json_response(int $status, array $payload): void {
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function sanitize_user(array $row): array {
    return [
        'id' => (int)$row['id'],
        'professorName' => $row['professor_name'],
        'email' => $row['email'],
        'city' => $row['city'],
        'role' => $row['role'],
        'createdAt' => $row['created_at']
    ];
}

function sanitize_record(array $row): array {
    return [
        'id' => (int)$row['id'],
        'nome' => $row['nome'] ?? '',
        'turma' => $row['turma'] ?? '',
        'turno' => $row['turno'] ?? '',
        'motivo' => $row['motivo'] ?? '',
        'dataentrega' => $row['data_entrega'] ?? '',
        'datainicio' => $row['data_inicio'] ?? '',
        'horaInicio' => $row['hora_inicio'] ?? '',
        'diaInicio' => $row['dia_inicio'] ?? '',
        'datatermino' => $row['data_termino'] ?? '',
        'horaTermino' => $row['hora_termino'] ?? '',
        'diaTermino' => $row['dia_termino'] ?? '',
        'createdAt' => $row['created_at'] ?? ''
    ];
}

function can_write_records(array $user): bool {
    if (($user['role'] ?? '') === 'admin') {
        return true;
    }
    return normalize_email((string)($user['email'] ?? '')) === 'supervisao@profe.sed.sc.gov.br';
}

function make_reset_token(): string {
    return bin2hex(random_bytes(32));
}

function hash_token(string $token): string {
    return hash('sha256', $token);
}

function token_expired(string $expiresAt): bool {
    $expires = strtotime($expiresAt);
    if ($expires === false) {
        return true;
    }
    return time() > $expires;
}

function now_plus_minutes_iso(int $minutes): string {
    return gmdate('c', time() + ($minutes * 60));
}

function env_bool(string $name, bool $default = false): bool {
    $raw = getenv($name);
    if ($raw === false || $raw === '') {
        return $default;
    }
    $value = strtolower(trim((string)$raw));
    return in_array($value, ['1', 'true', 'yes', 'on'], true);
}

function recovery_page_url(): string {
    $configured = trim((string)(getenv('RECOVERY_PAGE_URL') ?: ''));
    if ($configured !== '') {
        return $configured;
    }
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return $scheme . '://' . $host . '/recover.html';
}

function recovery_link(string $token): string {
    $base = recovery_page_url();
    $separator = str_contains($base, '?') ? '&' : '?';
    return $base . $separator . 'token=' . urlencode($token);
}

function smtp_send_reset_email(string $toEmail, string $token, string $expiresAt): array {
    $smtpHost = trim((string)(getenv('SMTP_HOST') ?: ''));
    $smtpPort = (int)(getenv('SMTP_PORT') ?: 0);
    $smtpUser = trim((string)(getenv('SMTP_USER') ?: ''));
    $smtpFromEmail = trim((string)(getenv('SMTP_FROM_EMAIL') ?: ''));
    $smtpFromName = trim((string)(getenv('SMTP_FROM_NAME') ?: 'Gestao de Atestados'));

    if ($smtpHost === '' || $smtpPort <= 0) {
        return ['sent' => false, 'reason' => 'smtp_not_configured'];
    }

    $link = recovery_link($token);
    $subject = 'Recuperacao de senha - Gestao de Atestados';
    $messageText = "Voce solicitou a recuperacao da sua senha.\n\n"
        . "Link de redefinicao: {$link}\n"
        . "Token: {$token}\n"
        . "Expira em: {$expiresAt}\n\n"
        . "Se voce nao solicitou, ignore este e-mail.";

    $fromEmail = $smtpFromEmail !== '' ? $smtpFromEmail : $smtpUser;
    $fromHeader = $fromEmail !== ''
        ? sprintf('From: %s <%s>', $smtpFromName, $fromEmail)
        : sprintf('From: %s', $smtpFromName);

    $headers = [
        $fromHeader,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8'
    ];

    $success = @mail($toEmail, $subject, $messageText, implode("\r\n", $headers));
    if ($success) {
        return ['sent' => true];
    }
    return ['sent' => false, 'reason' => 'mail_failed'];
}

function ensure_seed_user(PDO $pdo, string $professorName, string $email, string $password, string $city, string $role): void {
    $email = normalize_email($email);
    $check = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $check->execute(['email' => $email]);
    if ($check->fetch()) {
        return;
    }

    $stmt = $pdo->prepare('INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (:professor_name, :email, :password_hash, :city, :role)');
    $stmt->execute([
        'professor_name' => $professorName,
        'email' => $email,
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'city' => $city,
        'role' => $role
    ]);
}

function require_auth(PDO $pdo): array {
    $userId = $_SESSION['user_id'] ?? null;
    if (!$userId) {
        json_response(401, ['ok' => false, 'message' => 'Nao autenticado.']);
    }

    $stmt = $pdo->prepare('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $userId]);
    $user = $stmt->fetch();
    if (!$user) {
        json_response(401, ['ok' => false, 'message' => 'Sessao invalida.']);
    }

    return $user;
}

function require_admin(PDO $pdo): array {
    $user = require_auth($pdo);
    if (($user['role'] ?? 'user') !== 'admin') {
        json_response(403, ['ok' => false, 'message' => 'Apenas admin pode executar esta acao.']);
    }
    return $user;
}

ensure_seed_user($pdo, 'Administrador', 'admin123@profe.sed.sc.gov.br', 'Senha123', 'Joinville', 'admin');
ensure_seed_user($pdo, 'Supervisao', 'supervisao@profe.sed.sc.gov.br', 'Senha123', 'Joinville', 'admin');
ensure_seed_user($pdo, 'Priscila', 'priscila@profe.sed.sc.gov.br', 'Senha123', 'Joinville', 'user');
ensure_seed_user($pdo, 'Cesar', 'cesar@profe.sed.sc.gov.br', 'Senha123', 'Joinville', 'user');
