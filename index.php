<?php

declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$apiPos = strpos($path, '/api');
if ($apiPos !== false) {
    $path = substr($path, $apiPos + 4);
}
if (str_starts_with($path, '/index.php')) {
    $path = substr($path, strlen('/index.php'));
}
if ($path === '') {
    $path = '/';
}
$input = json_input();

if ($method === 'GET' && $path === '/health') {
    json_response(200, [
        'ok' => true,
        'provider' => 'php',
        'now' => gmdate('c')
    ]);
}

if ($method === 'POST' && $path === '/auth/login') {
    $email = normalize_email((string)($input['email'] ?? ''));
    $password = (string)($input['password'] ?? '');

    if ($email === '' || $password === '') {
        json_response(400, ['ok' => false, 'message' => 'Informe email e senha.']);
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, (string)$user['password_hash'])) {
        json_response(401, ['ok' => false, 'message' => 'Email ou senha invalidos.']);
    }

    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['role'] = $user['role'];

    json_response(200, ['ok' => true, 'user' => sanitize_user($user)]);
}

if ($method === 'POST' && $path === '/auth/register') {
    $professorName = trim((string)($input['professorName'] ?? ''));
    $email = normalize_email((string)($input['email'] ?? ''));
    $password = (string)($input['password'] ?? '');
    $city = trim((string)($input['city'] ?? ''));

    if ($professorName === '' || $email === '' || $password === '' || $city === '') {
        json_response(400, ['ok' => false, 'message' => 'Preencha todos os campos obrigatorios.']);
    }
    if (!is_allowed_email($email)) {
        json_response(400, ['ok' => false, 'message' => 'O email deve terminar com @profe.sed.sc.gov.br.']);
    }
    if (strlen($password) < 6) {
        json_response(400, ['ok' => false, 'message' => 'A senha precisa ter pelo menos 6 caracteres.']);
    }

    $check = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $check->execute(['email' => $email]);
    if ($check->fetch()) {
        json_response(409, ['ok' => false, 'message' => 'Ja existe usuario com este email.']);
    }

    $insert = $pdo->prepare('INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (:professor_name, :email, :password_hash, :city, :role)');
    $insert->execute([
        'professor_name' => $professorName,
        'email' => $email,
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'city' => $city,
        'role' => 'user'
    ]);

    $userId = (int)$pdo->lastInsertId();
    $stmt = $pdo->prepare('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $userId]);
    $user = $stmt->fetch();

    json_response(201, ['ok' => true, 'user' => sanitize_user($user ?: [])]);
}

if ($method === 'POST' && $path === '/auth/logout') {
    require_auth($pdo);
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool)$params['secure'], (bool)$params['httponly']);
    }
    session_destroy();
    json_response(200, ['ok' => true]);
}

if ($method === 'GET' && $path === '/auth/me') {
    $user = require_auth($pdo);
    json_response(200, ['ok' => true, 'user' => sanitize_user($user)]);
}

if ($method === 'POST' && $path === '/auth/password/forgot') {
    $email = normalize_email((string)($input['email'] ?? ''));
    $generic = [
        'ok' => true,
        'message' => 'Se o email existir, as instrucoes de recuperacao foram geradas.'
    ];

    if ($email === '' || !is_allowed_email($email)) {
        json_response(200, $generic);
    }

    $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();
    if (!$user) {
        json_response(200, $generic);
    }

    $token = make_reset_token();
    $tokenHash = hash_token($token);
    $expiresAt = now_plus_minutes_iso(30);

    $invalidate = $pdo->prepare('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE user_id = :user_id AND used_at IS NULL');
    $invalidate->execute(['user_id' => (int)$user['id']]);

    $insert = $pdo->prepare('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (:user_id, :token_hash, :expires_at)');
    $insert->execute([
        'user_id' => (int)$user['id'],
        'token_hash' => $tokenHash,
        'expires_at' => $expiresAt
    ]);

    $payload = $generic;
    $delivery = smtp_send_reset_email($email, $token, $expiresAt);
    $payload['delivery'] = !empty($delivery['sent']) ? 'sent' : 'not_sent';

    if (strtolower((string)getenv('APP_ENV')) !== 'production' && env_bool('EXPOSE_RESET_TOKEN', false)) {
        $payload['resetToken'] = $token;
        $payload['resetExpiresAt'] = $expiresAt;
    }
    json_response(200, $payload);
}

if ($method === 'POST' && $path === '/auth/password/reset') {
    $token = trim((string)($input['token'] ?? ''));
    $newPassword = (string)($input['newPassword'] ?? '');

    if ($token === '' || $newPassword === '') {
        json_response(400, ['ok' => false, 'message' => 'Token e nova senha sao obrigatorios.']);
    }
    if (strlen($newPassword) < 6) {
        json_response(400, ['ok' => false, 'message' => 'A nova senha deve ter ao menos 6 caracteres.']);
    }

    $tokenHash = hash_token($token);
            }
    json_response(200, ['ok' => true, 'message' => 'Senha redefinida com sucesso.']);


    $where = [];
    $params = [];

    if ($nome !== '') {
        $where[] = 'LOWER(nome) LIKE ?';
        $params[] = '%' . $nome . '%';
    }
    if ($turno !== '') {
        $where[] = 'LOWER(turno) LIKE ?';
        $params[] = '%' . $turno . '%';
    }
    if (!empty($turmas)) {
        $clauses = [];
        foreach ($turmas as $term) {
            $clauses[] = 'LOWER(turma) LIKE ?';
            $params[] = '%' . $term . '%';
        }
        $where[] = '(' . implode(' OR ', $clauses) . ')';
    }
    if (!is_allowed_email($email)) {
        json_response(400, ['ok' => false, 'message' => 'O email deve terminar com @profe.sed.sc.gov.br.']);
    }
    if (strlen($password) < 6) {
        json_response(400, ['ok' => false, 'message' => 'A senha precisa ter pelo menos 6 caracteres.']);
    }

    $check = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $check->execute(['email' => $email]);
    if ($check->fetch()) {
        json_response(409, ['ok' => false, 'message' => 'Ja existe usuario com este email.']);
    }

    $insert = $pdo->prepare('INSERT INTO users (professor_name, email, password_hash, city, role) VALUES (:professor_name, :email, :password_hash, :city, :role)');
    $insert->execute([
        'professor_name' => $professorName,
        'email' => $email,
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'city' => $city,
        'role' => $role
    ]);

    $id = (int)$pdo->lastInsertId();
    $stmt = $pdo->prepare('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $id]);
    $created = $stmt->fetch();
    json_response(201, ['ok' => true, 'user' => sanitize_user($created ?: [])]);
}

if (preg_match('#^/users/(\d+)$#', $path, $matches) === 1 && $method === 'PUT') {
    require_admin($pdo);

    $id = (int)$matches[1];
    $professorName = trim((string)($input['professorName'] ?? ''));
    $email = normalize_email((string)($input['email'] ?? ''));
    $city = trim((string)($input['city'] ?? ''));
    $role = (($input['role'] ?? 'user') === 'admin') ? 'admin' : 'user';
    $password = (string)($input['password'] ?? '');

    if ($id <= 0 || $professorName === '' || $email === '' || $city === '') {
        json_response(400, ['ok' => false, 'message' => 'Dados invalidos para atualizacao.']);
    }
    if (!is_allowed_email($email)) {
        json_response(400, ['ok' => false, 'message' => 'O email deve terminar com @profe.sed.sc.gov.br.']);
    }

    $currentStmt = $pdo->prepare('SELECT id, professor_name, email, city, role, created_at FROM users WHERE id = :id LIMIT 1');
    $currentStmt->execute(['id' => $id]);
    $current = $currentStmt->fetch();
    if (!$current) {
        json_response(404, ['ok' => false, 'message' => 'Usuario nao encontrado.']);
    }

    $collision = $pdo->prepare('SELECT id FROM users WHERE email = :email AND id != :id LIMIT 1');
    $collision->execute(['email' => $email, 'id' => $id]);
    if ($collision->fetch()) {
        json_response(409, ['ok' => false, 'message' => 'Este email ja pertence a outro usuario.']);
    }

    if ($password !== '') {
        if (strlen($password) < 6) {
            json_response(400, ['ok' => false, 'message' => 'Nova senha deve ter ao menos 6 caracteres.']);
        }
        $stmt = $pdo->prepare('UPDATE users SET professor_name = :professor_name, email = :email, city = :city, role = :role, password_hash = :password_hash WHERE id = :id');
        $stmt->execute([
            'professor_name' => $professorName,
            'email' => $email,
            'city' => $city,
            'role' => $role,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            'id' => $id
        ]);
    } else {
        $stmt = $pdo->prepare('UPDATE users SET professor_name = :professor_name, email = :email, city = :city, role = :role WHERE id = :id');
        $stmt->execute([
            'professor_name' => $professorName,
            'email' => $email,
            'city' => $city,
            'role' => $role,
            'id' => $id
        ]);
    }

    $currentStmt->execute(['id' => $id]);
    $updated = $currentStmt->fetch();
    json_response(200, ['ok' => true, 'user' => sanitize_user($updated ?: [])]);
}

if (preg_match('#^/users/(\d+)$#', $path, $matches) === 1 && $method === 'DELETE') {
    require_admin($pdo);

    $id = (int)$matches[1];
    if ($id <= 0) {
        json_response(400, ['ok' => false, 'message' => 'ID invalido.']);
    }

    $stmt = $pdo->prepare('SELECT id, email FROM users WHERE id = :id LIMIT 1');
    $stmt->execute(['id' => $id]);
    $user = $stmt->fetch();
    if (!$user) {
        json_response(404, ['ok' => false, 'message' => 'Usuario nao encontrado.']);
    }
    if (($user['email'] ?? '') === 'admin123@profe.sed.sc.gov.br') {
        json_response(400, ['ok' => false, 'message' => 'Nao e permitido apagar o admin principal.']);
    }

    $delete = $pdo->prepare('DELETE FROM users WHERE id = :id');
    $delete->execute(['id' => $id]);
    json_response(200, ['ok' => true]);
}

if ($method === 'POST' && $path === '/records') {
    $authUser = require_auth($pdo);
    if (!can_write_records($authUser)) {
        json_response(403, ['ok' => false, 'message' => 'Sem permissao para gravar atestados.']);
    }

    $nome = trim((string)($input['nome'] ?? ''));
    $turma = trim((string)($input['turma'] ?? ''));
    $turno = trim((string)($input['turno'] ?? ''));
    $motivo = trim((string)($input['motivo'] ?? ''));
    $dataEntrega = trim((string)($input['dataentrega'] ?? ''));
    $dataInicio = trim((string)($input['datainicio'] ?? ''));
    $horaInicio = trim((string)($input['horaInicio'] ?? ''));
    $diaInicio = trim((string)($input['diaInicio'] ?? ''));
    $dataTermino = trim((string)($input['datatermino'] ?? ''));
    $horaTermino = trim((string)($input['horaTermino'] ?? ''));
    $diaTermino = trim((string)($input['diaTermino'] ?? ''));

    if ($nome === '' || $turma === '' || $dataEntrega === '' || $dataInicio === '' || $dataTermino === '') {
        json_response(400, ['ok' => false, 'message' => 'Campos obrigatorios do atestado nao informados.']);
    }

    $stmt = $pdo->prepare('INSERT INTO records (nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_by) VALUES (:nome, :turma, :turno, :motivo, :data_entrega, :data_inicio, :hora_inicio, :dia_inicio, :data_termino, :hora_termino, :dia_termino, :created_by)');
    $stmt->execute([
        'nome' => $nome,
        'turma' => $turma,
        'turno' => $turno,
        'motivo' => $motivo,
        'data_entrega' => $dataEntrega,
        'data_inicio' => $dataInicio,
        'hora_inicio' => $horaInicio,
        'dia_inicio' => $diaInicio,
        'data_termino' => $dataTermino,
        'hora_termino' => $horaTermino,
        'dia_termino' => $diaTermino,
        'created_by' => (int)($authUser['id'] ?? 0)
    ]);

    $id = (int)$pdo->lastInsertId();
    $select = $pdo->prepare('SELECT * FROM records WHERE id = :id LIMIT 1');
    $select->execute(['id' => $id]);
    $record = $select->fetch();

    json_response(201, ['ok' => true, 'record' => sanitize_record($record ?: [])]);
}

if (preg_match('#^/records/(\d+)$#', $path, $matches) === 1 && ($method === 'PUT' || $method === 'POST')) {
    $authUser = require_auth($pdo);
    if (!can_write_records($authUser)) {
        json_response(403, ['ok' => false, 'message' => 'Sem permissao para editar atestados.']);
    }

    $id = (int)$matches[1];
    $nome = trim((string)($input['nome'] ?? ''));
    $turma = trim((string)($input['turma'] ?? ''));
    $turno = trim((string)($input['turno'] ?? ''));
    $motivo = trim((string)($input['motivo'] ?? ''));
    $dataEntrega = trim((string)($input['dataentrega'] ?? ''));
    $dataInicio = trim((string)($input['datainicio'] ?? ''));
    $horaInicio = trim((string)($input['horaInicio'] ?? ''));
    $diaInicio = trim((string)($input['diaInicio'] ?? ''));
    $dataTermino = trim((string)($input['datatermino'] ?? ''));
    $horaTermino = trim((string)($input['horaTermino'] ?? ''));
    $diaTermino = trim((string)($input['diaTermino'] ?? ''));

    if ($id <= 0 || $nome === '' || $turma === '' || $dataEntrega === '' || $dataInicio === '' || $dataTermino === '') {
        json_response(400, ['ok' => false, 'message' => 'Campos obrigatorios do atestado nao informados.']);
    }

    $check = $pdo->prepare('SELECT id FROM records WHERE id = :id LIMIT 1');
    $check->execute(['id' => $id]);
    if (!$check->fetch()) {
        json_response(404, ['ok' => false, 'message' => 'Registro nao encontrado.']);
    }

    $stmt = $pdo->prepare('UPDATE records SET nome = :nome, turma = :turma, turno = :turno, motivo = :motivo, data_entrega = :data_entrega, data_inicio = :data_inicio, hora_inicio = :hora_inicio, dia_inicio = :dia_inicio, data_termino = :data_termino, hora_termino = :hora_termino, dia_termino = :dia_termino WHERE id = :id');
    $stmt->execute([
        'nome' => $nome,
        'turma' => $turma,
        'turno' => $turno,
        'motivo' => $motivo,
        'data_entrega' => $dataEntrega,
        'data_inicio' => $dataInicio,
        'hora_inicio' => $horaInicio,
        'dia_inicio' => $diaInicio,
        'data_termino' => $dataTermino,
        'hora_termino' => $horaTermino,
        'dia_termino' => $diaTermino,
        'id' => $id
    ]);

    $select = $pdo->prepare('SELECT * FROM records WHERE id = :id LIMIT 1');
    $select->execute(['id' => $id]);
    $record = $select->fetch();

    json_response(200, ['ok' => true, 'record' => sanitize_record($record ?: [])]);
}

if ($method === 'GET' && $path === '/records') {
    require_auth($pdo);

    $nome = strtolower(trim((string)($_GET['nome'] ?? '')));
    $turno = strtolower(trim((string)($_GET['turno'] ?? '')));
    $turmasCsv = trim((string)($_GET['turmas'] ?? ''));
    $turmas = [];
    if ($turmasCsv !== '') {
        foreach (explode(',', $turmasCsv) as $part) {
            $term = strtolower(trim($part));
            if ($term !== '') {
                $turmas[] = $term;
            }
         }
     }

    $where = [];
    $params = [];

    if ($nome !== '') {
        $where[] = 'LOWER(nome) LIKE ?';
        $params[] = '%' . $nome . '%';
    }
    if ($turno !== '') {
        $where[] = 'LOWER(turno) LIKE ?';
        $params[] = '%' . $turno . '%';
    }
    if (!empty($turmas)) {
        $clauses = [];
        foreach ($turmas as $term) {
            $clauses[] = 'LOWER(turma) LIKE ?';
            $params[] = '%' . $term . '%';
        }
        $where[] = '(' . implode(' OR ', $clauses) . ')';
    }
 
     $sql = 'SELECT id, nome, turma, turno, motivo, data_entrega, data_inicio, hora_inicio, dia_inicio, data_termino, hora_termino, dia_termino, created_at FROM records';
     if (!empty($where)) {
         $sql .= ' WHERE ' . implode(' AND ', $where);
@@
 if ($method === 'DELETE' && $path === '/records') {
     $authUser = require_auth($pdo);
     if (!can_write_records($authUser)) {
         json_response(403, ['ok' => false, 'message' => 'Sem permissao para apagar atestados.']);
@@
 }
 
 json_response(404, ['ok' => false, 'message' => 'Endpoint nao encontrado.']);
