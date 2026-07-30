<?php

declare(strict_types=1);

$root = realpath(__DIR__ . '/..');
if ($root === false) {
    http_response_code(500);
    echo 'Workspace root nao encontrado.';
    exit;
}

$uriPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$filePath = realpath($root . $uriPath);

if ($filePath !== false && str_starts_with($filePath, $root) && is_file($filePath)) {
    return false;
}

if (str_starts_with($uriPath, '/api')) {
    require __DIR__ . '/api/index.php';
    return true;
}

if ($uriPath === '/' || $uriPath === '') {
    readfile($root . '/index.html');
    return true;
}

http_response_code(404);
echo 'Pagina nao encontrada.';
