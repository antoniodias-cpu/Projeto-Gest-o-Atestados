# Sistema Completo (PHP + Node.js)

Este projeto agora possui:

- login e sessao no servidor
- CRUD de usuarios (admin)
- atestados no banco SQLite com filtros no servidor
- recuperacao de senha por token seguro
- frontend e API no mesmo host (sem CORS)

## Estrutura

- backend/node: app Node.js (API + frontend estatico)
- backend/php/api: API PHP (mesmos endpoints REST)
- backend/php/router.php: roteador para servir frontend + API no mesmo host
- backend/data/auth.db: banco SQLite compartilhado

## Rodar com Node.js (recomendado)

1. Abra terminal em backend/node
2. Instale dependencias:

   npm install

3. Inicie:

   npm start

4. Acesse:

   ./index.html

Tudo (HTML + API) roda no mesmo host/porta.

Configuracao SMTP no Node:

1. Copie backend/node/.env.example para backend/node/.env
2. Preencha SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS e SMTP_FROM_EMAIL
3. Reinicie o servidor Node

## Rodar com PHP

No terminal, na pasta raiz do projeto HTML, execute:

php -S localhost:8000 backend/php/router.php

Acesse:

./index.html

Tambem fica tudo no mesmo host/porta.

Configuracao SMTP no PHP:

1. Defina variaveis de ambiente no sistema (SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_FROM_EMAIL)
2. Opcional: use backend/php/.env.example como referencia de valores
3. Reinicie o servidor PHP

## Endpoints principais

Autenticacao:

- GET /api/health
- POST /api/auth/register
- POST /api/auth/login
- POST /api/auth/logout
- GET /api/auth/me
- POST /api/auth/password/forgot
- POST /api/auth/password/reset

Usuarios (admin):

- GET /api/users
- POST /api/users
- PUT /api/users/:id
- DELETE /api/users/:id

Atestados:

- POST /api/records
- GET /api/records
- DELETE /api/records

Filtros server-side em /api/records:

- nome=<texto>
- turno=<texto>
- turmas=<turma1,turma2,turma3>

## Fluxo de recuperacao de senha

1. A pagina recover.html chama POST /api/auth/password/forgot com o e-mail.
2. O servidor gera token aleatorio e salva apenas hash + expiracao no banco.
3. O servidor tenta enviar o token por e-mail SMTP.
4. O token expira em 30 minutos e e invalidado apos uso.
5. POST /api/auth/password/reset troca a senha com hash bcrypt.

Seguranca de token em desenvolvimento:

- O token so aparece na resposta se EXPOSE_RESET_TOKEN=1 e ambiente nao for producao.
- Em producao, mantenha EXPOSE_RESET_TOKEN=0.

## Usuarios seed

- admin123@profe.sed.sc.gov.br / Senha123 (admin)
- supervisao@profe.sed.sc.gov.br / Senha123 (admin)

## Observacoes

- As senhas sao armazenadas com hash bcrypt.
- O banco e compartilhado entre Node e PHP em backend/data/auth.db.
