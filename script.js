// Exemplo de envio de dados do HTML para o Banco através da API da Vercel
fetch('/api/salvar-dados', {
    method: 'POST',
    body: JSON.stringify({ nome: "Exemplo" }),
    headers: { 'Content-Type': 'application/json' }
});
