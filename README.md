# Nino backend – Etapa 1 (autenticação)

1. `cp .env.example .env` e edite os valores (senha do banco e JWT_KEY).
2. `docker compose up --build`
3. Em outro terminal: `./testar.sh`

Endpoints: POST /auth/register, /auth/login, /auth/trocar-senha,
/auth/esqueci-senha, /auth/redefinir-senha; GET /me (protegido), GET /health.

Esqueci a senha (modo desenvolvimento): o token aparece no log da API
(`docker compose logs api | grep DEV-ONLY`). Depois:
curl -X POST localhost:5080/auth/redefinir-senha -H 'Content-Type: application/json' \
  -d '{"token":"COLE_AQUI","novaSenha":"OutraSenha#2026"}'

Testar a troca periódica sem esperar 90 dias:
docker compose exec db psql -p 54329 -U nino_app -d nino \
  -c "update usuario set senha_alterada_em = now() - interval '100 days';"
e faça login: deve retornar 403 SENHA_EXPIRADA. Troque em /auth/trocar-senha.

## Etapa 2 – Logs e observabilidade
- Logs do PostgreSQL: conexões, desconexões, DDL e consultas lentas (flags no docker-compose.yml).
- Logs da API: eventos AUDIT (login, falhas, trocas e redefinições de senha) e requisições do Kestrel.
- Rotação: 3 arquivos de 10 MB por serviço (driver json-file do Docker).
  Conferir: docker inspect nino-backend-db-1 --format "{{.HostConfig.LogConfig.Config}}"
- Observabilidade: docker compose --profile obs up -d  (exige DD_API_KEY no .env)
