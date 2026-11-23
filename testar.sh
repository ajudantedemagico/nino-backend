#!/usr/bin/env bash
# Testa os fluxos de senha. Uso: ./testar.sh   (com a API no ar em localhost:5080)
A=http://localhost:5080; J='Content-Type: application/json'
p() { echo; echo "== $1"; }
p "1. senha fraca (deve dar 400)"
curl -s -X POST $A/auth/register -H "$J" -d '{"email":"t@ex.com","senha":"abc123","perfil":"Terapeuta"}'
p "2. cadastro com senha forte (201)"
curl -s -X POST $A/auth/register -H "$J" -d '{"email":"t@ex.com","senha":"Senha#Forte2026","perfil":"Terapeuta"}'
p "3. login (200 + token)"
T=$(curl -s -X POST $A/auth/login -H "$J" -d '{"email":"t@ex.com","senha":"Senha#Forte2026"}'); echo $T
TOKEN=$(echo $T | sed 's/.*"token":"\([^"]*\)".*/\1/')
p "4. rota protegida sem token (401)"; curl -s -o /dev/null -w "%{http_code}" $A/me
p "5. rota protegida com token (200)"; curl -s -H "Authorization: Bearer $TOKEN" $A/me
p "6. cinco senhas erradas e bloqueio (429 na 6a)"
for i in 1 2 3 4 5 6; do curl -s -o /dev/null -w "%{http_code} " -X POST $A/auth/login -H "$J" -d '{"email":"t@ex.com","senha":"errada"}'; done
echo
