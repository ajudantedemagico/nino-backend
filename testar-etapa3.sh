#!/usr/bin/env bash
# Uso: ./testar-etapa3.sh   (precisa de um terapeuta cadastrado; usa t@ex.com)
A=http://localhost:5080; J='Content-Type: application/json'
SENHA=${1:-Senha#Forte2026}
T=$(curl -s -X POST $A/auth/login -H "$J" -d "{\"email\":\"t@ex.com\",\"senha\":\"$SENHA\"}")
TOKEN=$(echo $T | sed 's/.*"token":"\([^"]*\)".*/\1/'); H="Authorization: Bearer $TOKEN"
echo "== 1. cadastra crianca";  C=$(curl -s -X POST $A/criancas -H "$J" -H "$H" -d '{"nome":"Ana"}'); echo $C
ID=$(echo $C | sed 's/.*"id":"\([^"]*\)".*/\1/')
echo; echo "== 2. registra emocoes (criptografadas no banco)"
curl -s -X POST $A/criancas/$ID/emocoes -H "$J" -H "$H" -d '{"emocao":"Triste"}'; echo
curl -s -X POST $A/criancas/$ID/emocoes -H "$J" -H "$H" -d '{"emocao":"Ansioso"}'; echo
echo "== 3. le as emocoes pela API (descriptografadas)"
curl -s $A/criancas/$ID/emocoes -H "$H"; echo
echo "== 4. emocao invalida (400)"
curl -s -X POST $A/criancas/$ID/emocoes -H "$J" -H "$H" -d '{"emocao":"x"}'; echo
echo "== 5. sem token (401)"; curl -s -o /dev/null -w "%{http_code}\n" $A/criancas/$ID/emocoes
echo "== 6. busca por nome"; curl -s "$A/criancas?nome=an" -H "$H"; echo
