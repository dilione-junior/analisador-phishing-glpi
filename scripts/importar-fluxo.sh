#!/usr/bin/env bash
# Importa os dois fluxos no n8n do laboratório (Docker) e os publica.
# Atenção: substitui a versão que estiver no n8n com os mesmos ids (phishAnalisa0001 e phishDecisao0001).
# Se alterou os fluxos pela tela do n8n, exporte-os antes ou as mudanças serão perdidas.
# Credenciais já existentes no n8n (GLPI, Redis, Gemini, VirusTotal, abuse.ch) são reaproveitadas.
#
# Uso:  bash scripts/importar-fluxo.sh [nome-do-container]   (padrão: ng-soc-automacao-n8n-1)
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
export PYTHONIOENCODING=utf-8

n8n="${1:-ng-soc-automacao-n8n-1}"
tmp=$(mktemp -d -p . .importacao.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

python scripts/gerar-fluxo.py

# O n8n precisa destas variáveis (infra/n8n/.env do ng-soc-lab, repassadas no compose.yaml).
faltam=""
for v in PHISHING_TELEGRAM_TOKEN PHISHING_TELEGRAM_CHAT_ID PHISHING_ANALISTAS; do
    [ -n "$(docker exec "$n8n" printenv "$v" 2>/dev/null || true)" ] || faltam="$faltam $v"
done
[ -z "$faltam" ] || echo "AVISO: faltam no n8n as variáveis:$faltam (o Telegram não vai funcionar até configurar; veja o README)."

docker exec "$n8n" sh -c 'umask 077; n8n export:credentials --all --output=/tmp/cred-lista.json >/dev/null 2>&1; cat /tmp/cred-lista.json; rm -f /tmp/cred-lista.json' \
    | python -c "import json,sys; print(json.dumps([{k: c[k] for k in ('id','name','type')} for c in json.load(sys.stdin)]))" > "$tmp/credenciais.json"

for fluxo in phishing-analisa-relatos:phishAnalisa0001 phishing-decisoes-analista:phishDecisao0001; do
    arquivo=${fluxo%%:*}; id=${fluxo##*:}
    echo "Credenciais de $arquivo:"
    python scripts/ajustar-credenciais.py "workflow/$arquivo.json" "$tmp/credenciais.json" > "$tmp/$arquivo.json"
    docker cp "$tmp/$arquivo.json" "$n8n":/tmp/"$arquivo".json
    docker exec "$n8n" n8n import:workflow --input=/tmp/"$arquivo".json
    docker exec -u root "$n8n" rm -f /tmp/"$arquivo".json
    docker exec "$n8n" n8n publish:workflow --id="$id"
done
docker restart "$n8n" >/dev/null
echo "n8n reiniciado. Os fluxos começam a rodar sozinhos (a cada 2 min e a cada 1 min)."
echo "Dica: as primeiras execuções logo após o restart podem usar a versão anterior; espere 1-2 min antes de testar."
