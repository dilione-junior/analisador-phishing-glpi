#!/usr/bin/env bash
# Prepara o GLPI do laboratório NG-SOC para os relatos de phishing, ou abre um chamado de teste.
#
#   bash glpi/preparar-glpi.sh                         -> cria grupo, categoria, tipos de solução e permissões
#   bash glpi/preparar-glpi.sh teste tests/amostras/phishing-banco.eml "Cliquei no link e digitei a senha"
#
# Durante a execução liga o login por senha na API do GLPI (só aceita pedidos de dentro do container);
# no final desliga, mesmo se der erro. A senha do admin vem do .env do GLPI do ng-soc-lab e nunca é impressa.
# Variável opcional: NGSOC_LAB (padrão: ../ng-soc-lab).
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
glpi=ng-soc-chamados-glpi-1
env_glpi="${NGSOC_LAB:-../ng-soc-lab}/infra/glpi/.env"
[ -f "$env_glpi" ] || { echo "Não achei $env_glpi (defina NGSOC_LAB com a pasta do ng-soc-lab)."; exit 1; }
docker ps --format '{{.Names}}' | grep -qx "$glpi" || { echo "O container $glpi não está rodando. Ligue o GLPI antes."; exit 1; }
le() { grep "^$1=" "$env_glpi" | cut -d= -f2- | tr -d '\r\n'; }

modo="${1:-estrutura}"
config() { docker exec "$glpi" php /var/www/glpi/bin/console config:set "$1" "$2" >/dev/null; }
final() { config enable_api_login_credentials 0; docker exec -u root "$glpi" rm -f /tmp/estrutura-phishing.php /tmp/relato-teste.eml
          echo "API do GLPI: login por senha desligado de novo."; }
trap final EXIT
config enable_api_login_credentials 1
docker cp glpi/estrutura-phishing.php "$glpi":/tmp/estrutura-phishing.php >/dev/null
if [ "$modo" = "teste" ]; then
    [ -f "${2:-}" ] || { echo "Informe o arquivo .eml do teste."; exit 1; }
    docker cp "$2" "$glpi":/tmp/relato-teste.eml >/dev/null
    docker exec -e GLPI_ADMIN_PASSWORD="$(le GLPI_ADMIN_PASSWORD)" "$glpi" php /tmp/estrutura-phishing.php teste /tmp/relato-teste.eml "${3:-Recebi este e-mail estranho.}"
else
    docker exec -e GLPI_ADMIN_PASSWORD="$(le GLPI_ADMIN_PASSWORD)" "$glpi" php /tmp/estrutura-phishing.php estrutura
fi
