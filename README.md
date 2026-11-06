# Analisador de Relatos de Phishing (GLPI + IA + Telegram)

Triagem automática dos chamados do GLPI em que um usuário relata **phishing, e-mail ou contato suspeito**.
A IA analisa o caso com as evidências técnicas, o analista recebe a ficha num **grupo do Telegram só de relatos de phishing**
e decide com um clique (**phishing**, **legítimo**, **spam** ou **escalar N2**). A decisão volta para o GLPI: o usuário recebe a resposta e o chamado é encerrado.

Faz parte do laboratório [NG-SOC](../ng-soc-lab) e reaproveita a mesma infraestrutura (n8n, GLPI, Redis) e as chaves de reputação do
[Scanner de Segurança Web](../scanner-seguranca-web). Custo zero: só serviços gratuitos.

Tudo roda num **único fluxo do n8n, `analisador-phishing-glpi-ia`**, com duas rotinas: cada uma tem o seu gatilho
(análise a cada 2 min, decisões a cada 1 min) e o nó **Qual rotina?** manda cada execução para o seu ramo.

```
Usuário abre chamado no GLPI                      Rotina 1: análise (a cada 2 min)
categoria "Segurança > Phishing e      ──────►    1. busca chamados ABERTOS da categoria + grupo Segurança da Informação
e-mail suspeito" (anexa o .eml)                   2. lê o relato, os acompanhamentos e o .eml/.msg anexado
           │                                      3. extrai remetente real, SPF/DKIM/DMARC, IP de origem, links, anexos, sinais
           │ grupo "Segurança da Informação"      4. reputação (só leitura): VirusTotal, URLhaus, RDAP (idade do domínio)
           ▼ (atribuído pela categoria)           5. IA (Gemini) dá o parecer  →  travas  →  sugestão final
                                                  6. acompanhamento PRIVADO no GLPI + ficha no Telegram com botões

Analista no grupo "Relatos de Phishing"           Rotina 2: decisões (a cada 1 min, resposta quase imediata)
  [🎣 É phishing] [✅ É legítimo]       ──────►    nota interna (decisão, checklist, IOCs) + resposta ao usuário (texto fixo)
  [📨 Spam]       [⬆️ Escalar N2]                  + solução no GLPI (ou inclui o grupo SOC N2) + confirmação no grupo
  /nota 123 texto · /reanalisar 123                + métrica: a IA acertou?
```

## Visão do analista SOC

A ficha que chega no Telegram responde às perguntas da triagem de phishing, nesta ordem:

1. **O que a IA acha e quão grave é**: sugestão, confiança, gravidade, tipo de ataque e técnica MITRE ATT&CK (T1566.001 anexo, T1566.002 link...).
2. **O usuário interagiu?** Se disse que *clicou*, *digitou senha*, *abriu o anexo*, *respondeu* ou *pagou*, aparece em destaque
   (com o trecho do relato) e a gravidade sobe. "Não cliquei" conta como negação.
3. **Quem mandou de verdade**: From real (o último `<...>`, não o nome de exibição), Reply-To, Return-Path,
   SPF/DKIM/DMARC (só o `Authentication-Results` de cima vale: os de baixo podem ser forjados) e o IP de origem.
4. **Evidências** e **sinais de legitimidade**, para o analista concordar ou discordar com base em fatos.
5. **Reputação**: VirusTotal (link, domínio, hash do anexo), URLhaus e idade do domínio.
6. **Ações recomendadas**: as de resposta a incidente vêm primeiro (trocar senha, isolar máquina, acionar o banco).
7. **IOCs desarmados** (`hxxps://site[.]com`), prontos para copiar para o bloqueio sem virar link clicável.

O que acontece em cada decisão:

| Botão | No GLPI | Para o usuário (texto fixo) |
|---|---|---|
| 🎣 É phishing | nota interna com checklist de resposta e IOCs; solução **Phishing confirmado** | "confirmamos que é phishing: não clique, apague; se clicou ou digitou a senha, responda agora" |
| ✅ É legítimo | nota interna; solução **Contato legítimo** | "o contato é legítimo; na dúvida, confirme por canal oficial" |
| 📨 Spam | nota interna; solução **Spam (não malicioso)** | "é propaganda, sem sinal de golpe; pode apagar" |
| ⬆️ Escalar N2 | nota interna; grupo **SOC N2** incluído (chamado continua aberto) | "encaminhado para análise aprofundada; não interaja com a mensagem" |

Comandos no grupo: `/nota 123 texto` (nota interna, ex.: "bloqueei o domínio no proxy"), `/reanalisar 123`
(analisa de novo, ex.: o usuário anexou o e-mail depois) e `/ajuda`.

O roteiro completo de atendimento está em [docs/playbook-phishing.md](docs/playbook-phishing.md).

## O que a análise olha

| Sinal | Peso | Exemplo |
|---|---|---|
| VirusTotal: 3+ motores maliciosos | +40 (forte) | link marcado por 7/94 motores |
| URLhaus: host listado | +40 (forte) | host distribuindo phishing/malware |
| Link disfarçado | +25 | o texto mostra `itau.com.br`, o link leva para outro domínio |
| Domínio parecido / marca imitada | +20 a +25 | `itau-seguranca...`, `micros0ft...`, nome "Microsoft 365" com domínio qualquer |
| Anexo perigoso ou extensão dupla | +25 | `boleto.pdf.html`, `.iso`, `.lnk`, `.js`, Office com macro |
| DMARC fail / SPF fail / DKIM fail | +20 / +15 / +10 | o e-mail não prova que veio de quem diz |
| Domínio registrado há menos de 30 dias | +20 | RDAP |
| Nome de exibição com outro e-mail | +20 | `"Banco <atendimento@banco.com>" <golpe@x.com>` |
| Link para IP, com `usuário@`, punycode | +15 a +20 | `http://1.2.3.4/login` |
| Reply-To para outro domínio | +15 | respostas vão para um Gmail |
| Fraude do "chefe" (BEC) | +15 | "estou em reunião, compre cartões-presente" |
| Urgência, pedido de senha, pagamento, QR Code | +10 cada | "sua conta será bloqueada em 24 horas" |
| Webmail gratuito falando em nome de empresa | +10 | "Financeiro" usando Gmail |
| SPF + DKIM + DMARC passando | −15 | o e-mail saiu mesmo do domínio (não quer dizer que o domínio é confiável) |

A soma vira a **nota automática** (0 a 100). A IA lê o dossiê completo e dá o parecer, mas com travas:

- evidência forte (VirusTotal 3+ ou URLhaus) **nunca** vira "legítimo" ou "spam";
- nota automática 50+ não vira "legítimo": no máximo "inconclusivo";
- a gravidade sobe pelo que o usuário fez (digitou senha / abriu anexo / pagou = **crítica**);
- IA fora do ar ou resposta fora do formato = vale o parecer automático (o relato não fica parado).

## Segurança do próprio analisador

O e-mail analisado é **escrito pelo atacante**. Por isso:

- **Nada é aberto nem visitado.** Links e domínios são só consultados em bases de reputação (consulta, não envio).
  Anexos que não são e-mail (PDF, Office, executáveis) nunca são baixados: vale o SHA-1 que o GLPI já calcula.
  O `.eml`/`.msg` é lido como texto.
- **Injeção de prompt:** o dossiê vai para a IA marcado como dado não confiável; a IA não tem ferramentas e só devolve JSON,
  que é validado. As travas acima impedem um e-mail de "convencer" a IA a dizer que é seguro.
- **Nada escrito pela IA vai para o usuário.** As respostas ao usuário são textos fixos (em `src/montar-acoes.js`):
  um e-mail malicioso não consegue fazer o SOC mandar um golpe ao usuário.
- **Tudo é escapado** antes de ir para o Telegram e para o GLPI, e os IOCs são **desarmados**.
- **Quem pode decidir:** só cliques vindos do grupo configurado e de IDs do Telegram listados em `PHISHING_ANALISTAS`.
  Sem configuração, nada é aceito. Uma decisão por chamado (trava no Redis), mesmo com dois analistas clicando juntos.
- **A IA só sugere.** Toda decisão é humana e fica registrada no GLPI com o nome e o ID do analista.
- **Privacidade (LGPD):** o conteúdo do e-mail e o relato vão para o Gemini. No plano gratuito o Google pode usar os dados
  para melhorar os produtos. No laboratório os dados são **fictícios**; com dados reais, use um plano pago
  (ou um modelo local) e avise o encarregado de dados.

## Instalação no laboratório

Pré-requisitos: o [ng-soc-lab](../ng-soc-lab) rodando (n8n, GLPI, Redis), a credencial `GLPI (n8n-api)` no n8n e as credenciais
do scanner (`Gemini`, `VirusTotal (x-apikey)`, `abuse.ch (Auth-Key)`). Comandos no Git Bash, a partir desta pasta.

**1. Estrutura no GLPI** (grupo, categoria visível para o usuário, tipos de solução, leitura de anexos para o `n8n-api`):

```bash
bash glpi/preparar-glpi.sh
```

> Atenção: o `infra/glpi/criar-estrutura.sh` do ng-soc-lab redefine as permissões do perfil `NG-SOC API (N8N)`.
> Se rodá-lo de novo, rode este também (ou inclua `document` e `dropdown` com leitura no `estrutura.php` de lá).

**2. Bot e grupo no Telegram** (um bot **separado** do bot de alertas do NG-SOC: dois leitores no mesmo bot brigam pelas mensagens):

1. No [@BotFather](https://t.me/BotFather): `/newbot` (ex.: `ngsoc_phishing_bot`). Guarde o token **sem colar em chat**.
2. Crie o grupo **Relatos de Phishing**, adicione o bot e os analistas.
3. Para descobrir o número do grupo e o seu ID: mande `/ajuda` no grupo e abra
   `https://api.telegram.org/bot<TOKEN>/getUpdates` no navegador (`chat.id` do grupo e `from.id` de cada analista).
   Faça isso **antes** de importar o fluxo (depois, a rotina de decisões passa a ler as mensagens).

**3. Variáveis no n8n.** Abra o `infra/n8n/.env` do ng-soc-lab no Bloco de Notas e acrescente:

```
PHISHING_TELEGRAM_TOKEN=cole-o-token-do-bot
PHISHING_TELEGRAM_CHAT_ID=-100xxxxxxxxxx
PHISHING_ANALISTAS=111111111,222222222
```

No `infra/n8n/compose.yaml`, na lista `environment:` do n8n, acrescente:

```yaml
      - PHISHING_TELEGRAM_TOKEN=${PHISHING_TELEGRAM_TOKEN:-}
      - PHISHING_TELEGRAM_CHAT_ID=${PHISHING_TELEGRAM_CHAT_ID:-}
      - PHISHING_ANALISTAS=${PHISHING_ANALISTAS:-}
```

e recrie o container: `docker compose up -d n8n` (na pasta `infra/n8n`; só reiniciar não lê o `.env` de novo).

> Por que o token fica numa variável e não numa credencial: a API do Telegram só aceita o token **dentro do endereço**,
> e a credencial do n8n não consegue colocá-lo lá para o `getUpdates`. Qualquer fluxo do n8n consegue ler variáveis,
> então use um bot exclusivo, que só está nesse grupo: o pior caso é alguém com acesso ao n8n mandar mensagens nesse grupo.

**4. Importar e publicar o fluxo** (reinicia o n8n):

```bash
bash scripts/importar-fluxo.sh
```

Se os dois fluxos antigos (`Phishing - analisa relatos do GLPI` e `Phishing - decisões do analista (Telegram)`) estiverem no n8n,
o script os **despublica** antes (dois leitores do Telegram entrariam em conflito). Depois de conferir o novo, apague-os pela tela.

**5. Testar com um chamado fictício:**

```bash
bash glpi/preparar-glpi.sh teste tests/amostras/phishing-banco.eml "Recebi do banco, cliquei no link e digitei minha senha. Não abri o anexo."
```

Em até 2 minutos a ficha chega no grupo; clique num botão e confira no GLPI a nota interna, a solução e a resposta ao usuário.
Outros exemplos: `tests/amostras/legitimo-loja.eml` (contato legítimo) e `tests/amostras/encaminhado-como-anexo.eml` (fraude do "chefe").

## Configuração

No nó **Configuração** (um só, para as duas rotinas; o JSON é gerado por `scripts/gerar-fluxo.py`; mude lá e gere de novo):

| Campo | Padrão | Para quê |
|---|---|---|
| `categoria` | `Segurança > Phishing e e-mail suspeito` | só chamados desta categoria |
| `grupo` | `Segurança da Informação` | ... e atribuídos a este grupo |
| `cotaDiaria` | 20 | máximo de análises por dia (cota gratuita do Gemini); o excedente fica para o dia seguinte |
| `maxVirusTotal` | 4 | consultas por chamado (plano grátis: 4/min, 500/dia, compartilhado com o scanner) |
| `tipoPhishing` / `tipoLegitimo` / `tipoSpam` / `grupoN2` | nomes do GLPI | usados na decisão |

Chaves no Redis (prefixo `phishing:`): `relato:<id>` (já analisado, 90 dias), `analise:<id>` (ficha usada na decisão, 90 dias),
`decisao:<id>` (trava), `cota:<data>`, `telegram:offset`, `metricas:ia_<sugestão>:analista_<decisão>` (precisão da IA).

## Desenvolvimento

```bash
node tests/testar-codigo.js      # 55 testes do código dos nós, sem n8n
python scripts/gerar-fluxo.py    # gera workflow/analisador-phishing-glpi-ia.json a partir de src/ (nunca edite o JSON à mão)
```

Execuções que deram certo não são guardadas no n8n (a rotina de decisões roda a cada minuto); as com erro, sim.
O resultado de cada análise fica no GLPI, no Telegram e no Redis.

O CI roda os testes, confere se o JSON está atualizado e passa o gitleaks.

## Limites conhecidos

- `.msg` do Outlook é binário: são lidos os links, e-mails e cabeçalhos visíveis no arquivo; para análise completa peça o `.eml`.
- Sem o e-mail anexado (só o relato), a confiança fica limitada a 50% e a ficha sugere pedir o arquivo ao usuário.
- Chamado aberto em outra categoria não entra: o analista corrige a categoria no GLPI e ele entra na rodada seguinte.
- Lista de marcas e domínios oficiais é curta (bancos, Microsoft, Google, Correios, gov.br...); amplie em `src/lib/indicadores.js`.

## Roteiro

- [ ] Ação "bloquear IOCs": ao confirmar phishing, enviar os domínios para a lista CDB do Wazuh (com aprovação).
- [ ] Busca de outras vítimas: quantos chamados/usuários relataram o mesmo remetente ou link (campanha).
- [ ] `/painel` no Telegram: relatos do dia, tempo até a decisão e precisão da IA (métricas do Redis).
- [ ] Ler o caixa de e-mail `phishing@` (botão "Reportar" do Outlook) e abrir o chamado sozinho.

## Licença

MIT
