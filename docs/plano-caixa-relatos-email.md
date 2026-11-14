# Plano: caixa de e-mail para relatos de phishing

Objetivo: o usuário relata um e-mail suspeito **encaminhando-o para uma caixa do time de SI**, sem precisar abrir
chamado no GLPI. O chamado nasce sozinho e segue o caminho que já existe (análise → Telegram → decisão).

## Decisões (12/11/2026, com o usuário)

| # | Assunto | Decisão |
|---|---------|---------|
| 1 | Quem lê a caixa | **n8n** (Graph API, credencial OAuth do Outlook), não o coletor nativo do GLPI |
| 2 | Escopo | **Só relatos de phishing** nesta 1ª fase (pedidos comuns ao SI ficam para depois) |
| 3 | Quem pode enviar | **Qualquer um** (sem lista de remetentes) → proteções contra abuso são obrigatórias |
| 4 | Requerente no GLPI | Usuário **genérico** com nome parecido com o da caixa (nome definido depois que a caixa existir); e-mail do remetente registrado no chamado |
| 5 | Resposta por e-mail | **Completa**: confirmação de recebimento + aviso da decisão final (texto fixo, nada da IA) |
| 6 | Credencial (14/11) | **Credencial NOVA** no n8n só para a caixa de relatos (login em janela anônima). A credencial atual é do e-mail pessoal do usuário e **não muda** |
| 7 | "Encaminhar como anexo" (14/11) | **Prática oficial do projeto**: orientar na apresentação ([orientacao-usuarios.md](orientacao-usuarios.md)) e o próprio fluxo dar o exemplo (ver abaixo) |

## Encaminhar como anexo: o projeto dá o exemplo

- Detectar a forma do relato (casos reais vistos nos testes de 14/11 com a caixa nova):

  | Forma | Como reconhecer no MIME do relato | Resultado |
  |-------|-----------------------------------|-----------|
  | E-mail anexado | parte `message/rfc822`, ou anexo `.eml`/`.msg` (Graph: `itemAttachment`) | **completo** |
  | Arquivo anexado, sem e-mail | `multipart/mixed` só com `application/pdf`, imagem, zip... | **parcial**: arquivo analisado (hash, links, QR), sem cabeçalho do original |
  | Encaminhado no corpo | `multipart/alternative`, sem anexo, com "De: … Enviado: …" / "Forwarded message" no texto | **parcial** |
  | Só o pedido | `X-MS-Has-Attach` vazio, `multipart/alternative`, texto curto sem bloco encaminhado | **sem o e-mail**: chamado aberto, resposta ensina a anexar |
- Confirmação ao remetente diz a forma; se parcial, agradece e ensina o passo a passo (texto fixo, curto).
- Ficha do Telegram mostra "Forma do relato: anexo / corpo".
- Contador no Redis (relatos por forma) para medir adoção; entra no futuro `/painel`.
- Testes, corpus e demonstrações usam sempre relato **como anexo** (mais um caso de corpo, para cobrir o parcial).

## Sugestões ainda a confirmar com o usuário (14/11)

| # | Assunto | Sugestão |
|---|---------|----------|
| A | Frequência | A cada 2 min |
| B | Pastas lidas | Caixa de Entrada + Lixo Eletrônico |
| C | E-mail sem anexo e quase sem texto | Abre chamado com "análise parcial" e pede reenvio como anexo |
| D | Limite por remetente | 5/hora e 20/dia; excesso vai para "Descartados" sem chamado nem resposta |
| E | Limite por leitura | 10 e-mails por rodada |
| F | E-mail de quem relatou | Acompanhamento **privado** no chamado |
| G | Respostas | Saem da própria caixa, texto fixo |
| H | Depois de processar | Marca lido e move para "Processados"/"Descartados"; nada é apagado |

Por que não o coletor do GLPI: Outlook.com exige OAuth no IMAP (precisaria do plugin oauthimap), o coletor
transforma o e-mail em texto (perde os cabeçalhos do original) e o GLPI do lab não envia e-mail.

## Desenho

```
Caixa SI (Outlook.com) ──Graph──> n8n, rotina nova DENTRO do fluxo único
   ├─ lê Caixa de Entrada + Lixo Eletrônico (não lidas)
   ├─ descarta: resposta automática, mailer-daemon, as próprias respostas, excesso por remetente
   ├─ baixa a mensagem inteira (MIME, /messages/{id}/$value) → .eml
   ├─ abre o chamado na API do GLPI: categoria 12, grupo 3, requerente genérico, .eml anexado
   ├─ responde ao remetente: "Recebemos seu relato, chamado #N" (texto fixo)
   └─ move a mensagem para a pasta "Processados" (ou "Descartados")
                 ↓
   analisador existente pega o chamado (sem mudança)
                 ↓
   decisão no Telegram → além do GLPI, e-mail ao remetente com o texto fixo da decisão
```

## Proteções (porque qualquer um pode enviar)

- Limite de chamados por remetente por hora e limite total por execução (contadores no Redis).
- Não responder a: `Auto-Submitted` diferente de `no`, `Precedence: bulk/list/junk`, mailer-daemon/postmaster,
  remetente igual à própria caixa, assunto de resposta automática ("Automatic reply", "Resposta automática"...).
- Resposta só com texto fixo; nunca repetir conteúdo do e-mail recebido (evita usar a caixa para refletir spam).
- Conteúdo do e-mail é sempre dado, nunca instrução (já vale no analisador).
- O e-mail do remetente fica no chamado (não é o requerente), para o aviso final saber para quem escrever.

## Limitações conhecidas

- Encaminhar no corpo perde os cabeçalhos do original: chamado segue com aviso "análise parcial". Orientar
  "Encaminhar como anexo".
- Outlook.com bloqueia alguns anexos perigosos: a análise usa o que sobrar.

## Para depois (2ª fase)

- Resposta do usuário com "[Chamado #N]" no assunto vira acompanhamento do chamado existente.
- Pedidos comuns ao SI em outra categoria, sem análise.
- Caixa compartilhada `phishing@` / botão "Reportar" do Outlook (exige Microsoft 365 de empresa).

## Do lado do usuário

1. [x] Criar a conta Outlook.com nova, com MFA e nome neutro.
2. [x] Registrar no Microsoft Entra um aplicativo **só para a caixa** ("contas em qualquer diretório organizacional e
   contas pessoais da Microsoft"; redirecionamento `http://localhost:5678/rest/oauth2-credential/callback`).
   O app é registrado com a conta dona do Azure; a conta da caixa só dá consentimento no login.
3. [x] Credencial nova no n8n ("Outlook - caixa de relatos (seguranca)"); ID e segredo no `.env` local (fora do git).
4. [ ] "Connect my account" com a conta da caixa, em janela anônima (senão entra a conta pessoal do navegador).
5. [ ] Escolher o nome do requerente genérico no GLPI.
6. [ ] Confirmar as sugestões A–H.
