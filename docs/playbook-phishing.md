# Playbook SOC: relato de phishing pelo usuário

Roteiro para o analista que recebe a ficha no grupo **Relatos de Phishing**. A IA adianta a triagem; a decisão é sempre sua.
MITRE ATT&CK: **T1566 Phishing** (.001 anexo, .002 link, .003 por serviço/mensageiro, .004 voz), T1598 (coleta de informações), T1534 (phishing interno).

## 1. Triagem (primeiros 5 minutos)

1. **O usuário interagiu?** Se a ficha mostra ⚠️ *clicou / digitou senha / abriu anexo / pagou*, pule para a seção 3 **antes** de terminar a análise.
2. **Quem mandou de verdade?** Compare o nome de exibição com o endereço real, o Reply-To e o Return-Path.
3. **Autenticação:** DMARC=fail num domínio de marca é quase sempre falsificação. SPF/DKIM/DMARC=pass só prova que o e-mail saiu
   daquele domínio: confira se o domínio é o oficial ou um parecido registrado há poucos dias.
4. **Links:** o texto mostrado bate com o destino? Encurtador, serviço gratuito de formulário/página, IP direto?
5. **Anexos:** `.html`, `.iso`, `.img`, `.lnk`, `.js`, `.one`, Office com macro, compactado ou extensão dupla = alto risco.
6. **Reputação:** 3+ motores no VirusTotal ou URLhaus listado = forte. 1 motor isolado costuma ser falso positivo.
   "Nunca analisado" **não** prova que é seguro (phishing novo quase nunca está em base nenhuma).
7. **Contexto:** o usuário esperava esse contato? É fornecedor, cliente, sistema interno? Na dúvida, pergunte (`/nota` registra a resposta).

**Nunca** abra o link ou o anexo na sua máquina. Se precisar ver a página, use uma sandbox (ex.: urlscan.io em modo privado ou o
modo "Completa" do Scanner de Segurança Web em ambiente isolado).

## 2. Decisão

| Situação | Botão |
|---|---|
| Tenta roubar senha/dados/dinheiro, imita marca/pessoa, entrega malware | 🎣 **É phishing** |
| Remetente e domínio oficiais, autenticação ok, contexto esperado | ✅ **É legítimo** |
| Propaganda não solicitada, sem golpe | 📨 **Spam** |
| Usuário digitou senha de conta privilegiada, anexo executado, campanha em vários usuários, BEC com pagamento, VIP | ⬆️ **Escalar N2** |

Se a IA errou, decida mesmo assim: a nota interna registra que você **discordou**, e a métrica
`phishing:metricas:ia_<sugestão>:analista_<decisão>` mostra onde a IA precisa melhorar.

## 3. Resposta conforme o que o usuário fez

| O usuário... | Faça (nesta ordem) | Gravidade |
|---|---|---|
| digitou a senha | trocar a senha; encerrar sessões/revogar tokens; conferir MFA (dispositivos novos?); procurar regras de encaminhamento na caixa; ver logins suspeitos depois do horário do clique | Crítica |
| abriu/executou o anexo | isolar a máquina; varredura com antivírus/EDR; coletar o hash do arquivo; procurar o mesmo hash em outras máquinas | Crítica |
| fez pagamento/PIX | acionar financeiro e banco na hora (PIX: pedir o MED); preservar comprovantes; boletim de ocorrência | Crítica |
| só clicou | confirmar se digitou algo; procurar o acesso ao domínio nos logs de proxy/DNS; bloquear o domínio | Alta |
| respondeu | ver o que enviou; se mandou dados, tratar como vazamento | Média/Alta |
| não interagiu | contenção abaixo | Média (phishing) / Baixa |

## 4. Contenção (phishing confirmado)

O checklist entra automaticamente na nota interna do chamado. Registre cada passo com `/nota <chamado> texto`.

1. Bloquear o remetente e o domínio no filtro/gateway de e-mail.
2. Procurar e apagar cópias da mesma mensagem nas outras caixas (ex.: Microsoft Purview, busca de conteúdo + limpeza).
3. Bloquear links e domínios no proxy, DNS ou firewall.
4. Ver nos logs de proxy/DNS quem mais acessou os domínios (outras vítimas = abrir chamados ligados).
5. Incluir os IOCs na lista de bloqueio (ex.: lista CDB do Wazuh) e, se for o caso, reportar a URL (ex.: Google Safe Browsing, abuse do provedor).
6. Se for campanha (vários relatos iguais), avisar os usuários com um alerta curto e um exemplo do e-mail.

## 5. Encerramento

- A decisão pelo botão já responde ao usuário (texto fixo) e soluciona o chamado com o tipo certo.
- Agradeça sempre: usuário que reporta é sensor do SOC. Relato "legítimo" também é bom relato.
- Casos em que a IA errou viram exemplos para ajustar os sinais (`src/lib/indicadores.js`) ou o prompt (`scripts/gerar-fluxo.py`).

## Métricas sugeridas

- Tempo entre a abertura do chamado e a decisão (meta: menos de 1 h; crítica: 15 min).
- Relatos por dia e por categoria de ataque; campanhas detectadas.
- Precisão da IA: `metricas:ia_X:analista_X` (concordou) ÷ total.
- Usuários que interagiram (clicou/senha/anexo) ÷ relatos: indica onde reforçar o treinamento.
