# Plano: Phishing Intelligence (versão reduzida)

Origem: proposta "Ecossistema de Aprendizado Contínuo para Phishing Intelligence" (11/11/2026). Depois da análise de
SOC N3, ficou combinada a **versão reduzida**, ligada ao analisador que já existe. A ideia é que nada mude sozinho:
toda técnica nova passa por um analista e por um PR, e precisa melhorar o placar do
[conjunto de referência](../tests/corpus/README.md) sem criar falso positivo.

Ficou de fora, por não caber no analisador ou no laboratório: deepfake, vishing puro e MFA fatigue (esses são do
NG-SOC, nos logs do Entra), consultas para ferramentas que o laboratório não tem (KQL, SPL, CrowdStrike, Sentinel,
Elastic) e mudança automática de prompts ou regras.

## Ordem combinada

| # | Etapa | Situação |
|---|---|---|
| 0 | Conjunto de referência: 25 `.eml` realistas com gabarito, avaliador no CI | **feito** em 11/11 (PR #4), instalado no n8n |
| 1 | Feeds de IOC (OpenPhish, ThreatFox, URLhaus em lote) no Redis, conferidos na análise como evidência forte | a fazer |
| 2 | Catálogo de técnicas versionado (detectores no `.eml` + resumo no prompt): os `sinais_futuros` do conjunto | a fazer |
| 3 | Taxonomia da proposta (tipo, canal, alvo, gravidade, confiança) na saída da IA | a fazer |
| 4 | Aprender com as decisões dos analistas (precedentes), junto com a ideia 1 (campanhas) | a fazer |
| 5 | Radar semanal: poucas fontes por RSS; a IA propõe técnica nova no Telegram; o analista aprova; vira PR | a fazer |
| 6 | Regras de detecção só em Sigma e Wazuh, como rascunho num PR | a fazer |

## Onde paramos (11/11/2026)

- **Placar de partida** (só regras, IA desligada): phishing **3 de 17** detectados, 8 inconclusivos, **6 falsos
  negativos**; legítimos e spam **8 de 8** certos, **0 falsos positivos**.
- O conjunto achou dois defeitos de bloqueio, já corrigidos e instalados: `sharepointonline.com` não era oficial da
  Microsoft, e encurtadores (`bit.ly`) entravam inteiros nas listas do Wazuh.

## Próximo passo: etapa 1 (feeds de IOC)

A decidir antes de começar:

- Quais feeds. Sugestão: OpenPhish community (gratuito), ThreatFox e URLhaus da abuse.ch (já temos a chave). PhishTank
  está com o cadastro fechado.
- Frequência da carga. Sugestão: a cada 6 horas, numa rotina nova dentro do mesmo fluxo único (sem criar outro fluxo).
- Validade das entradas no Redis. Sugestão: 7 dias para URL e host.
- Se o que estiver no feed também vai, sozinho, para as listas CDB do Wazuh. Sugestão: **não**; só depois do clique do
  analista, como hoje.

Como medir: acrescentar ao conjunto casos em que o link está no feed, mas o VirusTotal não conhece (o cenário de
campanha nova).

## Depois: etapa 2 (catálogo de técnicas)

Começar pelas lacunas que dá para detectar só olhando o `.eml`, sem abrir nada:

| Sinal futuro | Caso | O que detectar |
|---|---|---|
| `html-smuggling` | 04 | anexo `.html` com `atob(` + `Blob` + `download`/`msSaveOrOpenBlob` |
| `svg-script` | 05 | `.svg` com `<script>` ou `onload`; decodificar o `atob()` para achar a URL (IOC escondido) |
| `oauth-consentimento` | 06 | `oauth2/.../authorize` com `prompt=consent`, escopos `Mail.*`/`Files.*`/`offline_access` e `redirect_uri` externo; orientar a revogar o app no Entra ID |
| `zip-conteudo-perigoso` | 15 | listar os nomes dentro do `.zip` (`.lnk`, `.js`, `.pdf.lnk`) |
| `qrcode-decodificado` | 03 | ler o QR Code das imagens (precisa de um decodificador que rode no n8n) |
| `imita-organizacao` | 03, 17 | domínio parecido com o da casa (`dominiosConfiaveis`) |
| `callback-telefone` | 16 | "ligue para cancelar" + telefone + cobrança de assinatura; telefone vira IOC |
| `bec-conta-salario` | 10 | troca de conta salário ou de dados bancários vinda de webmail |
| `bec-nome-interno` | 08 | nome de pessoa da organização com e-mail de fora (precisa da lista de nomes: GLPI ou AD) |
| `dominio-sosia-conversa` | 09 | domínio do remetente quase igual a um que já aparece na conversa citada |
| `aitm-isca` | 02 | e-mail da vítima em base64 na URL + "documento compartilhado" fora do SharePoint/OneDrive |
| `relato-pagina-falsa` | 07 | o relato diz que a página pediu senha em outro endereço |
| calibração | 11, 13, 14 | marca imitada + domínio com menos de 30 dias deve bastar para phishing (hoje dá 53 a 55) |
