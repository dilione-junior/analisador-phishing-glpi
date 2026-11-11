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
| 2 | Catálogo de técnicas versionado (detectores no `.eml` + resumo no prompt): os `sinais_futuros` do conjunto | **feito** em 11/11 ([catálogo](catalogo-tecnicas.md)) |
| 3 | Taxonomia da proposta (tipo, canal, alvo, gravidade, confiança) na saída da IA | a fazer |
| 4 | Aprender com as decisões dos analistas (precedentes), junto com a ideia 1 (campanhas) | a fazer |
| 5 | Radar semanal: poucas fontes por RSS; a IA propõe técnica nova no Telegram; o analista aprova; vira PR | a fazer |
| 6 | Regras de detecção só em Sigma e Wazuh, como rascunho num PR | a fazer |

## Onde paramos (11/11/2026)

- **Placar de partida** (só regras, IA desligada): phishing **3 de 17** detectados, 8 inconclusivos, **6 falsos
  negativos**; legítimos e spam **8 de 8** certos, **0 falsos positivos**.
- O conjunto achou dois defeitos de bloqueio, já corrigidos e instalados: `sharepointonline.com` não era oficial da
  Microsoft, e encurtadores (`bit.ly`) entravam inteiros nas listas do Wazuh.
- **Depois da etapa 2** (catálogo de técnicas, 11/11): phishing **16 de 18** detectados, 2 inconclusivos, **0 falsos
  negativos**; legítimos e spam **12 de 12** certos, **0 falsos positivos**. Entraram 5 casos novos: o anexo HTML com
  tela de login e 4 legítimos difíceis (zip de notas, alerta de banco com telefone, login Microsoft da TI interna,
  comunicado do RH sobre conta salário). O alerta de banco pegou um falso positivo do detector de telefone, que foi
  corrigido antes de terminar. Sobram 3 lacunas: QR Code (03), SharePoint de cliente invadido (07, só o relato
  denuncia) e conta salário sem a lista de funcionários (10).
- Defeito antigo achado na etapa 2: subdomínio de hospedagem gratuita (`golpe.pages.dev`) não ia para o bloqueio;
  agora vai (o domínio do serviço, `pages.dev`, continua fora).

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

## Etapa 2 (catálogo de técnicas): feita

Os detectores, pesos, ações obrigatórias e cuidados com falso positivo estão em
[catalogo-tecnicas.md](catalogo-tecnicas.md). Ficaram para depois: listar `.rar`/`.7z`/`.iso` e a lista completa de funcionários (AD/GLPI) para `bec-nome-interno`.

**QR Code (11/11, depois da etapa 2):** serviço `leitor-qr` no ng-soc-lab (zxing-cpp + PDFium, rede interna sem internet)
+ QR desenhado em tabela HTML/caracteres convertido no nó. Placar: phishing **18 de 20**, legítimos **13 de 13**, 0 falsos
positivos; lacunas: só 07 e 10. Falta ler QR em print anexado direto no chamado (o fluxo não baixa imagens do GLPI).
