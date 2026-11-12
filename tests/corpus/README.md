# Conjunto de referência (corpus) do analisador

São 38 e-mails `.eml` feitos para parecer exatamente com o que chega numa caixa do Microsoft 365, cada um com o
**gabarito de um analista N3**: classificação certa, tipo de ataque, alvo, gravidade, MITRE, o que deve e o que não
pode ir para o bloqueio. Serve para provar, com números, que uma mudança deixou o analisador **mais inteligente**
e não só **diferente**.

```bash
node tests/avaliar-corpus.js            # relatório (regras + travas, IA desligada, reputação simulada)
node tests/avaliar-corpus.js --caso 06  # detalhe de um caso: sinais, IOCs, fora do bloqueio, interação
node tests/avaliar-corpus.js --ci       # o mesmo, mas sai com erro se houver regressão (roda no CI)
node tests/avaliar-corpus.js --json antes.json   # guarda o resultado para comparar com a próxima versão
```

O leitor de QR Code é **simulado** pelo campo `qr` do gabarito (o que há em cada imagem/PDF). Para provar que o leitor
de verdade lê a mesma coisa, rode `tests/conferir-leitor-qr.js` dentro da rede do laboratório (comando no README principal).

## Como os e-mails foram feitos

Tudo sai de [`gerar-corpus.py`](gerar-corpus.py) (nunca edite os `.eml` à mão). Para gerar de novo:

```bash
pip install --target <pasta-temporária> segno==1.6.6     # só para o QR Code do caso 03
python -I tests/corpus/gerar-corpus.py --libs <pasta-temporária>
```

O resultado é determinístico (mesmos bytes a cada execução). O que torna os e-mails realistas:

- **Cabeçalhos do Exchange Online de verdade:** cadeia de `Received` do EOP, `Authentication-Results` com `compauth`,
  `Received-SPF`, `X-Forefront-Antispam-Report`, `X-MS-Exchange-*`, `DKIM-Signature`, Message-IDs no formato de cada
  plataforma (Outlook, Gmail, PHPMailer, SendGrid...).
- **O atacante de hoje se autentica:** em vários casos o golpista tem domínio próprio com SPF/DKIM/DMARC passando, ou
  usa infraestrutura legítima (conta invadida de parceiro, SharePoint, PayPal). Só os golpes mais baratos falham no DMARC.
- **MIME como o dos clientes de e-mail:** multipart/alternative com texto e HTML, quoted-printable, assunto em RFC 2047,
  imagem inline por `cid:`, e-mail encaminhado como anexo (`message/rfc822`), resposta com conversa citada.
- **Técnicas atuais:** AiTM, quishing, HTML e SVG smuggling, consent phishing OAuth, abuso de SharePoint e IPFS,
  homógrafo IDN, BEC (diretoria, fornecedor e RH), callback phishing e zip com `.lnk`.
- **Iscas brasileiras:** Receita/CPF, Correios/PIX, NF-e/DANFE, comprovante de PIX, conta salário.

### Regras de segurança (o repositório é público)

- Todo domínio do atacante termina em **`.example`** (RFC 2606: reservado, nunca vai existir).
- Todo IP do atacante é de **documentação** (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). O analisador
  descarta esses IPs como não públicos; **só o avaliador** os trata como públicos, para fazerem o papel de IP do atacante.
- Domínios e IPs reais aparecem só como **infraestrutura legítima** (Microsoft, Google, PayPal, DocuSign, Itaú), do
  jeito que aparecem nos e-mails de verdade. Pessoas, empresas, telefones (prefixo `0`, inválido) e contas bancárias
  (zeros) são inventados. A organização é a fictícia **Cybersecurity Ltda** (`cybersecurity.local`).
- **Nenhum anexo é malicioso:** o `.zip` "contrabandeado" pelo HTML tem só um `LEIA-ME.txt`; o `.lnk` é texto; os
  PDFs são mínimos, só com texto. Importa a **estrutura** (extensões, `atob`, `Blob`, `<script>` no SVG, QR Code), não
  um malware de verdade. O Windows Defender não acusou nada ao gerar.

## O gabarito ([`casos.json`](casos.json))

| Campo | O que é |
|---|---|
| `esperado` | classificação (`phishing`/`legitimo`/`spam`), `phishing_type`, `delivery_channel`, `target`, `gravidade`, `mitre`: a taxonomia da proposta de Phishing Intelligence |
| `relato`, `requerente` | o que o usuário escreveu no chamado e de que setor ele é |
| `sinais_obrigatorios` / `sinais_proibidos` | sinais que o analisador **já** tem que dar / que seriam falso positivo |
| `bloqueio.deve_ter` / `nao_pode_ter` | o que tem que ir para as listas do Wazuh / o que nunca pode ir (domínio oficial, da casa, compartilhado) |
| `reputacao` | VirusTotal, URLhaus e idade do domínio (RDAP) simulados. Na maioria dos casos o VirusTotal **não conhece** o link, como numa campanha nova |

Os feeds de IOC simulados ficam em [`feeds.json`](feeds.json) (texto do OpenPhish e resposta do ThreatFox, com ruído
realista). O avaliador passa esse conteúdo pelo mesmo nó que carrega o Redis ("Prepara os IOCs dos feeds") e todos os
casos consultam o resultado: é assim que um legítimo pode tropeçar num IOC do feed. `--sem-feeds` mede o placar sem eles.
| `lacuna` | o que o analisador **ainda não sabe** fazer nesse caso: o erro aparece no relatório, mas não quebra o CI |
| `sinais_futuros` | o sinal que vai provar que a lacuna foi resolvida. **É a lista de trabalho do catálogo de técnicas** |
| `ioc_escondido` | IOC que só aparece se o analisador abrir a camada escondida (QR Code, JavaScript do SVG) |

**Quebra o CI (regressão):** caso sem lacuna classificado errado; **qualquer** falso positivo; sinal obrigatório
ausente ou proibido presente; item proibido nas listas de bloqueio (sempre, com ou sem lacuna).

Como é o relatório: **ok** = acertou; **parcial** = inconclusivo (vai para o analista decidir, não é perigoso);
**ERRO** = phishing saindo como legítimo (falso negativo) ou o contrário (falso positivo). Para spam, as regras não
distinguem spam de legítimo (quem faz isso é a IA); só não pode virar phishing.

## Os casos

| # | Caso | Técnica | Esperado | Sinal do catálogo / lacuna |
|---|---|---|---|---|
| 01 | Microsoft 365 "senha expira hoje" | domínio sósia `rn`→`m`, link disfarçado, autenticação passando | phishing | — |
| 02 | Escritório parceiro invadido | **AiTM** (Tycoon/EvilProxy): pages.dev + e-mail da vítima em base64; usuário aprovou o MFA | phishing, crítica | `aitm-isca`, `relato-pagina-falsa` |
| 03 | "Reconfigure o MFA" | **quishing**: link só dentro do QR Code; imita a TI da casa | phishing | `qrcode-decodificado`, `aitm-isca`, `imita-organizacao` |
| 04 | NF-e com anexo .html | **HTML smuggling** (`atob` + `Blob` + download) | phishing | `html-smuggling` |
| 05 | "Mensagem de voz" .svg | **SVG smuggling** (`<script>` + `atob` + redirecionamento) | phishing | `svg-script` |
| 06 | "Assine o aditivo" | **consent phishing OAuth**: link verdadeiro da Microsoft, escopos de e-mail e `redirect_uri` externo | phishing, crítica | `oauth-consentimento` |
| 07 | SharePoint de cliente invadido | **abuso de SharePoint** em 2 etapas: e-mail 100% legítimo, evidência só no relato | phishing (sai inconclusivo) | `relato-pagina-falsa`; **lacuna**: só o relato denuncia |
| 08 | Diretora pede cartões-presente | **BEC** por Gmail com nome de diretora real | phishing | `bec-nome-interno` |
| 09 | Fornecedor troca a conta | **BEC de fornecedor**: sósia `i`→`l` entra numa conversa real com PDF | phishing | `dominio-sosia-conversa` |
| 10 | "Troque minha conta salário" | **desvio de salário** (BEC contra o RH) por Outlook.com | phishing (sai inconclusivo) | `bec-conta-salario`, `bec-pretexto`; **lacuna**: falta a lista de funcionários |
| 11 | Receita Federal / CPF | encurtador, prazo de 48 h, DARF | phishing | `imitacao-dominio-novo` |
| 12 | Correios / PIX (usuária pagou) | taxa falsa; URLhaus conhece o host | phishing, crítica | — |
| 13 | DocuSign falso | página no **IPFS** com o e-mail no `#` | phishing | `imitacao-dominio-novo`, `aitm-isca` |
| 14 | Alerta de login "Microsoft" | **homógrafo IDN** (`і` cirílico) | phishing | `imitacao-dominio-novo` |
| 15 | Comprovante de PIX .zip | **zip com `.pdf.lnk`** (trojan bancário) | phishing, crítica | `zip-conteudo-perigoso` |
| 16 | Fatura do PayPal | **callback phishing (TOAD)**: fatura real com 0800 falso | phishing | `callback-telefone` |
| 17 | "RH" com reajuste 2027 | **encaminhado como anexo**; imita o RH; usuário digitou a senha | phishing, crítica | `imita-organizacao` |
| 18 | Fatura em anexo .html | **tela de login dentro do anexo**: o formulário manda a senha para o atacante | phishing | `html-login-local` |
| 19 | Contrato "assine pelo celular" | **quishing em PDF**: o link só existe no QR desenhado dentro do PDF anexo | phishing | `qrcode-decodificado` |
| 20 | "Verificação de segurança" | **QR desenhado com tabela HTML** (sem imagem) | phishing | `qrcode-desenhado` |
| 21 | Proposta de fornecedor invadido | **campanha nova**: conta legítima autenticada; o host do link já está no OpenPhish com outro token | phishing | `feed-host` |
| 22 | DARF da "contabilidade" em .zip | **malware**: o .zip parece inofensivo; o hash está no ThreatFox | phishing | `feed-hash` |
| 23 | Certificado de evento | página em **bucket do Google Cloud**: host compartilhado, URL exata (sem o `#`) no OpenPhish | phishing | `feed-url` (e nunca `feed-host`) |
| L1 | Alerta verdadeiro da Microsoft | texto de phishing, origem oficial | legítimo | — |
| L2 | DocuSign verdadeiro | contrato esperado; Reply-To para o cliente | legítimo | — |
| L3 | SharePoint verdadeiro do contador | par do caso 07, arquivo esperado | legítimo | — |
| L4 | TI interna: senha expira | fala de senha e prazo, mas é interno e não pede senha | legítimo | — |
| L5 | NF-e do fornecedor verdadeiro | par do caso 09: boleto, PDF e XML | legítimo | — |
| L6 | Comunicado do Itaú | subdomínio oficial, descadastro | legítimo | — |
| L7 | .zip de notas do fornecedor | par do 15: zip, mas só PDF e XML | legítimo | — |
| L8 | Alerta de compra do Itaú | par do 16: "assinatura mensal" + telefone da central, de banco autenticado | legítimo | — |
| L9 | TI interna: login no sistema de ponto | par do 06: `oauth2/authorize` verdadeiro, só perfil básico, volta para a casa | legítimo | — |
| L10 | RH lembra a regra da conta salário | par do 10: fala de conta salário e e-mail pessoal, mas é interno | legítimo | — |
| L11 | Boleto da gráfica com PIX | par do 19: QR em PDF, mas é código PIX do próprio fornecedor | legítimo | — |
| L12 | Site de evento no Google Sites | par do 23: OUTRA página do Google Sites está no feed; o host não pode ser marcado | legítimo | nunca `feed-host`/`feed-url` |
| L13 | Newsletter da padaria | site invadido (página em `/wp-content/` no ThreatFox): vira "site invadido", não evidência forte | legítimo | `feed-site-invadido` |
| S1 | Newsletter "Black November" | marketing autenticado | spam | — |
| S2 | Prospecção de SEO | Gmail, sem link | spam | — |

Os casos L7 a L10 são "pares legítimos": cada um imita um golpe do catálogo e prova que o detector não dá falso positivo. O L8 pegou um falso positivo real do detector de golpe por telefone, corrigido antes de entrar.

## Para acrescentar um caso

1. Escreva o e-mail em `gerar-corpus.py` (copie um caso parecido) com o gabarito completo.
2. Rode o gerador e `node tests/avaliar-corpus.js --caso <id>`.
3. Se o analisador erra porque **não sabe** a técnica, registre a `lacuna` e o `sinal_futuro`. Se erra por **defeito**
   (ex.: bloquearia um domínio oficial), corrija o analisador; não afrouxe o gabarito.

Ao resolver uma lacuna, o relatório mostra "lacuna RESOLVIDA? revise o gabarito": tire `lacuna`/`sinais_futuros` do caso
e ponha o sinal novo em `sinais_obrigatorios`, para ele passar a ser cobrado.
