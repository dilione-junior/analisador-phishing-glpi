# Catálogo de técnicas de phishing

Detectores que leem o e-mail suspeito **sem abrir nada**: anexos HTML/SVG lidos como texto, `.zip` lido pelo índice
(sem descompactar), links e parâmetros de URL, texto do e-mail e relato do usuário. O código fica em
[`src/lib/tecnicas.js`](../src/lib/tecnicas.js). Cada achado:

- vira um **sinal** com peso na nota automática (0 a 100);
- aparece na ficha do Telegram ("🧪 Técnicas detectadas") e no acompanhamento do GLPI;
- vai para a IA no dossiê (`tecnicas_detectadas`), e o nome da técnica entra em "tipo de ataque" e no MITRE quando a IA falha;
- quando a técnica tem **ação obrigatória**, ela entra no topo das ações do SOC.

**Forte** (🔴) = artefato que não aparece em e-mail legítimo. Conta como evidência forte: a IA não consegue rebaixar
para "legítimo" ou "spam" (o analista continua decidindo). **Abuso de serviço** = o golpe usa um serviço ou uma conta
legítimos; nesse caso, "SPF/DKIM/DMARC passaram" deixa de contar a favor.

## Anexos

| Técnica (`id`) | O que procura | Peso | Forte | Ação obrigatória / observação |
|---|---|---|---|---|
| HTML smuggling (`html-smuggling`) | anexo `.html`/`.svg` com base64 + `Blob`/`createObjectURL` + download automático. Decodifica a carga, lista o que há dentro (se for `.zip`) e calcula o **hash** dela (vai para o bloqueio) | 40 | 🔴 | procurar o arquivo baixado no computador do usuário e bloquear o hash |
| SVG com script (`svg-script`) | `.svg` com `<script>`, `onload=`, `javascript:`, `<foreignObject>`/`<iframe>`. Decodifica `atob()` para achar o **destino escondido** (vira IOC) | 40 | 🔴 | — |
| Tela de login no anexo (`html-login-local`) | anexo HTML com campo de senha; o destino do formulário (`action`) vira IOC | 35 | | não é forte: alguns serviços de e-mail criptografado mandam HTML com senha |
| Anexo que redireciona (`html-redireciona`) | anexo HTML com `location=`, `location.replace()` ou `meta refresh` para um site de fora | 30 | | — |
| Zip com conteúdo perigoso (`zip-conteudo-perigoso`) | dentro do `.zip`: `.lnk`, `.js`, `.exe`, `.hta`, `.iso`... ou extensão dupla (`.pdf.lnk`) | 40 | 🔴 | confirmar se o usuário abriu; se abriu, isolar a máquina |
| | dentro do `.zip` só há `.html`/`.svg` | 25 | | — |
| Zip com senha (`zip-com-senha`) | `.zip` criptografado: o antivírus não vê o conteúdo | 15 | | — |
| PDF com senha (`pdf-com-senha`) | o leitor de QR não consegue abrir o PDF porque ele pede senha | 15 | | — |

## QR Code (quishing)

Imagens e PDFs do e-mail vão para o **leitor-qr**, um serviço do laboratório (ng-soc-lab, `infra/leitor-qr`) que lê QR
Codes com o zxing-cpp e desenha as páginas do PDF com o PDFium. Ele fica numa rede interna só com o n8n, sem internet. O
QR "desenhado" sem imagem (tabela HTML com células pretas, ou caracteres █ ▀ ▄) é convertido em imagem no próprio nó
e vai para o mesmo leitor. O link lido entra como qualquer link: reputação, RDAP e bloqueio. Se o leitor estiver fora do
ar, a análise segue sem o QR e o parecer avisa.

| Técnica (`id`) | O que procura | Peso | Forte | Ação obrigatória / observação |
|---|---|---|---|---|
| QR Code com link (`qrcode-decodificado`) | QR (em imagem, PDF ou desenhado) que leva para site fora da organização e das marcas oficiais | 20 | | perguntar se o usuário leu com o **celular**: o acesso sai do celular, fora do proxy e do antivírus |
| QR desenhado (`qrcode-desenhado`) | QR montado com tabela HTML ou caracteres, sem imagem, e que o leitor conseguiu ler | 30 | | é truque para fugir de filtro de imagem |
| QR com PIX | o QR traz um código PIX ("copia e cola"), não um link: recebedor, chave, valor e identificador aparecem na ficha | 0 | | **não soma**: boleto verdadeiro tem QR PIX. Confira se o recebedor é quem deveria receber (golpe do boleto) |

## Links

| Técnica (`id`) | O que procura | Peso | Forte | Ação obrigatória / observação |
|---|---|---|---|---|
| Consentimento OAuth (`oauth-consentimento`) | link **verdadeiro** `login.microsoftonline.com`/`accounts.google.com` `.../authorize` pedindo escopos de conteúdo (`Mail.*`, `Files.*`, `Sites.*`, Gmail, Drive...) e devolvendo o acesso para um site de fora (`redirect_uri`, que vira IOC) ou com `prompt=consent` | 35 | | **revogar o app no Entra ID**; trocar a senha não remove o acesso. Login só com `openid profile User.Read` não conta |
| Código de dispositivo (`device-code`) | link para `microsoft.com/devicelogin` (ou equivalente) + um código no texto | 35 | | revogar sessões e tokens; rever os logins por "device code" |
| Isca personalizada (`aitm-isca`) | o link (fora de domínio oficial) leva o e-mail da vítima escondido em base64 ou no `#fragmento`; ou o anexo carrega esse e-mail | 20 | | e-mail aberto na query (`?email=`, comum em descadastro) **não** conta |
| Compartilhamento falso (`compartilhamento-falso`) | "compartilhou um arquivo", "enviou um documento para você assinar"... e nenhum link vai para SharePoint, OneDrive, Google Drive, Dropbox, Box, DocuSign ou WeTransfer | 20 | | — |

## Remetente e domínios

| Técnica (`id`) | O que procura | Peso | Forte | Ação obrigatória / observação |
|---|---|---|---|---|
| Imita a organização (`imita-organizacao`) | domínio (remetente, Reply-To ou link) que contém o nome da organização ou difere dele por 1 ou 2 letras (`rh-cybersecurity.example`, `cybersecurlty...`) | 25 | | usa `dominiosConfiaveis`; só vale para nomes com 5 letras ou mais (nome curto daria falso positivo) |
| Sósia de quem está na conversa (`dominio-sosia-conversa`) | domínio do remetente quase igual a um que aparece na própria conversa citada (`graficapaullsta` × `graficapaulista`) | 35 | | não alterar dados bancários sem confirmar por telefone conhecido |

## Golpes sem link malicioso

| Técnica (`id`) | O que procura | Peso | Forte | Ação obrigatória / observação |
|---|---|---|---|---|
| Golpe por telefone (`callback-telefone`) | renovação/assinatura/antivírus + "ligue"/"telefone" + número. O telefone vira IOC | 40 | | perguntar se o usuário ligou e se instalou acesso remoto. Remetente **autenticado** de marca que não publica texto de terceiros (banco, Correios...) não conta: o telefone é a central dele. PayPal, DocuSign, Microsoft, Google, Amazon, Mercado Livre, LinkedIn e Meta contam, porque o golpista escreve o número dentro de uma fatura ou um convite verdadeiros |
| Conta salário (`bec-conta-salario`) | pedido de troca da conta salário (ou "troquei de banco") vindo de **fora** da organização | 30 | | não alterar sem confirmar com o funcionário |
| Desculpa de canal (`bec-pretexto`) | "do meu e-mail pessoal", "sem acesso à VPN", "em reunião, não posso atender", "celular novo" vindo de fora | 15 | | — |
| Executivo em webmail (`bec-executivo-webmail`) | assina como diretor/CEO/sócio usando Gmail, Outlook.com etc. | 20 | | — |
| Nome interno com endereço de fora (`bec-nome-interno`) | o nome do remetente é de uma pessoa-chave (configuração `nomesInternos`) e o endereço não é da organização | 30 | | confirmar com a pessoa por canal interno. **Só funciona com `nomesInternos` preenchido** |

## Relato do usuário

| Técnica (`id`) | O que procura | Peso | Forte | Ação obrigatória / observação |
|---|---|---|---|---|
| Página falsa no relato (`relato-pagina-falsa`) | o usuário conta que apareceu tela pedindo senha + "outro endereço", "deu erro", "não sou robô", "documento não abriu" | 25 | | é a única prova quando o e-mail é de uma conta verdadeira invadida (SharePoint de cliente, AiTM) |

## Calibração da nota

- **Webmail gratuito** com SPF/DKIM/DMARC passando: o −15 de "autenticado" vira 0, porque qualquer um cria conta no Gmail.
- **Abuso de serviço** (OAuth, código de dispositivo, callback, relato de página falsa) ou **domínio do remetente com
  menos de 30 dias**: o −15 de "autenticado" também vira 0.
- **Imitação + domínio novo** (`imitacao-dominio-novo`, +15): marca, organização ou contato imitados **e** domínio criado
  há menos de 30 dias. É o perfil típico de phishing, que antes ficava em 53 a 55 (inconclusivo).

## Fora do catálogo (por enquanto)

- **Print anexado direto no chamado** (sem o .eml): hoje o fluxo não baixa imagens do GLPI, então um QR que aparece
  só num print não é lido. O QR dentro do e-mail (.eml) é lido.
- **`.rar`, `.7z`, `.iso`**: o conteúdo não é listado (o `.iso` já conta como anexo perigoso).
- **Lista de funcionários**: `bec-nome-interno` usa só as pessoas-chave da configuração. Com a lista do AD ou do GLPI, o
  caso 10 (troca de conta salário) passaria de inconclusivo para phishing.

## Como acrescentar uma técnica

1. Entrada em `TECNICAS` (nome, MITRE, peso, forte, abusaServico, orientacao) e regra em `detectarTecnicas()`.
2. Um caso de phishing **e** um caso legítimo parecido no [conjunto de referência](../tests/corpus/README.md) (o legítimo
   prova que a regra não dá falso positivo).
3. `node tests/testar-codigo.js` e `node tests/avaliar-corpus.js`: o placar tem que melhorar sem falso positivo novo.
