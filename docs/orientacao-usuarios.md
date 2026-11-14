# Orientação aos usuários: como relatar um e-mail suspeito

Material de apoio para a **apresentação do projeto** às pessoas que vão relatar phishing. A mensagem principal é uma só:

> **Encaminhe o e-mail suspeito COMO ANEXO.** Assim a análise fica completa e a resposta sai mais rápida e mais certa.

## Por que "como anexo" faz diferença

Quando você encaminha do jeito comum (no corpo da mensagem), o seu programa de e-mail **reescreve** a mensagem:
guarda só o texto e alguns campos, e joga fora o que mais ajuda a desmascarar um golpe. Encaminhando **como anexo**,
o e-mail original segue inteiro, do jeito que chegou para você.

| O que a análise usa | Encaminhado como anexo | Encaminhado no corpo |
|---------------------|:----------------------:|:--------------------:|
| Remetente verdadeiro (`From`, `Return-Path`, `Reply-To`) | ✅ | ⚠️ só o nome exibido |
| Autenticação do remetente (SPF, DKIM, DMARC) | ✅ | ❌ |
| Caminho que o e-mail percorreu (servidores e IPs de envio) | ✅ | ❌ |
| Links reais (não só o texto que aparece) | ✅ | ⚠️ podem ser alterados ou "protegidos" |
| Anexos originais e seus hashes | ✅ | ⚠️ alguns somem ou são bloqueados |
| QR Code em imagem dentro do e-mail | ✅ | ⚠️ nem sempre |

Sem esses dados o analisador ainda trabalha, mas marca o chamado como **análise parcial** e a confiança fica limitada.

## Passo a passo

**Outlook na web (outlook.com / Outlook novo)** — testado em 14/11/2026:
1. Clique em **Novo email**.
2. **Arraste** o e-mail suspeito da lista para dentro da mensagem nova: ele vira anexo.
3. Escreva uma linha (ex.: "Parece golpe, não cliquei") e envie para a caixa de relatos.

(Alternativa: no e-mail aberto, menu **⋯** → **Baixar** → salvar o `.eml` e anexá-lo pelo clipe 📎.)
Para ver o cabeçalho completo: menu **⋯** → **Exibir** → **Exibir origem da mensagem**.

**Outlook clássico (Windows):** selecione o e-mail na lista → **Ctrl + Alt + F**
(ou guia Página Inicial → **Mais** ao lado de Encaminhar → **Encaminhar como Anexo**).

**Gmail no computador:** na lista de mensagens, marque a caixinha do e-mail suspeito → menu **⋮** →
**Encaminhar como anexo**.

**Celular:** os aplicativos do Outlook e do Gmail normalmente **não** têm essa opção. Se puder, relate pelo computador.
Se não der, encaminhe do jeito comum mesmo: **o relato é aceito** e vira chamado; só a análise fica parcial.

## Regras de ouro (junto com o relato)

- **Não clique** nos links e **não abra** os anexos do e-mail suspeito.
- **Não responda** ao remetente.
- **Clicou ou digitou a senha?** Relate do mesmo jeito, diga isso no texto e **troque a senha imediatamente**.
  Quem relata rápido ajuda; ninguém é punido por ter caído.
- Depois de relatar, pode apagar o e-mail suspeito da sua caixa.

## O que acontece depois

1. Você recebe um e-mail de confirmação com o número do chamado.
2. O time de Segurança da Informação analisa (com apoio automático) e decide.
3. Você recebe outro e-mail com a conclusão: phishing, legítimo ou spam, e o que fazer.

## Como o projeto dá o exemplo

O próprio analisador reforça essa prática, para que ela vire hábito:

- O e-mail de confirmação diz se o relato chegou **completo** (como anexo) ou **parcial** (no corpo). Quando chega
  parcial, agradece e ensina, em poucas linhas, como encaminhar como anexo da próxima vez (texto fixo).
- A ficha do analista no Telegram mostra a **forma do relato** (anexo ou corpo).
- O Redis conta quantos relatos chegam como anexo, para acompanhar a adoção (vai para o futuro `/painel`).
- Nos testes e nas demonstrações do time, os relatos são sempre enviados **como anexo**.
