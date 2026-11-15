# Suplemento do Outlook: "Reportar phishing"

Botão no Outlook que prepara o relato de um e-mail suspeito: abre uma mensagem nova para a caixa de
Segurança (`config.js`) com o **e-mail original anexado** (com todos os cabeçalhos), assunto
`[Relato phishing] <assunto original>` e o que o usuário fez (clicou, digitou senha...). O usuário confere e
clica em **Enviar**. Daí em diante é a rotina da caixa de relatos ([plano](../docs/plano-caixa-relatos-email.md)).

Jeito "A" (simples): sem login, sem Azure, sem segredo. Só a permissão `ReadItem` (ler o e-mail aberto).

## Arquivos

| Arquivo | Papel |
|---|---|
| `manifest.xml` | O que se instala no Outlook: botão, ícones, endereço do painel |
| `relatar.html` / `.css` / `.js` | Painel que abre ao clicar no botão |
| `relato.js` | Monta assunto e corpo do relato (testado em `tests/testar-suplemento.js`) |
| `config.js` | Endereço da caixa de Segurança |
| `icones/` | Gerados por `python scripts/gerar-icones-suplemento.py` |

Publicado no GitHub Pages (`https://dilione-junior.github.io/analisador-phishing-glpi/`) pelo workflow
`pages-suplemento.yml` a cada mudança desta pasta na `main`.

## Instalar (uma pessoa, para teste)

1. Baixe o manifesto: abra `https://dilione-junior.github.io/analisador-phishing-glpi/manifest.xml` e salve
   como `manifest.xml` (Ctrl+S).
2. Entre no **Outlook na web** (outlook.live.com) com a conta de quem vai **relatar** (não a caixa de Segurança).
3. Em outra aba, abra **https://aka.ms/olksideload**: abre a janela "Suplementos do Outlook".
   (O menu ⋯ do e-mail **não** tem essa opção.)
4. **Meus suplementos** → **Suplementos personalizados** → **Adicionar um suplemento personalizado** →
   **Adicionar do arquivo** → escolha o `manifest.xml` → confirme o aviso. Deve aparecer "Adicionado".
5. Aperte F5, abra um e-mail e clique no ícone **Aplicativos** (quadradinhos ▦) **no cabeçalho do e-mail**, ao lado
   de responder/encaminhar → **Reportar phishing**. Não fica no menu ⋯ (lá está o "Relatar como phishing" da
   Microsoft, que manda para ela e não para nós). No novo Outlook do Windows pode levar até 24 h (cache).

Remover: o mesmo caminho do passo 4, em **Suplementos personalizados** → ⋯ → **Remover**.

Numa empresa com Microsoft 365, o administrador distribui o mesmo manifesto para todos
(Centro de administração → Aplicativos integrados) e ninguém instala nada à mão.

## Usar

Abrir o e-mail suspeito → **Reportar phishing** → marcar o que fez → **Preparar relato** → conferir o anexo →
**Enviar**.

## Testado

| Data | Cliente | Resultado |
|---|---|---|
| 15/11/2026 | Outlook na web (outlook.live.com, conta pessoal), tema escuro | ✅ painel ok; mensagem abriu com o e-mail **anexado**; chegou à caixa de Segurança |
| — | Novo Outlook do Windows / Outlook clássico | a testar |

## Limitações conhecidas

- Não aparece no Outlook do celular.
- Há relatos (de outros projetos) de mensagem abrindo **sem o anexo** em alguns clientes. No Outlook na web
  funcionou. O painel sempre pede para conferir; se faltar, arrastar o e-mail para a mensagem. Se acontecer em
  algum cliente usado de verdade, partir para o jeito "C" (envio pelo Graph).
- O marcador `[Relato phishing]` é só um rótulo: qualquer um pode escrevê-lo. Não dá confiança ao relato.
