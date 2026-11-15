/* global Office, Relato */
// Painel do botão "Reportar phishing": abre uma mensagem nova para a caixa de Segurança
// com o e-mail aberto anexado (como item). O usuário confere e clica em Enviar.
(function () {
  'use strict';
  const el = (id) => document.getElementById(id);
  const destino = () => (window.RELATO_CONFIG || {}).destino || '';

  function mostrar(secao) {
    for (const s of ['carregando', 'formulario', 'pronto', 'erro']) el(s).hidden = s !== secao;
  }
  function falhar(texto) {
    el('erro-texto').textContent = texto;
    el('erro-destino').textContent = destino() || 'o time de Segurança';
    mostrar('erro');
  }

  function montarOpcoes() {
    const caixa = el('interacoes');
    for (const i of Relato.INTERACOES) {
      const rotulo = document.createElement('label');
      rotulo.className = 'opcao';
      const marca = document.createElement('input');
      marca.type = 'checkbox';
      marca.value = i.id;
      marca.addEventListener('change', () => { if (marca.checked) el('nada').checked = false; });
      rotulo.append(marca, ' ' + i.rotulo);
      caixa.append(rotulo);
    }
    el('nada').addEventListener('change', () => {
      if (el('nada').checked) for (const m of caixa.querySelectorAll('input')) m.checked = false;
    });
  }

  function preparar() {
    const item = Office.context.mailbox.item;
    const relato = Relato.montarRelato({
      assunto: item.subject,
      remetente: item.from && item.from.emailAddress,
      nome: item.from && item.from.displayName,
      interacoes: [...el('interacoes').querySelectorAll('input:checked')].map((m) => m.value),
      nada: el('nada').checked,
      comentario: el('comentario').value,
    });
    const parametros = {
      toRecipients: [destino()],
      subject: relato.assunto,
      htmlBody: relato.corpoHtml,
      attachments: [{ type: 'item', itemId: item.itemId, name: relato.nomeAnexo }],
    };
    el('preparar').disabled = true;
    const mailbox = Office.context.mailbox;
    if (Office.context.requirements.isSetSupported('Mailbox', '1.9') && mailbox.displayNewMessageFormAsync) {
      mailbox.displayNewMessageFormAsync(parametros, (r) => {
        if (r.status === Office.AsyncResultStatus.Failed) falhar('Não consegui abrir a mensagem de relato: ' + (r.error && r.error.message));
        else mostrar('pronto');
      });
    } else {
      try {
        mailbox.displayNewMessageForm(parametros);
        mostrar('pronto');
      } catch (e) {
        falhar('Não consegui abrir a mensagem de relato: ' + e.message);
      }
    }
  }

  Office.onReady((info) => {
    if (info.host !== Office.HostType.Outlook) return falhar('Abra este painel pelo botão "Reportar phishing" dentro do Outlook.');
    if (!destino()) return falhar('Endereço do time de Segurança não configurado.');
    if (!Office.context.requirements.isSetSupported('Mailbox', '1.6')) {
      return falhar('Esta versão do Outlook não permite anexar o e-mail automaticamente.');
    }
    const item = Office.context.mailbox.item;
    if (!item || item.itemType !== Office.MailboxEnums.ItemType.Message || !item.itemId) {
      return falhar('Abra o e-mail suspeito (não um rascunho nem um convite) e clique de novo no botão.');
    }
    el('assunto').textContent = item.subject || '(sem assunto)';
    el('remetente').textContent = item.from ? `${item.from.displayName || ''} <${item.from.emailAddress || ''}>` : '';
    montarOpcoes();
    el('preparar').addEventListener('click', preparar);
    mostrar('formulario');
  });
})();
