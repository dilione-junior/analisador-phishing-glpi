// Monta a mensagem de relato que o botão "Reportar phishing" deixa pronta para o usuário enviar.
// Sem acesso ao Outlook: só texto. Usado pelo painel (navegador) e pelos testes (Node).
(function (raiz) {
  'use strict';

  const VERSAO = '1.0.0';
  const MARCADOR = '[Relato phishing]';

  // As frases precisam ser reconhecidas por interacaoDoUsuario() (src/lib/indicadores.js),
  // que liga o aviso "troque a senha IMEDIATAMENTE" na resposta. tests/testar-suplemento.js confere.
  const INTERACOES = [
    { id: 'clicou', rotulo: 'Cliquei no link', frase: 'Cliquei no link do e-mail.' },
    { id: 'senha', rotulo: 'Digitei senha ou dados', frase: 'Digitei minha senha ou dados em uma página aberta pelo e-mail.' },
    { id: 'anexo', rotulo: 'Abri o anexo', frase: 'Abri o anexo do e-mail.' },
    { id: 'respondeu', rotulo: 'Respondi ao remetente', frase: 'Respondi ao remetente.' },
    { id: 'pagou', rotulo: 'Fiz PIX ou pagamento', frase: 'Fiz o PIX ou pagamento pedido no e-mail.' },
  ];
  const FRASE_NADA = 'Não cliquei, não abri anexo e não digitei nada.';
  const MAX_COMENTARIO = 1000;
  const MAX_ASSUNTO = 150;

  function escapar(texto) {
    return String(texto ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Uma linha só, sem caracteres de controle (assunto vem do atacante).
  function umaLinha(texto, maximo) {
    const t = String(texto ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
    return t.length > maximo ? t.slice(0, maximo - 1) + '…' : t;
  }

  // dados: { assunto, remetente, nome, interacoes: [ids], nada: bool, comentario }
  function montarRelato(dados) {
    const assuntoOriginal = umaLinha(dados.assunto, MAX_ASSUNTO) || '(sem assunto)';
    const remetente = umaLinha(dados.nome ? `${dados.nome} <${dados.remetente ?? ''}>` : dados.remetente, 200);
    const escolhidas = INTERACOES.filter((i) => (dados.interacoes || []).includes(i.id));
    const comentario = String(dados.comentario ?? '').trim().slice(0, MAX_COMENTARIO);

    let oQueFiz;
    if (escolhidas.length) oQueFiz = escolhidas.map((i) => i.frase);
    else if (dados.nada) oQueFiz = [FRASE_NADA];
    else oQueFiz = ['Não informado.'];

    const assunto = `${MARCADOR} ${assuntoOriginal}`;
    const corpoHtml = [
      '<p>Relato de e-mail suspeito enviado pelo botão <b>Reportar phishing</b>. O e-mail original está anexado.</p>',
      `<p><b>Assunto do e-mail relatado:</b> ${escapar(assuntoOriginal)}<br>`,
      `<b>Remetente do e-mail relatado:</b> ${escapar(remetente || '(desconhecido)')}</p>`,
      `<p><b>O que eu fiz:</b><br>${oQueFiz.map(escapar).join('<br>')}</p>`,
      comentario ? `<p><b>Comentário:</b><br>${escapar(comentario).replace(/\r?\n/g, '<br>')}</p>` : '',
      `<p style="color:#666;font-size:small">Reportar phishing v${VERSAO}</p>`,
    ].join('\n');
    // Nome do anexo: só caracteres seguros (vira nome de arquivo no GLPI).
    const nomeAnexo = umaLinha(assuntoOriginal, 80).replace(/[\\/:*?"<>|]/g, '_');
    return { assunto, corpoHtml, nomeAnexo };
  }

  const api = { VERSAO, MARCADOR, INTERACOES, FRASE_NADA, escapar, montarRelato };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else raiz.Relato = api;
})(typeof window !== 'undefined' ? window : globalThis);
