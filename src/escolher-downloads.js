// Nó "Escolhe o que baixar": só o que for e-mail ou texto é baixado e lido (.eml, .msg, .txt, .html).
// Dos outros anexos (PDF, Office, executáveis, imagens) ficam o nome e o hash SHA-1 que o GLPI já
// calcula: o arquivo suspeito NUNCA é aberto pelo fluxo.
const docs = $input.all();
return docs.map((item, i) => {
  const d = item.json.body ?? {};
  const nome = String(d.filename ?? d.name ?? '');
  const mime = String(d.mime ?? '').toLowerCase();
  const ext = nome.toLowerCase().split('.').pop();
  const baixar = ['eml', 'msg', 'txt', 'htm', 'html'].includes(ext) || mime === 'message/rfc822' || mime === 'application/vnd.ms-outlook';
  return { json: {
    documento_id: Number(d.id ?? $('Lista os anexos').all()[i]?.json.documento_id),
    nome,
    mime,
    sha1: /^[0-9a-f]{40}$/i.test(String(d.sha1sum ?? '')) ? String(d.sha1sum).toLowerCase() : '',
    baixar,
  }, pairedItem: i };
});
