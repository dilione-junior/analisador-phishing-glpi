// Nó "Lista os anexos": documentos ligados ao chamado (o .eml do e-mail suspeito, prints, PDFs...).
// Sem anexo: devolve um item marcador, e o fluxo segue direto para a extração das evidências.
const corpo = $input.first().json.body;
const ligacoes = Array.isArray(corpo) ? corpo : [];
const maximo = Number($('Configuração').first().json.maxAnexos) || 4;
const ids = [...new Set(ligacoes.map((l) => Number(l.documents_id)).filter((id) => id > 0))].slice(0, maximo);
if (!ids.length) return [{ json: { sem_anexo: true } }];
return ids.map((id) => ({ json: { documento_id: id } }));
