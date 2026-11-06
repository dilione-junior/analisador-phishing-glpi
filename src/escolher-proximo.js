// Nó "Escolhe o próximo": pega o primeiro chamado que ainda não foi analisado.
// Um chamado por execução: o fluxo roda a cada 2 minutos, e assim a cota do VirusTotal
// (4 consultas por minuto) e a da IA nunca estouram, mesmo com muitos relatos de uma vez.
const candidatos = $('Lista os candidatos').all();
const prefixo = $('Configuração').first().json.prefixoRedis;
const hoje = new Date().toISOString().slice(0, 10);
const indice = $input.all().findIndex((item) => item.json.reserva === null || item.json.reserva === undefined || item.json.reserva === '');
if (indice < 0) return [{ json: { nenhum: true } }]; // todos já analisados: só fecha a sessão
const c = candidatos[indice].json;
return [{ json: { ...c, chave_cota: `${prefixo}cota:${hoje}` } }];
