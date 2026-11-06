<?php
// Prepara o GLPI para os relatos de phishing (roda DENTRO do container do GLPI, pela API em localhost).
// Pode rodar de novo: só cria o que ainda não existe. Nunca imprime senhas.
//
//   estrutura  -> grupo "Segurança da Informação", categoria "Segurança > Phishing e e-mail suspeito"
//                 (visível para o usuário abrir chamado), tipos de solução e permissões de leitura do n8n-api.
//   teste      -> abre um chamado de teste em nome de "usuario.teste", com o .eml anexado.
//
// Uso: bash glpi/preparar-glpi.sh [estrutura | teste arquivo.eml "texto do relato"]

$API = 'http://localhost/apirest.php';
$admin = getenv('GLPI_ADMIN_PASSWORD');
$modo = $argv[1] ?? 'estrutura';
if (!$admin) { fwrite(STDERR, "Falta a senha do admin no ambiente.\n"); exit(1); }

function pedido($metodo, $caminho, $corpo = null, $cab = [], $multipart = null) {
    global $API;
    $c = curl_init($API . $caminho);
    $cabecalhos = $multipart ? $cab : array_merge(['Content-Type: application/json'], $cab);
    curl_setopt_array($c, [CURLOPT_CUSTOMREQUEST => $metodo, CURLOPT_RETURNTRANSFER => true, CURLOPT_HTTPHEADER => $cabecalhos, CURLOPT_TIMEOUT => 30]);
    if ($multipart) curl_setopt($c, CURLOPT_POSTFIELDS, $multipart);
    elseif ($corpo !== null) curl_setopt($c, CURLOPT_POSTFIELDS, json_encode($corpo));
    $r = curl_exec($c);
    return [curl_getinfo($c, CURLINFO_HTTP_CODE), json_decode($r, true)];
}
[$cod, $s] = pedido('GET', '/initSession', null, ['Authorization: Basic ' . base64_encode('glpi:' . $admin)]);
if ($cod !== 200) { fwrite(STDERR, "Login na API falhou (HTTP $cod).\n"); exit(1); }
$SESSAO = ['Session-Token: ' . $s['session_token']];
function api($metodo, $caminho, $corpo = null) {
    global $SESSAO;
    [$cod, $r] = pedido($metodo, $caminho, $corpo, $SESSAO);
    if ($cod >= 300) { fwrite(STDERR, "ERRO $metodo $caminho: HTTP $cod " . json_encode($r) . "\n"); exit(1); }
    return $r;
}
function procura($tipo, $campo, $valor) {
    foreach (api('GET', "/$tipo?range=0-999&is_deleted=0") ?: [] as $i) if (($i[$campo] ?? null) === $valor) return $i['id'];
    return null;
}
function garante($tipo, $campo, $valor, $dados) {
    $id = procura($tipo, $campo, $valor);
    if ($id) { echo "  já existe: $tipo \"$valor\"\n"; return $id; }
    $r = api('POST', "/$tipo", ['input' => $dados]);
    echo "  criado: $tipo \"$valor\"\n";
    return $r['id'];
}
$todas = ['entities_id' => 0, 'is_recursive' => 1];
const CATEGORIA = 'Segurança > Phishing e e-mail suspeito';
const GRUPO = 'Segurança da Informação';

if ($modo === 'estrutura') {
    echo "Grupo\n";
    $si = garante('Group', 'name', GRUPO, $todas + ['name' => GRUPO, 'is_assign' => 1, 'is_requester' => 0, 'is_notify' => 1,
        'comment' => 'Time de Segurança da Informação: recebe os relatos de phishing e e-mails/contatos suspeitos.']);
    $dilione = procura('User', 'name', 'dilione');
    if ($dilione) {
        $ja = false;
        foreach (api('GET', "/User/$dilione/Group_User") ?: [] as $g) if ((int)$g['groups_id'] === (int)$si) $ja = true;
        if (!$ja) { api('POST', '/Group_User', ['input' => ['users_id' => $dilione, 'groups_id' => $si]]); echo "  dilione entrou no grupo " . GRUPO . "\n"; }
    }

    echo "Categoria (o usuário escolhe ao abrir o chamado)\n";
    $pai = garante('ITILCategory', 'completename', 'Segurança', $todas + ['name' => 'Segurança', 'is_incident' => 1, 'is_request' => 0, 'is_problem' => 1, 'is_change' => 0]);
    $cat = garante('ITILCategory', 'completename', CATEGORIA, $todas + ['name' => 'Phishing e e-mail suspeito', 'itilcategories_id' => $pai,
        'is_incident' => 1, 'is_request' => 1, 'is_problem' => 0, 'is_change' => 0, 'is_helpdeskvisible' => 1, 'groups_id' => $si,
        'comment' => 'MITRE ATT&CK T1566 (Phishing). Use para relatar e-mail, SMS, ligação ou mensagem suspeita. ' .
                     'Anexe o e-mail como arquivo (.eml ou .msg) e conte se clicou, digitou senha ou abriu anexo.']);
    // Garante o grupo responsável e a visibilidade mesmo se a categoria já existia.
    api('PUT', "/ITILCategory/$cat", ['input' => ['id' => $cat, 'groups_id' => $si, 'is_helpdeskvisible' => 1, 'is_request' => 1, 'is_incident' => 1]]);
    echo "  categoria atribui ao grupo " . GRUPO . " e aparece na abertura de chamado\n";

    // Atribuição automática pela categoria (só preenche o que vier vazio; não muda os chamados do Wazuh).
    $entidade = api('GET', '/Entity/0');
    // -10 (Entity::CONFIG_NEVER) e 0 = desligada; 1 e 2 = ligada.
    if (in_array((int)($entidade['auto_assign_mode'] ?? 0), [0, -10], true)) {
        api('PUT', '/Entity/0', ['input' => ['id' => 0, 'auto_assign_mode' => 2]]);
        echo "  entidade: atribuição automática pela categoria LIGADA\n";
    } else {
        echo "  entidade: atribuição automática já estava ligada (modo {$entidade['auto_assign_mode']})\n";
    }

    echo "Tipos de solução (decisão do analista)\n";
    foreach ([['Phishing confirmado', 'Relato de phishing confirmado pelo analista (verdadeiro positivo).'],
              ['Contato legítimo', 'O e-mail ou contato relatado era legítimo (falso positivo do usuário).'],
              ['Spam (não malicioso)', 'Propaganda não solicitada, sem tentativa de golpe.']] as [$nome, $comentario]) {
        garante('SolutionType', 'name', $nome, $todas + ['name' => $nome, 'comment' => $comentario]);
    }

    echo "Permissões do n8n-api (só leitura a mais)\n";
    $perfil = procura('Profile', 'name', 'NG-SOC API (N8N)');
    if (!$perfil) { fwrite(STDERR, "Perfil 'NG-SOC API (N8N)' não existe: rode antes o infra/glpi/criar-estrutura.sh do ng-soc-lab.\n"); exit(1); }
    // document READ = baixar o .eml anexado; dropdown READ = ler os tipos de solução. Os outros direitos não mudam.
    $mais = ['document' => 1, 'dropdown' => 1];
    foreach (api('GET', "/Profile/$perfil/ProfileRight?range=0-999") ?: [] as $pr) {
        if (!isset($mais[$pr['name']])) continue;
        $novo = (int)$pr['rights'] | $mais[$pr['name']];
        if ($novo !== (int)$pr['rights']) { api('PUT', "/ProfileRight/{$pr['id']}", ['input' => ['id' => $pr['id'], 'rights' => $novo]]); echo "  {$pr['name']}: leitura liberada\n"; }
        else echo "  {$pr['name']}: já tinha leitura\n";
    }

    echo "Usuário de teste (fictício, sem senha: não entra pela tela)\n";
    garante('User', 'name', 'usuario.teste', ['name' => 'usuario.teste', 'realname' => 'Teste', 'firstname' => 'Usuária',
        '_profiles_id' => 1, '_entities_id' => 0, '_is_recursive' => 0, 'comment' => 'Requerente dos chamados de teste do analisador de phishing.']);
}

if ($modo === 'teste') {
    $arquivo = $argv[2] ?? '';
    $relato = $argv[3] ?? 'Recebi este e-mail estranho. Não cliquei em nada.';
    $cat = procura('ITILCategory', 'completename', CATEGORIA);
    $si = procura('Group', 'name', GRUPO);
    $usuario = procura('User', 'name', 'usuario.teste');
    if (!$cat || !$si || !$usuario) { fwrite(STDERR, "Falta a estrutura: rode antes 'bash glpi/preparar-glpi.sh'.\n"); exit(1); }
    $r = api('POST', '/Ticket', ['input' => ['name' => '[TESTE] E-mail suspeito', 'content' => '<p>' . htmlspecialchars($relato) . '</p>',
        'type' => 1, 'itilcategories_id' => $cat, '_users_id_requester' => $usuario, '_groups_id_assign' => $si, 'entities_id' => 0]]);
    $chamado = $r['id'];
    echo "  chamado de teste #$chamado aberto\n";
    if ($arquivo && is_file($arquivo)) {
        $nome = basename($arquivo);
        [$cod, $doc] = pedido('POST', '/Document', null, $SESSAO, [
            'uploadManifest' => json_encode(['input' => ['name' => "E-mail do chamado #$chamado", '_filename' => [$nome]]]),
            'filename[0]' => new CURLFile($arquivo, 'message/rfc822', $nome),
        ]);
        if ($cod >= 300 || empty($doc['id'])) { fwrite(STDERR, "Falhou ao anexar (HTTP $cod) " . json_encode($doc) . "\n"); exit(1); }
        api('POST', '/Document_Item', ['input' => ['documents_id' => $doc['id'], 'itemtype' => 'Ticket', 'items_id' => $chamado, 'entities_id' => 0]]);
        echo "  anexo $nome ligado ao chamado\n";
    }
    echo "CHAMADO=$chamado\n";
}

pedido('GET', '/killSession', null, $SESSAO);
echo "Pronto.\n";
