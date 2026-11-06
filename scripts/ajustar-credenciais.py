"""Liga os nós do fluxo às credenciais que já existem no n8n.

O JSON do repositório usa ids fixos (ex.: scanGeminiApi001). Se a credencial foi criada pela
tela do n8n, ela tem outro id. Este script troca a referência pela credencial existente do
MESMO TIPO, desde que haja só uma desse tipo (se houver várias, prefere a de nome igual).

Uso: python scripts/ajustar-credenciais.py fluxo.json credenciais.json > fluxo-ajustado.json
     (credenciais.json = saída de "n8n export:credentials --all"; só id, nome e tipo são lidos)
"""
import json
import sys

fluxo = json.load(open(sys.argv[1], encoding="utf-8"))
existentes = json.load(open(sys.argv[2], encoding="utf-8"))
por_id = {c["id"] for c in existentes}

for no in fluxo["nodes"]:
    for tipo, ref in (no.get("credentials") or {}).items():
        if ref["id"] in por_id:
            continue
        candidatas = [c for c in existentes if c["type"] == tipo]
        mesmo_nome = [c for c in candidatas if c["name"] == ref["name"]]
        escolhida = mesmo_nome[0] if mesmo_nome else candidatas[0] if len(candidatas) == 1 else None
        if escolhida:
            print(f"  {no['name']}: usando a credencial '{escolhida['name']}'", file=sys.stderr)
            no["credentials"][tipo] = {"id": escolhida["id"], "name": escolhida["name"]}
        elif candidatas:
            print(f"  {no['name']}: há {len(candidatas)} credenciais do tipo {tipo}; renomeie uma para '{ref['name']}'", file=sys.stderr)
        else:
            print(f"  {no['name']}: falta criar a credencial '{ref['name']}' (tipo {tipo})", file=sys.stderr)

json.dump(fluxo, sys.stdout, ensure_ascii=False, indent=2)
