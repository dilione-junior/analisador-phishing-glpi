"""Gera os ícones PNG do suplemento "Reportar phishing" (círculo vermelho com "!").

Sem bibliotecas externas (só zlib/struct). Uso:  python scripts/gerar-icones-suplemento.py
"""
import pathlib
import struct
import zlib

TAMANHOS = (16, 32, 64, 80, 128)
FUNDO = (198, 40, 40)
FRENTE = (255, 255, 255)
AMOSTRAS = 4  # supersampling por eixo (bordas suaves)
DESTINO = pathlib.Path(__file__).resolve().parent.parent / "outlook-suplemento" / "icones"


def forma(x, y):
    """Coordenadas de 0 a 1. Devolve None (transparente), 'fundo' ou 'frente'."""
    dx, dy = x - 0.5, y - 0.5
    if dx * dx + dy * dy > 0.48 ** 2:
        return None
    if abs(dx) <= 0.07 and 0.18 <= y <= 0.60:
        return "frente"
    if (x - 0.5) ** 2 + (y - 0.76) ** 2 <= 0.08 ** 2:
        return "frente"
    return "fundo"


def pixel(tam, px, py):
    r = g = b = a = 0
    for sy in range(AMOSTRAS):
        for sx in range(AMOSTRAS):
            f = forma((px + (sx + 0.5) / AMOSTRAS) / tam, (py + (sy + 0.5) / AMOSTRAS) / tam)
            if f is None:
                continue
            cor = FRENTE if f == "frente" else FUNDO
            r, g, b, a = r + cor[0], g + cor[1], b + cor[2], a + 1
    if a == 0:
        return (0, 0, 0, 0)
    return (r // a, g // a, b // a, round(255 * a / AMOSTRAS ** 2))


def png(tam):
    linhas = b"".join(b"\x00" + bytes(c for px in range(tam) for c in pixel(tam, px, py)) for py in range(tam))

    def bloco(tipo, dados):
        return struct.pack(">I", len(dados)) + tipo + dados + struct.pack(">I", zlib.crc32(tipo + dados) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + bloco(b"IHDR", struct.pack(">IIBBBBB", tam, tam, 8, 6, 0, 0, 0))
            + bloco(b"IDAT", zlib.compress(linhas, 9)) + bloco(b"IEND", b""))


def main():
    DESTINO.mkdir(parents=True, exist_ok=True)
    for tam in TAMANHOS:
        arquivo = DESTINO / f"icone-{tam}.png"
        arquivo.write_bytes(png(tam))
        print(arquivo.relative_to(DESTINO.parent.parent))


if __name__ == "__main__":
    main()
