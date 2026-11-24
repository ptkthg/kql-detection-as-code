"""Gera o catálogo do README e a camada Navigator de forma determinística."""
import argparse
import json
import sys

from .modelo import RAIZ, carregar_deteccoes

INICIO = "<!-- deteccoes:inicio -->"
FIM = "<!-- deteccoes:fim -->"


def link_attack(tecnica):
    return "https://attack.mitre.org/techniques/" + tecnica.replace(".", "/") + "/"


def gerar(raiz=RAIZ, check=False):
    readme = raiz / "README.md"
    texto = readme.read_text(encoding="utf-8")
    if texto.count(INICIO) != 1 or texto.count(FIM) != 1 or texto.index(INICIO) >= texto.index(FIM):
        print("README.md: exige um par ordenado de marcadores de detecções", file=sys.stderr)
        return 1
    linhas = ["| ID | Título | Técnicas | Táticas | Severidade |", "| --- | --- | --- | --- | --- |"]
    cobertura = {}
    for caminho, d in carregar_deteccoes(raiz):
        tecnicas = sorted({a["tecnica"] for a in d["attack"]})
        taticas = sorted({a["tatica"] for a in d["attack"]})
        links = ", ".join(f"[{t}]({link_attack(t)})" for t in tecnicas)
        titulo = d["titulo"].replace("|", "\\|").replace("\n", " ")
        linhas.append(f"| [{d['id']}]({caminho.relative_to(raiz).as_posix()}) | {titulo} | {links} | {', '.join(taticas)} | {d['severidade']} |")
        for tecnica in tecnicas:
            cobertura.setdefault(tecnica, set()).add(d["id"])
    antes, resto = texto.split(INICIO)
    _, depois = resto.split(FIM)
    novo_readme = antes + INICIO + "\n\n" + "\n".join(linhas) + "\n\n" + FIM + depois
    camada = {
        "name": "KDAC — detecções v1", "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack", "description": "Cobertura declarada pelas detecções sintéticas KDAC; não mede eficácia em produção.",
        "techniques": [{"techniqueID": t, "comment": ", ".join(sorted(ids)), "enabled": True, "color": "#4a90d9"}
                       for t, ids in sorted(cobertura.items())],
    }
    saidas = {readme: novo_readme, raiz / "navigator/layer.json": json.dumps(camada, ensure_ascii=False, indent=2) + "\n"}
    desatualizados = [p for p, conteudo in saidas.items() if not p.exists() or p.read_text(encoding="utf-8") != conteudo]
    if check:
        for p in desatualizados:
            print(f"Desatualizado: {p.relative_to(raiz)}", file=sys.stderr)
        if not desatualizados:
            print("Documentação atualizada: README.md e navigator/layer.json.")
        return int(bool(desatualizados))
    for p in desatualizados:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(saidas[p], encoding="utf-8")
    print("Documentação gerada: README.md e navigator/layer.json.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="confere sem escrever")
    args = parser.parse_args()
    return gerar(check=args.check)


if __name__ == "__main__":
    sys.exit(main())
