"""Validação estrutural com erros localizados; o motor valida a query."""
import json
import re
import sys

import yaml

from .executar import literal
from .modelo import RAIZ, carregar_deteccoes, carregar_schemas

TATICAS = set("reconnaissance resource-development initial-access execution persistence privilege-escalation defense-evasion credential-access discovery lateral-movement collection command-and-control exfiltration impact".split())


def validar_deteccao(caminho, d, schemas, raiz=RAIZ):
    erros = []

    def erro(mensagem):
        erros.append(f"{caminho.name}: {mensagem}")

    if not isinstance(d, dict):
        return [f"{caminho.name}: YAML deve ser um objeto"]
    for campo in ("id", "titulo", "descricao", "query"):
        if not isinstance(d.get(campo), str) or not d[campo].strip():
            erro(f"{campo}: texto não vazio obrigatório")
    identificador = d.get("id")
    if not isinstance(identificador, str) or not re.fullmatch(r"KDAC-\d{3}", identificador) or not caminho.name.startswith(identificador + "-"):
        erro("id: formato KDAC-NNN e prefixo do arquivo devem coincidir")
    if d.get("severidade") not in ("baixa", "media", "alta"):
        erro("severidade inválida")
    for campo in ("falsos_positivos", "referencias", "tabelas"):
        valor = d.get(campo)
        if not isinstance(valor, list) or not valor or any(not isinstance(v, str) or not v.strip() for v in valor):
            erro(f"{campo}: lista não vazia de textos obrigatória")
    tabelas = d.get("tabelas")
    tabelas = tabelas if isinstance(tabelas, list) else []
    conhecidos = []
    for tabela in tabelas:
        if not isinstance(tabela, str) or tabela not in schemas:
            erro(f"tabelas: schema ausente para {tabela!r}")
        else:
            conhecidos.append(tabela)
    attack = d.get("attack")
    if not isinstance(attack, list) or not attack:
        erro("attack: lista não vazia obrigatória")
    else:
        for item in attack:
            if not isinstance(item, dict):
                erro("attack: entrada deve ser um objeto")
                continue
            if not isinstance(item.get("tecnica"), str) or not re.fullmatch(r"T\d{4}(\.\d{3})?", item["tecnica"]):
                erro("attack.tecnica: formato inválido")
            if not isinstance(item.get("tatica"), str) or item["tatica"] not in TATICAS:
                erro("attack.tatica: tática Enterprise inválida")
            if not isinstance(item.get("nome"), str) or not item["nome"].strip():
                erro("attack.nome: texto obrigatório")
    testes = d.get("testes")
    if not isinstance(testes, dict):
        erro("testes: objeto obrigatório")
        return erros
    for cenario, limite in (("positivo", "minimo"), ("negativo", "maximo")):
        caso = testes.get(cenario)
        if not isinstance(caso, dict):
            erro(f"testes.{cenario}: objeto obrigatório")
            continue
        if type(caso.get(limite)) is not int or caso[limite] < (1 if cenario == "positivo" else 0):
            erro(f"testes.{cenario}.{limite}: inteiro fora do intervalo permitido")
        fixture = caso.get("fixture")
        if not isinstance(fixture, str) or not fixture:
            erro(f"testes.{cenario}.fixture: caminho obrigatório")
            continue
        arquivo = (raiz / fixture).resolve()
        if not arquivo.is_relative_to(raiz.resolve()):
            erro(f"fixture fora do repositório: {fixture}")
            continue
        try:
            linhas = json.loads(arquivo.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            erro(f"fixture {fixture}: {exc}")
            continue
        if not isinstance(linhas, list) or not linhas:
            erro(f"fixture {fixture}: lista vazia ou inválida")
            continue
        # Formato V1: uma lista de objetos para a única tabela declarada.
        if len(conhecidos) != 1:
            erro("fixture em lista exige exatamente uma tabela com schema")
            continue
        colunas = {c["nome"]: c["tipo"] for c in schemas[conhecidos[0]]["colunas"]}
        for numero, linha in enumerate(linhas, 1):
            if not isinstance(linha, dict):
                erro(f"fixture {fixture}, linha {numero}: objeto obrigatório")
                continue
            for coluna, valor in linha.items():
                if coluna not in colunas:
                    erro(f"fixture {fixture}: coluna inexistente {coluna}")
                else:
                    try:
                        literal(valor, colunas[coluna])
                    except ValueError as exc:
                        erro(f"fixture {fixture}, linha {numero}, {coluna}: {exc}")
    return erros


def validar_repositorio(raiz=RAIZ):
    try:
        deteccoes = carregar_deteccoes(raiz)
        schemas = carregar_schemas(raiz)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return [f"Erro de leitura: {exc}"]
    erros, ids = [], set()
    if not deteccoes:
        erros.append("Nenhuma detecção encontrada")
    for caminho, deteccao in deteccoes:
        erros.extend(validar_deteccao(caminho, deteccao, schemas, raiz))
        identificador = deteccao.get("id") if isinstance(deteccao, dict) else None
        if isinstance(identificador, str):
            if identificador in ids:
                erros.append(f"{caminho.name}: id duplicado {identificador}")
            ids.add(identificador)
    return erros


def main():
    erros = validar_repositorio()
    if erros:
        print("\n".join(erros), file=sys.stderr)
        return 1
    print(f"Validação OK: {len(carregar_deteccoes())} detecções.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
