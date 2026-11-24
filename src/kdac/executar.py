"""Literais tipados, datatables completos e cliente REST stdlib."""
import json
import os
from datetime import datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def literal(valor, tipo):
    tipo = "bool" if tipo == "boolean" else tipo
    if tipo not in {"string", "datetime", "long", "int", "bool", "dynamic"}:
        raise ValueError(f"Tipo KQL não suportado: {tipo}")
    if valor is None:
        return '""' if tipo == "string" else f"{tipo}(null)"
    if tipo == "string" and isinstance(valor, str):
        return json.dumps(valor, ensure_ascii=False)
    if tipo == "datetime" and isinstance(valor, str):
        try:
            datetime.fromisoformat(valor.replace("Z", "+00:00"))
        except ValueError as erro:
            raise ValueError(f"datetime inválido: {valor!r}") from erro
        return f"datetime({valor})"
    if tipo in {"long", "int"} and type(valor) is int:
        bits = 64 if tipo == "long" else 32
        if -(2 ** (bits - 1)) <= valor < 2 ** (bits - 1):
            return str(valor)
    if tipo == "bool" and type(valor) is bool:
        return str(valor).lower()
    if tipo == "dynamic":
        return f"dynamic({json.dumps(valor, ensure_ascii=False, allow_nan=False)})"
    raise ValueError(f"Valor incompatível com {tipo}: {valor!r}")


def montar_consulta(deteccao, linhas, schemas):
    partes = []
    # V1 usa uma tabela por detecção. Um mapa permite fixtures por tabela no futuro.
    if len(deteccao["tabelas"]) > 1 and not isinstance(linhas, dict):
        raise ValueError("Detecção com várias tabelas exige fixtures mapeados por tabela")
    for tabela in deteccao["tabelas"]:
        colunas = schemas[tabela]["colunas"]
        registros = linhas[tabela] if isinstance(linhas, dict) else linhas
        cabecalho = ", ".join(f"{c['nome']}:{'bool' if c['tipo'] == 'boolean' else c['tipo']}" for c in colunas)
        valores = [", ".join(literal(r.get(c["nome"]), c["tipo"]) for c in colunas) for r in registros]
        partes.append(f"let {tabela} = datatable({cabecalho})[\n" + ",\n".join(valores) + "\n];")
    return "\n".join(partes) + "\n" + deteccao["query"]


def _post(csl, endpoint, timeout):
    url = os.environ.get("KDAC_KUSTO_URL", "http://localhost:8080").rstrip("/")
    requisicao = Request(url + endpoint, data=json.dumps({"db": "NetDefaultDB", "csl": csl}).encode(),
                         headers={"Content-Type": "application/json"})
    try:
        with urlopen(requisicao, timeout=timeout) as resposta:
            return json.load(resposta)
    except HTTPError as erro:
        detalhe = erro.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Kusto HTTP {erro.code}: {detalhe}") from erro


def verificar_saude():
    return _post(".show databases", "/v1/rest/mgmt", 5)


def consultar(csl):
    dados = _post(csl, "/v1/rest/query", 30)
    if dados.get("Exceptions"):
        raise RuntimeError(f"Kusto: {dados['Exceptions']}")
    tabela = dados["Tables"][0]
    return {"quantidade": len(tabela["Rows"]), "linhas": tabela["Rows"],
            "colunas": [c["ColumnName"] for c in tabela["Columns"]]}
