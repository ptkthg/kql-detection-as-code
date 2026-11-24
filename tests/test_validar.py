"""Contratos da validação e serialização, sem depender do emulador."""
import copy
import json

import pytest

from kdac.executar import literal, montar_consulta
from kdac.modelo import RAIZ, carregar_deteccoes, carregar_schemas
from kdac.validar import validar_deteccao, validar_repositorio


def test_repositorio_valido():
    assert validar_repositorio(RAIZ) == []
    assert len(carregar_deteccoes(RAIZ)) == 8


@pytest.mark.parametrize("tipo,valor,esperado", [
    ("string", 'a\\b"c\n', '"a\\\\b\\"c\\n"'),
    ("string", None, '""'), ("datetime", None, "datetime(null)"),
    ("long", None, "long(null)"), ("int", None, "int(null)"),
    ("boolean", None, "bool(null)"), ("bool", True, "true"),
    ("boolean", False, "false"), ("int", 7, "7"),
    ("dynamic", {"x": [1]}, 'dynamic({"x": [1]})'),
    ("dynamic", None, "dynamic(null)"),
    ("datetime", "2026-01-01T10:00:00Z", "datetime(2026-01-01T10:00:00Z)"),
])
def test_literais(tipo, valor, esperado):
    assert literal(valor, tipo) == esperado


@pytest.mark.parametrize("tipo,valor", [
    ("int", True), ("bool", "false"), ("datetime", "x); print 1; //"),
    ("long", "1"), ("int", 2**31), ("long", 2**63), ("string", 1),
])
def test_rejeita_valor_incompativel(tipo, valor):
    with pytest.raises(ValueError):
        literal(valor, tipo)


def test_datatable_completo_e_boolean():
    schemas = {"T": {"colunas": [
        {"nome": "Nome", "tipo": "string"}, {"nome": "Ativo", "tipo": "boolean"},
        {"nome": "Contagem", "tipo": "long"},
    ]}}
    query = montar_consulta({"tabelas": ["T"], "query": "T | count"}, [{"Nome": "ana"}], schemas)
    assert "datatable(Nome:string, Ativo:bool, Contagem:long)" in query
    assert '"ana", bool(null), long(null)' in query
    assert query.endswith("T | count")


@pytest.mark.parametrize("campo,valor,trecho", [
    ("id", "KDAC-999", "prefixo"), ("titulo", 2, "titulo"),
    ("descricao", "", "descricao"), ("attack", [], "attack"),
    ("severidade", "critica", "severidade"), ("tabelas", ["Inventada"], "schema"),
    ("falsos_positivos", [], "falsos_positivos"), ("referencias", [3], "referencias"),
    ("query", None, "query"), ("testes", [], "testes"),
])
def test_metadados_invalidos(campo, valor, trecho):
    caminho, deteccao = carregar_deteccoes(RAIZ)[0]
    deteccao = copy.deepcopy(deteccao)
    deteccao[campo] = valor
    erros = validar_deteccao(caminho, deteccao, carregar_schemas(RAIZ), RAIZ)
    assert any(trecho in erro for erro in erros)


def test_attack_invalido():
    caminho, deteccao = carregar_deteccoes(RAIZ)[0]
    deteccao["attack"] = [{"tecnica": "T1", "nome": 4, "tatica": "invalida"}]
    erros = validar_deteccao(caminho, deteccao, carregar_schemas(RAIZ), RAIZ)
    assert any("tecnica" in erro for erro in erros)
    assert any("tatica" in erro for erro in erros)
    assert any("nome" in erro for erro in erros)


@pytest.mark.parametrize("linhas,trecho", [([], "vazia"), ([{"Inventada": 1}], "Inventada"),
    ([{"ProcessId": "texto"}], "ProcessId"), ([1], "objeto")])
def test_fixture_invalido(tmp_path, linhas, trecho):
    caminho, deteccao = carregar_deteccoes(RAIZ)[0]
    (tmp_path / "fixture.json").write_text(json.dumps(linhas), encoding="utf-8")
    for caso in deteccao["testes"].values():
        caso["fixture"] = "fixture.json"
    erros = validar_deteccao(caminho, deteccao, carregar_schemas(RAIZ), tmp_path)
    assert any(trecho in erro for erro in erros)


def test_fixture_ausente_e_limites_invalidos(tmp_path):
    caminho, deteccao = carregar_deteccoes(RAIZ)[0]
    deteccao["testes"]["positivo"]["minimo"] = True
    deteccao["testes"]["negativo"]["maximo"] = -1
    erros = validar_deteccao(caminho, deteccao, carregar_schemas(RAIZ), tmp_path)
    assert any("fixture" in erro for erro in erros)
    assert any("minimo" in erro for erro in erros)
    assert any("maximo" in erro for erro in erros)


def test_id_duplicado(tmp_path):
    import shutil
    for pasta in ("detections", "schemas", "tests/fixtures"):
        shutil.copytree(RAIZ / pasta, tmp_path / pasta)
    origem = next((tmp_path / "detections").glob("KDAC-001-*.yaml"))
    shutil.copy(origem, tmp_path / "detections/KDAC-001-duplicada.yaml")
    assert any("duplicado" in erro for erro in validar_repositorio(tmp_path))
