"""Executa KQL real; indisponibilidade pula, erro de consulta falha."""
import copy
import json

import pytest

from kdac.executar import consultar, montar_consulta, verificar_saude
from kdac.modelo import RAIZ, carregar_deteccoes, carregar_schemas

DETECCOES = carregar_deteccoes(RAIZ)


@pytest.fixture(scope="module", autouse=True)
def emulador():
    try:
        verificar_saude()
    except (OSError, TimeoutError) as erro:
        pytest.skip(f"Emulador Kusto indisponível em KDAC_KUSTO_URL (padrão localhost:8080): {erro}")


@pytest.mark.parametrize("caminho,deteccao", DETECCOES, ids=[d["id"] for _, d in DETECCOES])
@pytest.mark.parametrize("cenario", ["positivo", "negativo"])
def test_deteccao(caminho, deteccao, cenario):
    caso = deteccao["testes"][cenario]
    linhas = json.loads((RAIZ / caso["fixture"]).read_text(encoding="utf-8"))
    resultado = consultar(montar_consulta(deteccao, linhas, carregar_schemas(RAIZ)))
    if cenario == "positivo":
        assert resultado["quantidade"] >= caso["minimo"], resultado
    else:
        assert resultado["quantidade"] <= caso["maximo"], resultado


def test_coluna_inexistente_falha_no_motor():
    deteccao = copy.deepcopy(DETECCOES[0][1])
    deteccao["query"] = deteccao["query"].replace("FileName", "ColunaQueNaoExiste")
    linhas = json.loads((RAIZ / deteccao["testes"]["positivo"]["fixture"]).read_text(encoding="utf-8"))
    with pytest.raises(RuntimeError, match="HTTP 400"):
        consultar(montar_consulta(deteccao, linhas, carregar_schemas(RAIZ)))


@pytest.mark.parametrize("caminho,deteccao", DETECCOES[:7], ids=[d["id"] for _, d in DETECCOES[:7]])
def test_todas_variantes_positivas_e_filtro_benigno(caminho, deteccao):
    linhas = json.loads((RAIZ / deteccao["testes"]["positivo"]["fixture"]).read_text(encoding="utf-8"))
    resultado = consultar(montar_consulta(deteccao, linhas, carregar_schemas(RAIZ)))
    indice = resultado["colunas"].index("ReportId")
    # IDs < 100 são as variantes suspeitas; 100 é o ruído benigno inserido no positivo.
    assert {r[indice] for r in resultado["linhas"]} == {r["ReportId"] for r in linhas if r["ReportId"] < 100}


def test_schtasks_indicadores_de_prioridade():
    deteccao = next(d for _, d in DETECCOES if d["id"] == "KDAC-006")
    linhas = json.loads((RAIZ / deteccao["testes"]["positivo"]["fixture"]).read_text(encoding="utf-8"))
    resultado = consultar(montar_consulta(deteccao, linhas, carregar_schemas(RAIZ)))
    registros = [dict(zip(resultado["colunas"], linha)) for linha in resultado["linhas"]]
    por_id = {r["ReportId"]: r for r in registros}
    assert por_id[1]["ExecutaComoSystem"] is True
    assert por_id[1]["AcaoEmPastaGravavel"] is True
    assert por_id[2]["ExecutaComoSystem"] is False
    assert por_id[2]["AcaoEmPastaGravavel"] is False


@pytest.mark.parametrize("contas,tentativas,esperado", [(9, 1, 0), (10, 1, 1), (10, 3, 1), (10, 4, 0)])
def test_password_spray_limites(contas, tentativas, esperado):
    deteccao = next(d for _, d in DETECCOES if d["id"] == "KDAC-008")
    linhas = [{"Timestamp": "2026-01-01T10:05:00Z", "AccountUpn": f"conta-{i}@contoso.example",
               "IPAddress": "192.0.2.25", "ErrorCode": 50126}
              for i in range(contas) for _ in range(tentativas)]
    resultado = consultar(montar_consulta(deteccao, linhas, carregar_schemas(RAIZ)))
    assert resultado["quantidade"] == esperado
