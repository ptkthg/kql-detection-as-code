"""Verifica geração, preservação de texto manual e detecção de deriva."""
import json
import shutil

from kdac.documentar import gerar
from kdac.modelo import RAIZ


def test_geracao_e_check(tmp_path):
    shutil.copytree(RAIZ / "detections", tmp_path / "detections")
    readme = tmp_path / "README.md"
    readme.write_text("Antes\n<!-- deteccoes:inicio -->\nantigo\n<!-- deteccoes:fim -->\nDepois\n", encoding="utf-8")
    assert gerar(tmp_path, check=True) == 1
    assert not (tmp_path / "navigator").exists()
    assert gerar(tmp_path) == 0
    texto = readme.read_text(encoding="utf-8")
    assert texto.startswith("Antes\n") and texto.endswith("Depois\n")
    assert "detections/KDAC-001-" in texto
    layer = json.loads((tmp_path / "navigator/layer.json").read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) == len({t["techniqueID"] for t in layer["techniques"]})
    assert next(t for t in layer["techniques"] if t["techniqueID"] == "T1053.005")["comment"] == "KDAC-006"
    assert gerar(tmp_path, check=True) == 0
    readme.write_text(texto.replace("PowerShell", "alterado"), encoding="utf-8")
    antes = readme.read_bytes()
    assert gerar(tmp_path, check=True) == 1
    assert readme.read_bytes() == antes


def test_marcadores_ausentes(tmp_path):
    (tmp_path / "README.md").write_text("Texto manual", encoding="utf-8")
    assert gerar(tmp_path) == 1
    assert (tmp_path / "README.md").read_text(encoding="utf-8") == "Texto manual"
