"""Leitura dos arquivos, sem rede e sem efeitos de escrita."""
import json
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parents[2]


def carregar_deteccoes(raiz=RAIZ):
    return [(p, yaml.safe_load(p.read_text(encoding="utf-8")))
            for p in sorted((raiz / "detections").glob("*.yaml"))]


def carregar_schemas(raiz=RAIZ):
    return {p.stem: json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((raiz / "schemas/defender").glob("*.json"))}
