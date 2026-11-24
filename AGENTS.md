# kql-detection-as-code: instruções para agentes

Projeto de portfólio (security engineering): detecções KQL para o advanced hunting do Microsoft Defender XDR,
escritas do zero, versionadas como código e testadas num motor Kusto real (emulador oficial) no CI.

Idioma: português do Brasil, com acentuação correta. Nomes de tabelas, colunas, funções KQL e comandos ficam no original.

## Regras inegociáveis
1. **Só fontes públicas.** As detecções se baseiam na documentação pública do Microsoft Defender
   (Microsoft Learn) e no MITRE ATT&CK. Nada de conteúdo de empregadores, clientes ou incidentes reais.
2. **Dados de teste sintéticos.** Use nomes fictícios (`host-01`, `ana@contoso.example`) e IPs de
   documentação (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Nunca dados reais.
3. **Schema fiel à documentação.** Os arquivos em `schemas/` reproduzem as colunas e os tipos da
   página oficial da tabela. Coluna que não está na documentação não entra.
4. **Toda detecção tem teste positivo e negativo.** O negativo é um "parecido benigno" plausível, que
   mostra o raciocínio sobre falsos positivos.
5. **ATT&CK correto.** IDs de técnica ou subtécnica válidos (`T1059.001`), com a tática coerente.
6. **Sem segredos** em nenhum arquivo.
7. Python via `uv` (`uv run ...`). Dependências de runtime: só stdlib e PyYAML. `pytest` é dependência de desenvolvimento.

## Antes de terminar, tudo isto passa
```
uv run python -m kdac.validar
uv run python -m kdac.documentar --check
uv run pytest          # exige o emulador Kusto em http://localhost:8080
```
Specs ficam em `docs/tasks/NN-*.md`. Quem implementa registra em `docs/tasks/NN-resultado.md` o que fez,
as saídas dos comandos acima, os desvios da spec e as limitações.
