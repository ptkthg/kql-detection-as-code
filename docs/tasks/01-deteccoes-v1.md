# Spec 01: estrutura, ferramentas, 8 detecções e CI

**Implementador:** Codex. **Revisor:** Claude.
**Leia antes:** `AGENTS.md` e `docs/tasks/00-spike_kusto.py` (spike que já funcionou contra o emulador).

## Objetivo
Repositório de detection as code em KQL para o advanced hunting do Microsoft Defender XDR. Cada detecção é
um YAML com metadados e consulta. Os testes rodam a consulta de verdade no **emulador oficial do Kusto**
contra dados sintéticos, um positivo e um negativo por detecção. Uma coluna fora do schema oficial faz o
teste falhar.

## O que o spike já comprovou (24/11/2026)
- Imagem: `mcr.microsoft.com/azuredataexplorer/kustainer-linux`, digest do índice
  `sha256:81bb7fc1cdda3ee96f725221bbf37b525eca32718d2c2c6a4a6522f84ec97458`. Sobe com `-e ACCEPT_EULA=Y -p 8080:8080`
  e responde em cerca de 15 s.
- API: `POST http://localhost:8080/v1/rest/query` com JSON `{"db": "NetDefaultDB", "csl": "<consulta>"}`. A
  resposta traz `Tables[0].Columns` e `Tables[0].Rows`. Saúde: `POST /v1/rest/mgmt` com `.show databases` → 200.
- Funcionam: `let T = datatable(...)[...]`, `has_any`, `in~`, `=~`, `matches regex`, `parse_command_line(x, "windows")`,
  `bin()`, `dcount()`, `summarize`.
- Coluna ou tabela inexistente → HTTP 400 (`General_BadRequest`). **É isso que valida o schema.**
- Tempo por consulta: de 30 a 460 ms.

## Estrutura
```
detections/KDAC-00N-<slug>.yaml
tests/fixtures/KDAC-00N/positivo.json   # lista de objetos {coluna: valor}
tests/fixtures/KDAC-00N/negativo.json
schemas/defender/DeviceProcessEvents.json
schemas/defender/EntraIdSignInEvents.json   # {"tabela": ..., "fonte": <url>, "conferido_em": "2026-11-24", "colunas": [{"nome":..., "tipo":...}]}
src/kdac/__init__.py
src/kdac/modelo.py       # carrega YAML e schemas (funções puras)
src/kdac/validar.py      # python -m kdac.validar
src/kdac/executar.py     # cliente REST (urllib) + montagem do datatable
src/kdac/documentar.py   # python -m kdac.documentar [--check]
tests/test_validar.py    # testes unitários sem emulador (validação e montagem do datatable)
tests/test_deteccoes.py  # parametrizado por detecção; usa o emulador (pula com mensagem clara se ele não responder)
navigator/layer.json     # gerado
README.md                # trecho entre marcadores gerado
pyproject.toml           # uv; runtime: pyyaml; dev: pytest
.github/workflows/ci.yml
LICENSE                  # MIT, "Copyright (c) 2026 Patrick Santos"
```

## Formato da detecção (YAML)
```yaml
id: KDAC-001
titulo: PowerShell com comando codificado
descricao: >
  O que detecta e por que importa, em 2 ou 3 frases.
attack:
  - tecnica: T1059.001
    nome: "Command and Scripting Interpreter: PowerShell"
    tatica: execution
tabelas: [DeviceProcessEvents]
severidade: media            # baixa | media | alta
falsos_positivos:
  - Ferramentas de gerenciamento que usam -EncodedCommand legitimamente (ajuste por allowlist).
query: |
  DeviceProcessEvents
  | where ...
testes:
  positivo: { fixture: tests/fixtures/KDAC-001/positivo.json, minimo: 1 }
  negativo: { fixture: tests/fixtures/KDAC-001/negativo.json, maximo: 0 }
referencias:
  - https://attack.mitre.org/techniques/T1059/001/
```
`validar.py` confere:
- campos obrigatórios e tipos;
- `id` único e igual ao prefixo do arquivo;
- técnica no formato `^T\d{4}(\.\d{3})?$`;
- tática dentro das 14 táticas Enterprise (em minúsculas, com hífen);
- severidade válida;
- fixtures existentes e não vazios;
- cada coluna usada nos fixtures existindo no schema da tabela;
- `tabelas` com schema em `schemas/defender/`.
Erros claros, com código de saída 1.

## Execução (o coração)
`executar.py` monta, para cada tabela da detecção:
```
let <Tabela> = datatable(<TODAS as colunas do schema>:<tipo>)[ <linhas do fixture; colunas ausentes = valor nulo do tipo> ];
<query da detecção>
```
- Mapeamento de tipos para literais KQL:
  - `string` → `"..."` com escape de `\` e `"`;
  - `datetime` → `datetime(...)`; `long`/`int` → número; `bool`/`boolean` → `true`/`false`;
  - `dynamic` → `dynamic(...)`;
  - nulos → `""` em string, `datetime(null)`, `long(null)`, `int(null)`, `bool(null)`, `dynamic(null)`.
- Tipo `boolean` da documentação vira `bool` no KQL.
- Retorna o número de linhas e as linhas. Timeout de 30 s por consulta.
- URL do emulador configurável por `KDAC_KUSTO_URL` (padrão `http://localhost:8080`).

## Schemas
Copie as colunas **exatamente** das páginas oficiais, conferindo você mesmo na fonte:
- DeviceProcessEvents: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- EntraIdSignInEvents: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table

`EntraIdSignInEvents` é a sucessora da `AADSignInEventsBeta`, que está obsoleta, e ainda está em preview.
Registre isso no README.

Pontos já levantados que exigem conferência na fonte:
- a página da DeviceProcessEvents lista `LogonId` **e** `LogonID` (maiúscula). Mantenha os dois se a página
  mantiver e anote isso no resultado;
- na EntraIdSignInEvents, uma leitura prévia contou 61 linhas na tabela da página, mas só listou 52 colunas.
  Confira a lista completa.

## As 8 detecções (escreva do zero, com KQL limpo e comentado)
| ID | Detecção | ATT&CK (técnica / tática) | Ideia do negativo benigno |
|---|---|---|---|
| KDAC-001 | PowerShell com comando codificado (`-enc`, `-EncodedCommand`, `-ec` e abreviações) | T1059.001 / execution | `powershell.exe -File C:\scripts\backup.ps1`; um `-Encoding UTF8` num `Out-File` **não** pode disparar |
| KDAC-002 | Office ou Outlook iniciando interpretador de script (cmd, powershell, pwsh, wscript, cscript, mshta) | T1204.002 / execution; T1566.001 / initial-access | Outlook abrindo `msedge.exe` para um link |
| KDAC-003 | certutil baixando arquivo (`-urlcache` com `-f` ou `-split` e URL http/https) | T1105 / command-and-control | `certutil -hashfile arquivo.zip SHA256` |
| KDAC-004 | mshta com URL ou `javascript:`/`vbscript:`; rundll32 com `javascript:` | T1218.005 e T1218.011 / defense-evasion | `mshta.exe C:\Program Files\App\local.hta` (arquivo local de app instalado) |
| KDAC-005 | Dump do LSASS via `rundll32 comsvcs.dll, MiniDump` | T1003.001 / credential-access | `rundll32.exe shell32.dll,Control_RunDLL` |
| KDAC-006 | `schtasks /create` (com destaque para `/ru SYSTEM` ou ação em pasta gravável pelo usuário) | T1053.005 / persistence e execution | `schtasks /query /fo LIST` |
| KDAC-007 | `net user <x> /add` ou `net localgroup administrators <x> /add` (também `net1.exe`) | T1136.001 / persistence; T1098 / persistence | `net user ana` (só consulta) |
| KDAC-008 | Password spray: um `IPAddress` com falhas (`ErrorCode != 0`) para ≥ 10 contas distintas numa janela de 30 min, com poucas tentativas por conta | T1110.003 / credential-access | 12 falhas de **uma** conta só (senha esquecida) a partir de um IP |

- Na KDAC-008, os limiares ficam em `let` no topo da consulta (`limiar_contas = 10`, `janela = 30m`) e
  são comentados como ajustáveis.
- Fixtures: no positivo, a linha maliciosa mais pelo menos uma linha benigna (a consulta precisa filtrar).
  No negativo, só linhas benignas parecidas.
- Comparações de nome de arquivo sem diferenciar maiúsculas (`=~`, `in~`). Use `has`/`has_any` quando
  fizer sentido, por desempenho.

## Documentação gerada
`documentar.py`:
1. Reescreve no README o trecho entre `<!-- deteccoes:inicio -->` e `<!-- deteccoes:fim -->` com uma tabela
   (ID com link para o YAML, título, técnicas com link para o ATT&CK, tática, severidade).
2. Gera `navigator/layer.json`, uma camada do ATT&CK Navigator (domain `enterprise-attack`, uma técnica por
   entrada com `comment` listando os IDs KDAC).
3. Com `--check`, não escreve nada; sai com código 1 se algo estiver desatualizado.

## CI (`.github/workflows/ci.yml`)
- Dispara em `push` e `pull_request`, com `permissions: contents: read` no topo.
- Todas as actions fixadas por SHA de commit, com a versão em comentário.
- Job `validar`: setup do uv, `uv run python -m kdac.validar`, `uv run python -m kdac.documentar --check`,
  `uv run pytest tests/test_validar.py`.
- Job `testar`:
  - `services.kusto` com a imagem fixada pelo digest acima, `env: ACCEPT_EULA: Y`, porta 8080;
  - um passo que espera a saúde (laço com `curl` no `/v1/rest/mgmt`, até 180 s);
  - depois `uv run pytest -v`.

## README.md (pt-BR, com resumo curto em inglês no topo)
1. Badge do CI, mais o resumo em inglês (2 frases).
2. **Aviso**: "Detecções escritas do zero a partir de documentação pública (Microsoft Learn e MITRE ATT&CK).
   Não contém conteúdo de empregadores atuais ou anteriores. Todos os dados de teste são sintéticos."
3. Por que existe: detecção como código, revisável, testada antes de ir para produção.
4. Como funciona: YAML → fixtures → datatable com schema completo → emulador → CI. Inclua um diagrama
   mermaid simples.
5. Tabela gerada das detecções e link para `navigator/layer.json` (como abrir no ATT&CK Navigator).
6. Como rodar localmente (`docker run ...` e `uv run pytest`).
7. Como adicionar uma detecção (passo a passo curto).
8. Limitações:
   - o emulador não é o Defender (não há dados reais nem a cadência de ingestão);
   - dados sintéticos não reproduzem o volume de produção;
   - os limiares da KDAC-008 precisam de ajuste por ambiente;
   - EntraIdSignInEvents está em preview e exige Entra ID P2.

## Critérios de aceite
- Os três comandos do `AGENTS.md` passam. Se você não alcançar o emulador em `localhost:8080` dentro do
  seu sandbox, registre isso no resultado e rode pelo menos `kdac.validar`, `kdac.documentar --check` e
  `tests/test_validar.py`.
- Teste de sanidade registrado no resultado: trocar uma coluna de uma consulta por uma inexistente faz o
  teste da detecção falhar. Depois, desfaça.
- Nenhum nome de empresa real, cliente, IP fora da RFC 5737 ou dado pessoal real nos arquivos.
