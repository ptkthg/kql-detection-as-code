# Resultado da spec 01

Implementação concluída em 24/11/2026, por Codex, conforme `AGENTS.md` e
`docs/tasks/01-deteccoes-v1.md`. O emulador existente em `http://localhost:8080`
foi utilizado de fato; nenhum teste foi pulado.

## Entregas

- Oito detecções originais em YAML, KDAC-001 a KDAC-008, com consultas comentadas,
  metadados ATT&CK, falsos positivos e referências públicas.
- Dezesseis fixtures JSON, com 154 registros sintéticos: variantes suspeitas e
  ruído benigno nos positivos, parecidos benignos nos negativos. UPNs usam
  `@contoso.example`; os IPs dos fixtures pertencem exclusivamente à RFC 5737.
- Schemas completos de `DeviceProcessEvents` e `EntraIdSignInEvents`, obtidos e
  conferidos nas páginas oficiais em 24/11/2026.
- Pacote `src/kdac`: leitura de modelos, validação estrutural e de valores,
  serialização de literais, datatables completos, cliente REST com timeout de
  30 segundos e geração determinística da documentação.
- Catálogo do README e camada Navigator gerados. `--check` compara ambos sem
  escrever; testes verificam preservação do texto manual e detecção de deriva.
- `pyproject.toml` e `uv.lock`; runtime restrito a stdlib e PyYAML, pytest no grupo
  de desenvolvimento. Hatchling é dependência de construção, não de runtime.
- CI com jobs `validar` e `testar`, permissões somente de leitura, actions por
  SHA, imagem do emulador pelo digest especificado e espera de saúde por 180 s.
- README em pt-BR com resumo em inglês, aviso, diagrama Mermaid, instruções de
  execução e extensão, fontes e limitações; licença MIT solicitada.

## Conferência das fontes

- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table):
  **69 colunas**. A página mantém `LogonId` e `LogonID`, ambos `long`; os dois foram
  preservados. `AdditionalFields` permanece `string`, conforme a documentação.
- [EntraIdSignInEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table):
  **52 colunas**, da primeira (`Timestamp`) à última
  (`IsSignInThroughGlobalSecureAccess`). Não foram encontradas 61 colunas na
  tabela oficial consultada. Os tipos `boolean` foram preservados no JSON e
  convertidos para `bool` somente ao montar KQL.
- As onze técnicas/subtécnicas distintas referenciadas nos YAMLs foram
  conferidas nas respectivas páginas públicas do MITRE ATT&CK. Os IDs e nomes
  correspondem às páginas consultadas; as táticas seguem o mapeamento da spec.
- Os SHAs de `actions/checkout` v4.2.2 e `astral-sh/setup-uv` v6.0.1 foram
  resolvidos pela API pública do GitHub, sem credenciais.

## Verificação final

Ambiente: Windows, Python 3.14.4, uv 0.10.12, pytest 9.2.0. O `uv` instalado não
estava no PATH inicial da sessão; o PATH foi ajustado apenas no processo e o
cache configurado dentro do workspace. `uv sync --locked` também passou.

`uv run python -m kdac.validar` — código de saída **0**:

```text
Validação OK: 8 detecções.
```

`uv run python -m kdac.documentar --check` — código de saída **0**:

```text
Documentação atualizada: README.md e navigator/layer.json.
```

`uv run pytest` — código de saída **0**:

```text
============================= test session starts =============================
platform win32 -- Python 3.14.4, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\estudos\kql-detection-as-code
configfile: pyproject.toml
testpaths: tests
collected 69 items

tests\test_deteccoes.py .............................                    [ 42%]
tests\test_documentar.py ..                                              [ 44%]
tests\test_validar.py ......................................             [100%]

============================= 69 passed in 2.67s ==============================
```

Os 29 testes contra o motor incluem os 16 cenários obrigatórios, a falha por
coluna inexistente, a filtragem exata de todas as variantes de processo por
`ReportId`, os indicadores da KDAC-006 e os limites da KDAC-008 (9 e 10 contas;
1, 3 e 4 tentativas por conta). Os 38 testes de validação e os dois de
documentação independem do emulador.

## Sanidade: coluna fora do schema

Foi alterado temporariamente o YAML da KDAC-001, substituindo `FileName` por
`ColunaQueNaoExiste` na query, sem alterar o schema. Executou-se:

```sh
uv run pytest "tests/test_deteccoes.py::test_deteccao[positivo-KDAC-001]" -q --tb=short
```

Resultado esperado e observado, código de saída **1**:

```text
FAILED tests/test_deteccoes.py::test_deteccao[positivo-KDAC-001]
RuntimeError: Kusto HTTP 400: General_BadRequest: Request is invalid and cannot be executed.
1 failed in 0.40s
```

O arquivo original foi restaurado byte a byte em `finally`. A suíte completa
registrada acima foi executada **depois** da restauração. O teste permanente
`test_coluna_inexistente_falha_no_motor` reproduz a mesma verificação em memória,
sem modificar arquivos. O emulador retorna erro genérico, sem citar o nome da
coluna no corpo da resposta; o teste verifica HTTP 400.

## Decisões e desvios da spec

1. **Status de EntraIdSignInEvents:** a spec afirma que está em preview. O título
   da página pública ainda usa esse termo, mas o corpo informa que a substituição
   de `AADSignInEventsBeta` em 19/10/2026 remove o status. O README registra a
   inconsistência, a sucessão da tabela e o requisito Entra ID P2, sem apresentar
   preview como fato inequívoco.
2. **Poucas tentativas por conta:** a spec não quantifica. Foi adotado
   `maximo_por_conta = 3`, ajustável e comentado junto de `limiar_contas = 10` e
   `janela = 30m`. O limite se aplica à maior contagem por conta na janela, sem
   descartar previamente contas de alto volume.
3. **Escopo dos fixtures:** todas as oito detecções usam uma tabela. O validador
   restringe o formato de lista da v1 a uma tabela, para não reutilizar os mesmos
   registros ambiguamente em tabelas diferentes. O montador também aceita um mapa
   de registros por tabela, mas esse formato não faz parte da validação v1.
4. Foi acrescentado `tests/test_documentar.py` e cobertura adicional de variantes
   e limites. O job `validar` executa esses testes de documentação além dos testes
   exigidos em `tests/test_validar.py`.
5. O repositório inicial não possuía commits nem remote. O trabalho foi deixado
   nos arquivos do workspace, sem commit, push ou alteração das entradas
   existentes. O CI foi preparado, mas sua execução no GitHub depende da
   publicação do repositório e não foi observada nesta sessão.

## Revisão e limitações

Houve revisão auxiliar por um agente em contexto separado, somente leitura;
não foram encontrados bloqueadores ou problemas importantes. Essa revisão não
substitui a revisão por Claude prevista na spec.

Melhoria de baixa severidade adiada: na KDAC-006, o indicador
`AcaoEmPastaGravavel` examina o restante da linha após `/tr`. Um caminho em outro
parâmetro, como `/tn \\Temp\\Rotina`, pode marcá-lo como verdadeiro mesmo quando a
ação está em `C:\scripts`. Isso afeta a prioridade sugerida, não o filtro de
criação de tarefa: toda criação já é retornada por definição. O indicador é uma
heurística e exige conferir o argumento efetivo de `/tr` durante a triagem.

As limitações operacionais estão no README: o emulador valida KQL e schema, não
reproduz o Defender ou volume de produção; os testes usam somente dados
sintéticos. A KDAC-008 usa janelas fixas e depende de ajuste por ambiente,
podendo perder atividade na borda da janela ou distribuída. A KDAC-005 não
confirma que o PID alvo é LSASS; a KDAC-002 não prova phishing. A KDAC-007 usa o
nome inglês do grupo administrators e exclui `/domain`. As heurísticas de linha
de comando não cobrem toda ofuscação nem binários renomeados.

## Revisão (Claude), 24/11/2026

- Schemas conferidos com uma leitura independente das páginas do Microsoft Learn: DeviceProcessEvents
  com 69 colunas (incluindo `LogonId` e `LogonID`) e EntraIdSignInEvents com 52. As listas são idênticas.
  O "71" e o "61" da spec vinham de contagem errada da leitura prévia.
- As 8 consultas foram revisadas uma a uma. As limitações conhecidas estão declaradas no README: a
  KDAC-005 não confirma o PID do LSASS, a KDAC-007 cobre só o nome do grupo em inglês e as heurísticas
  de linha de comando não cobrem toda ofuscação.
- SHAs das actions conferidos na API do GitHub; batem com v4.2.2 e v6.0.1. A imagem do emulador está
  fixada pelo digest do spike.
- Busca por dados reais: nenhum nome de empregador ou cliente, nenhum contato pessoal, e todos os IPs
  dos fixtures dentro da RFC 5737.
- Suíte local: `validar` ok, `documentar --check` ok e `pytest` 69/69 com o emulador. Foi preciso usar
  `-p no:cacheprovider --basetemp` por causa da ACL das pastas temporárias criadas pelo sandbox.
- Ajuste: badge do README trocado do caminho relativo para a URL absoluta do repositório.
