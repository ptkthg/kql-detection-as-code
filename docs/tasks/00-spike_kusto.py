"""Spike: o emulador Kusto serve para testar detecções com datatable?"""
import json
import sys
import time
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")
URL = "http://localhost:8080/v1/rest/query"


def consultar(csl):
    corpo = json.dumps({"db": "NetDefaultDB", "csl": csl}).encode()
    req = urllib.request.Request(URL, data=corpo, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            dados = json.load(resp)
        tabela = dados["Tables"][0]
        return {"ok": True, "linhas": tabela["Rows"], "colunas": [c["ColumnName"] for c in tabela["Columns"]], "ms": round((time.perf_counter() - t0) * 1000)}
    except urllib.error.HTTPError as erro:
        texto = erro.read().decode(errors="replace")
        return {"ok": False, "erro": texto[:300], "ms": round((time.perf_counter() - t0) * 1000)}


DPE = """let DeviceProcessEvents = datatable(Timestamp:datetime, DeviceName:string, FileName:string, ProcessCommandLine:string, InitiatingProcessFileName:string, AccountName:string)[
  datetime(2026-01-01 10:00), "host-01", "powershell.exe", "powershell.exe -NoP -EncodedCommand SQBFAFgA", "cmd.exe", "ana",
  datetime(2026-01-01 10:01), "host-01", "powershell.exe", "powershell.exe -File C:\\\\scripts\\\\backup.ps1", "explorer.exe", "ana",
  datetime(2026-01-01 10:02), "host-02", "cmd.exe", "cmd.exe /c whoami", "WINWORD.EXE", "bruno"
];
"""

SIGNIN = """let Entra = datatable(Timestamp:datetime, AccountUpn:string, IPAddress:string, ErrorCode:int)[
  datetime(2026-01-01 10:00), "a@x.com", "203.0.113.7", 50126,
  datetime(2026-01-01 10:01), "b@x.com", "203.0.113.7", 50126,
  datetime(2026-01-01 10:02), "c@x.com", "203.0.113.7", 50126,
  datetime(2026-01-01 10:03), "d@x.com", "198.51.100.9", 0
];
"""

casos = {
    "has_any": DPE + 'DeviceProcessEvents | where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ") | project DeviceName, ProcessCommandLine',
    "regex e in~": DPE + 'DeviceProcessEvents | where InitiatingProcessFileName in~ ("winword.exe", "outlook.exe") and FileName in~ ("cmd.exe", "powershell.exe") | extend tem_enc = ProcessCommandLine matches regex @"(?i)-e(nc|ncodedcommand)?\\s"',
    "parse_command_line": DPE + 'DeviceProcessEvents | extend args = parse_command_line(ProcessCommandLine, "windows") | project args',
    "bin + dcount (password spray)": SIGNIN + "Entra | where ErrorCode != 0 | summarize contas = dcount(AccountUpn), tentativas = count() by IPAddress, bin(Timestamp, 30m) | where contas >= 3",
    "coluna inexistente (deve FALHAR)": DPE + "DeviceProcessEvents | where ColunaQueNaoExiste == 1",
    "tabela inexistente sem let (deve FALHAR)": "DeviceNetworkEvents | take 1",
}

for nome, csl in casos.items():
    r = consultar(csl)
    if r["ok"]:
        print(f"[OK]    {nome}: {len(r['linhas'])} linha(s) em {r['ms']} ms -> {r['linhas'][:2]}")
    else:
        print(f"[ERRO]  {nome}: {r['ms']} ms -> {r['erro'][:160]}")
