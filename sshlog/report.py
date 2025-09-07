from typing import Dict, Any, List
import os
import pandas as pd
from rich.console import Console
from rich.table import Table
from jinja2 import Template

console = Console()

def print_cli(findings: Dict[str, Any]):
    failed = findings.get("failed_by_ip", pd.DataFrame())
    alerts: List[dict] = findings.get("alerts", [])
    meta = findings.get("meta", {})

    console.rule(f"SSH Log Analyzer — window={meta.get('window')} threshold={meta.get('threshold')}")
    if failed is not None and not failed.empty:
        t = Table(title="Top sources (failed logins)")
        for col in ["ip", "fails", "first_seen", "last_seen"]:
            t.add_column(col)
        for _, r in failed.head(20).iterrows():
            t.add_row(str(r.ip), str(r.fails), str(r.first_seen), str(r.last_seen))
        console.print(t)
    else:
        console.print("[yellow]No failures found.[/yellow]")

    if alerts:
        t2 = Table(title="Alerts")
        for col in ["type", "ip", "user", "count", "first_seen", "last_seen"]:
            t2.add_column(col)
        for a in alerts:
            t2.add_row(a.get("type",""), a.get("ip",""), str(a.get("user","")), str(a.get("count","")),
                       str(a.get("first_seen","")), str(a.get("last_seen","")))
        console.print(t2)
    else:
        console.print("[green]No alerts triggered.[/green]")

def write_csv(findings: Dict[str, Any], base_path: str):
    failed = findings.get("failed_by_ip", pd.DataFrame())
    alerts = pd.DataFrame(findings.get("alerts", []))
    root, ext = os.path.splitext(base_path)
    failed_path = base_path if ext == ".csv" else f"{base_path}_failed.csv"
    alerts_path = f"{root}-alerts.csv" if ext == ".csv" else f"{base_path}_alerts.csv"

    if failed is not None and not failed.empty:
        failed.to_csv(failed_path, index=False)
    if alerts is not None and not alerts.empty:
        alerts.to_csv(alerts_path, index=False)

def write_html(findings: Dict[str, Any], out_path: str):
    failed = findings.get("failed_by_ip", pd.DataFrame())
    alerts = pd.DataFrame(findings.get("alerts", []))

    tmpl = Template("""
<!doctype html>
<html lang="en"><meta charset="utf-8">
<title>SSH Log Analyzer Report</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px;max-width:960px;margin:auto}
 table{border-collapse:collapse;width:100%;margin:16px 0}
 th,td{border:1px solid #ddd;padding:8px;font-size:14px}
 th{background:#111;color:#fff;text-align:left}
 .badge{display:inline-block;padding:2px 8px;border-radius:6px;background:#ffd54f}
</style>
<h1>SSH Log Analyzer Report</h1>
<p><span class="badge">window={{ meta.window }}</span>
   <span class="badge">threshold={{ meta.threshold }}</span></p>

<h2>Top sources (failed logins)</h2>
<table>
<thead><tr>{% for c in ['ip','fails','first_seen','last_seen'] %}<th>{{c}}</th>{% endfor %}</tr></thead>
<tbody>
{% for _, r in failed.iterrows() %}
<tr><td>{{r.ip}}</td><td>{{r.fails}}</td><td>{{r.first_seen}}</td><td>{{r.last_seen}}</td></tr>
{% endfor %}
</tbody></table>

<h2>Alerts</h2>
<table>
<thead><tr>{% for c in ['type','ip','user','count','first_seen','last_seen'] %}<th>{{c}}</th>{% endfor %}</tr></thead>
<tbody>
{% for _, r in alerts.iterrows() %}
<tr><td>{{r.type}}</td><td>{{r.ip}}</td><td>{{r.user}}</td><td>{{r.count}}</td><td>{{r.first_seen}}</td><td>{{r.last_seen}}</td></tr>
{% endfor %}
</tbody></table>
</html>
""")
    html = tmpl.render(failed=failed, alerts=alerts, meta=findings.get("meta", {}))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
