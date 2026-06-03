from __future__ import annotations

import csv
import html
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from models import PROJECT_DIR, RAW_DIR, RESULTS_DIR, ReportRow
from scanner import (
    load_packages_from_lockfile,
    run_guarddog,
    run_npm_audit,
    run_npq,
    run_osv,
    write_json,
)


def write_csv_report(path: Path, rows: list[ReportRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(asdict(rows[0]).keys()) if rows else ["package"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_html_report(path: Path, rows: list[ReportRow]) -> None:
    e = html.escape

    def cls(value: str) -> str:
        v = value.lower()
        if v.startswith("flagged"):
            return "bad"
        if v.startswith(("tool error", "not checked")):
            return "warn"
        return "ok"

    table_rows = "".join(
        "<tr>"
        f"<td><strong>{e(r.package)}</strong><br><code>{e(r.version)}</code></td>"
        f"<td><span class='{cls(r.npm_audit_result)}'>{e(r.npm_audit_result)}</span></td>"
        f"<td><span class='{cls(r.osv_result)}'>{e(r.osv_result)}</span></td>"
        f"<td><span class='{cls(r.npq_result)}'>{e(r.npq_result)}</span></td>"
        f"<td class='gd-cell'><span class='{cls(r.guarddog_result)}'>{e(r.guarddog_result)}</span></td>"
        "</tr>"
        for r in rows
    )

    generated_at = e(datetime.now(timezone.utc).isoformat(timespec="seconds"))

    doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>NPM Supply Chain Defense Comparison Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 32px; color: #222; }}
  h1 {{ margin-bottom: 4px; }}
  .subtitle {{ color: #666; margin-bottom: 24px; font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ border: 1px solid #ddd; padding: 10px; vertical-align: top; }}
  th {{ background: #f4f4f4; text-align: left; white-space: nowrap; }}
  code {{ background: #f5f5f5; padding: 2px 4px; border-radius: 4px; font-size: 12px; }}
  .bad  {{ color: #b00020; font-weight: bold; }}
  .warn {{ color: #9a6700; }}
  .ok   {{ color: #1b7f37; font-weight: bold; }}
  .gd-cell {{ max-width: 420px; word-break: break-word; }}
  .legend {{ margin-top: 20px; font-size: 12px; color: #555; border-top: 1px solid #eee; padding-top: 12px; }}
</style></head>
<body>
  <h1>NPM Supply Chain Defense Comparison Report</h1>
  <p class="subtitle">
    Generated at {generated_at}<br>
    <strong>npm audit / OSV</strong>:比對已知 CVE 資料庫,新發布的惡意套件通常抓不到<br>
    <strong>npq</strong>:檢查套件 metadata(domain、age、provenance)<br>
    <strong>GuardDog</strong>:Datadog 的 Semgrep 規則,偵測 process.env 序列化、敏感資料外洩、安裝腳本濫用等行為模式(本 demo 核心)
  </p>
  <table>
    <thead><tr>
      <th>Package</th><th>npm audit</th><th>OSV</th><th>npq</th>
      <th>GuardDog (Semgrep behavior)</th>
    </tr></thead>
    <tbody>{table_rows}</tbody>
  </table>
  <div class="legend">
    GuardDog 命中的規則:<em>npm-serialize-environment</em>=序列化 process.env ／
    <em>npm-exfiltrate-sensitive-data</em>=讀檔後網路外傳 ／
    <em>npm-install-script</em>=安裝腳本自動執行。<br>
    對照組:npm audit 與 OSV 對沒有 CVE 的新惡意套件不會有反應,凸顯供應鏈攻擊需要「行為偵測」而非僅靠版本比對。
  </div>
</body></html>"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")


def build_rows() -> list[ReportRow]:
    packages = load_packages_from_lockfile()
    npm_audit_results = run_npm_audit()
    osv_results = run_osv(packages)
    npq_results = run_npq(packages)
    guarddog_results = run_guarddog(packages)

    return [
        ReportRow(
            package=p.package,
            version=p.version,
            npm_audit_result=npm_audit_results.get(p.package, "not flagged"),
            osv_result=osv_results.get(p.package, "not checked"),
            npq_result=npq_results.get(p.package, "not checked"),
            guarddog_result=guarddog_results.get(p.package, "not checked"),
        )
        for p in packages
    ]


def main() -> None:
    if not (PROJECT_DIR / "package.json").exists():
        raise FileNotFoundError(f"Missing package.json in {PROJECT_DIR}")
    if not (PROJECT_DIR / "package-lock.json").exists():
        raise FileNotFoundError(f"Missing package-lock.json in {PROJECT_DIR}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    rows = build_rows()
    write_json(RESULTS_DIR / "report.json", [asdict(r) for r in rows])
    write_csv_report(RESULTS_DIR / "report.csv", rows)
    write_html_report(RESULTS_DIR / "report.html", rows)

    print("Scan finished.")
    print(f"Report: {RESULTS_DIR / 'report.html'}")
    print("Columns: Package | npm audit | OSV | npq | GuardDog")


if __name__ == "__main__":
    main()
