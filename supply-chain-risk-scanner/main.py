from __future__ import annotations

import csv
import html
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from models import PROJECT_DIR, RAW_DIR, RESULTS_DIR, ReportRow
from scanner import (
    load_packages_from_lockfile,
    run_npm_audit,
    run_npq,
    run_osv,
    write_json,
)


# ── Report writers ────────────────────────────────────────────────────────────

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

    def result_class(value: str) -> str:
        if value.startswith("flagged:"):
            return "bad"
        if value.startswith(("tool error", "not checked")):
            return "warn"
        return "ok"

    table_rows = "".join(
        "<tr>"
        f"<td><strong>{e(r.package)}</strong><br><code>{e(r.version)}</code></td>"
        f"<td><span class='{result_class(r.npm_audit_result)}'>{e(r.npm_audit_result)}</span></td>"
        f"<td><span class='{result_class(r.osv_result)}'>{e(r.osv_result)}</span></td>"
        f"<td><span class='{result_class(r.npq_result)}'>{e(r.npq_result)}</span></td>"
        "</tr>"
        for r in rows
    )

    generated_at = e(datetime.now(timezone.utc).isoformat(timespec="seconds"))

    doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>NPM Supply Chain Tool Result Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #222; }}
    h1 {{ margin-bottom: 4px; }}
    .subtitle {{ color: #666; margin-bottom: 24px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border: 1px solid #ddd; padding: 10px; vertical-align: top; }}
    th {{ background: #f4f4f4; text-align: left; }}
    code {{ background: #f5f5f5; padding: 2px 4px; border-radius: 4px; }}
    .bad  {{ color: #b00020; font-weight: bold; }}
    .warn {{ color: #9a6700; font-weight: bold; }}
    .ok   {{ color: #1b7f37; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>NPM Supply Chain Tool Result Report</h1>
  <p class="subtitle">
    Generated at {generated_at}. This report only shows selected public tool results.
    Demo behaviour is explained separately.
  </p>
  <table>
    <thead>
      <tr>
        <th>Package</th><th>npm audit result</th><th>OSV result</th><th>npq result</th>
      </tr>
    </thead>
    <tbody>{table_rows}</tbody>
  </table>
</body>
</html>"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")


# ── Entry point ───────────────────────────────────────────────────────────────

def build_rows() -> list[ReportRow]:
    packages = load_packages_from_lockfile()
    npm_audit_results = run_npm_audit()
    osv_results = run_osv(packages)
    npq_results = run_npq(packages)

    return [
        ReportRow(
            package=p.package,
            version=p.version,
            npm_audit_result=npm_audit_results.get(p.package, "not flagged"),
            osv_result=osv_results.get(p.package, "not checked"),
            npq_result=npq_results.get(p.package, "not checked"),
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
    print("Columns: Package, npm audit result, OSV result, npq result.")


if __name__ == "__main__":
    main()
