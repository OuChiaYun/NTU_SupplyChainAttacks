from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from cve_enricher import enrich_osv_results_with_cves, extract_cve_ids_from_text


OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
SEVERITY_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "info": 0, "none": 0, "unknown": 0}


@dataclass
class PackageRecord:
    name: str
    version: str
    dependency_type: str
    version_spec: str = ""
    lockfile_path: str = ""


@dataclass
class NpqResult:
    package: str
    version: str
    spec: str
    return_code: int
    timed_out: bool
    raw_log_path: str
    issue_types: list[str]
    important_lines: list[str]


@dataclass
class ReportRow:
    package: str
    version: str
    dependency_type: str
    npm_audit_vulnerability_count: int
    npm_audit_severity: str
    npm_audit_cve_ids: list[str]
    osv_vulnerability_count: int
    osv_ids: list[str]
    cve_ids: list[str]
    npq_scanned: bool
    npq_return_code: int | None
    npq_issue_types: list[str]
    npq_log_path: str
    risk_score: int
    risk_level: str


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def run_command(
    args: list[str],
    cwd: Path | None,
    output_path: Path,
    timeout: int = 180,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str, bool]:
    """Run a command, capture stdout+stderr, and always write a raw log."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(
        {
            "CI": "true",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_AUDIT": "false",
        }
    )
    if env_extra:
        env.update(env_extra)

    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env=env,
        )
        output = completed.stdout or ""
        output_path.write_text(output, encoding="utf-8", errors="replace")
        return completed.returncode, output, False
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        output += "\n[TIMEOUT] Command exceeded timeout.\n"
        output_path.write_text(output, encoding="utf-8", errors="replace")
        return 124, output, True


def prepare_workspace(project_dir: Path, raw_dir: Path) -> Path:
    """
    Copy only package metadata into a temporary workspace.

    This avoids writing package-lock.json into the mounted project folder.
    It also avoids copying node_modules or source files.
    """
    if not (project_dir / "package.json").exists():
        raise FileNotFoundError(f"package.json not found in project directory: {project_dir}")

    temp_dir = Path(tempfile.mkdtemp(prefix="npm-risk-scan-"))
    shutil.copy2(project_dir / "package.json", temp_dir / "package.json")

    existing_lock = project_dir / "package-lock.json"
    if existing_lock.exists():
        shutil.copy2(existing_lock, temp_dir / "package-lock.json")

    write_json(raw_dir / "workspace-info.json", {"temporary_workspace": str(temp_dir), "source_project": str(project_dir)})
    return temp_dir


def generate_lockfile(workspace: Path, raw_dir: Path, timeout: int) -> None:
    """
    Generate or refresh package-lock.json without installing package contents.

    npm may contact the registry for metadata, but this command should not create node_modules
    and should not run lifecycle scripts.
    """
    code, output, _ = run_command(
        [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--fund=false",
            "--audit=false",
        ],
        cwd=workspace,
        output_path=raw_dir / "npm-install-package-lock-only.txt",
        timeout=timeout,
    )
    if code != 0:
        raise RuntimeError("npm install --package-lock-only failed. See raw/npm-install-package-lock-only.txt")

    if (workspace / "node_modules").exists():
        # Keep going, but record it clearly. This should not happen with package-lock-only.
        (raw_dir / "warning-node-modules-created.txt").write_text(
            "node_modules was created unexpectedly. Review npm behavior and command options.\n",
            encoding="utf-8",
        )


def run_npm_audit(workspace: Path, raw_dir: Path, timeout: int) -> dict[str, Any]:
    code, output, _ = run_command(
        ["npm", "audit", "--json", "--package-lock-only"],
        cwd=workspace,
        output_path=raw_dir / "npm-audit.json",
        timeout=timeout,
        env_extra={"NPM_CONFIG_AUDIT": "true"},
    )
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": "npm audit did not return valid JSON", "return_code": code, "raw": output[:4000]}


def get_package_sections(package_json: dict[str, Any]) -> dict[str, str]:
    sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundledDependencies",
        "bundleDependencies",
    ]
    result: dict[str, str] = {}
    for section in sections:
        deps = package_json.get(section, {}) or {}
        if isinstance(deps, list):
            for name in deps:
                result[str(name)] = section
        elif isinstance(deps, dict):
            for name in deps:
                result[name] = section
    return result


def package_name_from_lock_path(lock_path: str) -> str:
    # Handles:
    # - node_modules/foo
    # - node_modules/@scope/pkg
    # - node_modules/a/node_modules/b
    marker = "node_modules/"
    if marker not in lock_path:
        return ""
    return lock_path.split(marker)[-1]


def load_packages_from_lockfile(workspace: Path) -> list[PackageRecord]:
    package_json = read_json(workspace / "package.json")
    direct_sections = get_package_sections(package_json)
    lock = read_json(workspace / "package-lock.json")

    packages_obj = lock.get("packages")
    records: dict[str, PackageRecord] = {}

    if isinstance(packages_obj, dict):
        for lock_path, meta in packages_obj.items():
            if not lock_path or not lock_path.startswith("node_modules/"):
                continue
            if not isinstance(meta, dict):
                continue

            name = package_name_from_lock_path(lock_path)
            version = str(meta.get("version") or "")
            if not name or not version:
                continue

            dep_type = direct_sections.get(name, "transitive")
            version_spec = ""
            if name in direct_sections:
                section = direct_sections[name]
                deps = package_json.get(section, {}) or {}
                if isinstance(deps, dict):
                    version_spec = str(deps.get(name, ""))

            # Prefer the first/root-level record for duplicate nested names, but keep exact name unique.
            key = f"{name}@{version}"
            records.setdefault(
                key,
                PackageRecord(
                    name=name,
                    version=version,
                    dependency_type=dep_type,
                    version_spec=version_spec,
                    lockfile_path=lock_path,
                ),
            )
    else:
        # package-lock v1 fallback
        deps = lock.get("dependencies", {}) or {}
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version") or "")
            if not version:
                continue
            dep_type = direct_sections.get(name, "transitive")
            records[f"{name}@{version}"] = PackageRecord(name=name, version=version, dependency_type=dep_type)

    return sorted(records.values(), key=lambda p: (p.dependency_type == "transitive", p.name.lower(), p.version))


def chunked(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def query_osv_batch(packages: list[PackageRecord], raw_dir: Path, batch_size: int = 100) -> dict[str, Any]:
    all_results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for batch_index, batch in enumerate(chunked(packages, batch_size), start=1):
        queries = [
            {
                "version": pkg.version,
                "package": {"name": pkg.name, "ecosystem": "npm"},
            }
            for pkg in batch
        ]
        payload = {"queries": queries}
        try:
            response = requests.post(OSV_QUERY_BATCH_URL, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            results = data.get("results", []) or []
            all_results.extend(results)
            write_json(raw_dir / f"osv-querybatch-{batch_index}.json", data)
        except Exception as exc:
            errors.append({"batch_index": batch_index, "error": str(exc)})
            all_results.extend({} for _ in batch)

    combined = {"results": all_results, "errors": errors}
    write_json(raw_dir / "osv-querybatch-combined.json", combined)
    return combined


def parse_audit_by_package(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    vulnerabilities = audit.get("vulnerabilities", {}) or {}
    if not isinstance(vulnerabilities, dict):
        return result

    for name, item in vulnerabilities.items():
        if not isinstance(item, dict):
            continue
        via = item.get("via", []) or []
        cve_ids = extract_cve_ids_from_text(item)
        titles = []
        for via_item in via:
            if isinstance(via_item, dict):
                if via_item.get("title"):
                    titles.append(via_item["title"])
                cve_ids.extend(extract_cve_ids_from_text(via_item))
        cve_ids = sorted(set(cve_ids))
        severity = str(item.get("severity") or "unknown").lower()
        result[name] = {
            "name": name,
            "severity": severity,
            "is_direct": bool(item.get("isDirect")),
            "via_count": len(via),
            "effects": item.get("effects", []) or [],
            "range": item.get("range"),
            "fix_available": item.get("fixAvailable"),
            "titles": sorted(set(titles)),
            "cve_ids": cve_ids,
        }
    return result


def osv_by_package(
    packages: list[PackageRecord],
    osv_batch_result: dict[str, Any],
    cve_enrichment: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    results = osv_batch_result.get("results", []) or []
    full_osv = cve_enrichment.get("osv_by_id", {}) or {}
    mapping: dict[str, dict[str, Any]] = {}

    for pkg, osv_result in zip(packages, results):
        vulns = osv_result.get("vulns", []) if isinstance(osv_result, dict) else []
        osv_ids = sorted({v.get("id") for v in vulns if isinstance(v, dict) and v.get("id")})
        cve_ids: set[str] = set()
        for osv_id in osv_ids:
            cve_ids.update(full_osv.get(osv_id, {}).get("cve_ids", []) or [])
        mapping[f"{pkg.name}@{pkg.version}"] = {
            "osv_ids": osv_ids,
            "cve_ids": sorted(cve_ids),
            "count": len(osv_ids),
        }

    return mapping


def safe_filename(spec: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", spec).strip("_")[:180] or "package"


def parse_npq_output(output: str, return_code: int, timed_out: bool) -> tuple[list[str], list[str]]:
    lower = output.lower()
    issue_types: set[str] = set()

    checks = [
        ("provenance_regression", ["provenance regression"]),
        ("provenance_unverified", ["unable to verify provenance", "without any attestations", "no provenance"]),
        ("supply_chain_security", ["supply chain security"]),
        ("package_health", ["package health"]),
        ("archived_repository", ["archived on github", "repository has been archived", "archived repository"]),
        ("old_package", ["detected an old package", "old package"]),
        ("install_script", ["preinstall", "postinstall", "install script", "lifecycle script"]),
        ("missing_license", ["missing license", "license"]),
        ("low_downloads", ["low download", "downloads"]),
        ("npq_error", ["error"]),
    ]

    for issue_type, keywords in checks:
        if any(keyword in lower for keyword in keywords):
            issue_types.add(issue_type)

    if return_code != 0:
        issue_types.add("nonzero_exit")
    if timed_out:
        issue_types.add("timeout")

    important_lines = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        l = stripped.lower()
        if any(
            keyword in l
            for keyword in [
                "supply chain",
                "package health",
                "provenance",
                "attestation",
                "archived",
                "old package",
                "preinstall",
                "postinstall",
                "error",
                "warning",
                "cve",
                "vulnerability",
            ]
        ):
            important_lines.append(stripped)

    return sorted(issue_types), important_lines[:20]


def run_npq_scan(
    packages: list[PackageRecord],
    raw_dir: Path,
    scope: str,
    max_packages: int,
    timeout: int,
) -> dict[str, NpqResult]:
    if scope == "none":
        return {}

    candidates = [p for p in packages if scope == "all" or p.dependency_type != "transitive"]
    if max_packages > 0:
        candidates = candidates[:max_packages]

    npq_dir = raw_dir / "npq"
    npq_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, NpqResult] = {}

    for pkg in candidates:
        spec = f"{pkg.name}@{pkg.version}"
        log_path = npq_dir / f"{safe_filename(spec)}.txt"

        # Important: check-only mode. Do NOT use `npq install ...`.
        # `--plain` makes output easier to parse.
        code, output, timed_out = run_command(
            ["npq", spec, "--plain"],
            cwd=None,
            output_path=log_path,
            timeout=timeout,
        )
        issue_types, important_lines = parse_npq_output(output, code, timed_out)
        results[f"{pkg.name}@{pkg.version}"] = NpqResult(
            package=pkg.name,
            version=pkg.version,
            spec=spec,
            return_code=code,
            timed_out=timed_out,
            raw_log_path=str(log_path),
            issue_types=issue_types,
            important_lines=important_lines,
        )

    return results


def severity_max(a: str, b: str) -> str:
    a = (a or "unknown").lower()
    b = (b or "unknown").lower()
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def compute_risk_score(
    audit_count: int,
    audit_severity: str,
    osv_count: int,
    cve_count: int,
    npq_issue_types: list[str],
) -> int:
    score = 0
    if audit_count:
        score += 15
        score += SEVERITY_ORDER.get(audit_severity, 0) * 8
    if osv_count:
        score += 12 + min(osv_count, 5) * 3
    if cve_count:
        score += min(cve_count, 5) * 4

    issue_weights = {
        "provenance_regression": 30,
        "provenance_unverified": 12,
        "supply_chain_security": 12,
        "archived_repository": 15,
        "install_script": 12,
        "package_health": 6,
        "old_package": 5,
        "low_downloads": 5,
        "missing_license": 3,
        "nonzero_exit": 5,
        "timeout": 3,
    }
    for issue in npq_issue_types:
        score += issue_weights.get(issue, 2)
    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def build_report_rows(
    packages: list[PackageRecord],
    audit_by_name: dict[str, dict[str, Any]],
    osv_mapping: dict[str, dict[str, Any]],
    npq_results: dict[str, NpqResult],
) -> list[ReportRow]:
    rows: list[ReportRow] = []

    for pkg in packages:
        key = f"{pkg.name}@{pkg.version}"
        audit_item = audit_by_name.get(pkg.name, {})
        audit_count = int(audit_item.get("via_count", 0) or 0)
        audit_sev = str(audit_item.get("severity", "none") or "none")
        audit_cves = audit_item.get("cve_ids", []) or []

        osv_item = osv_mapping.get(key, {})
        osv_ids = osv_item.get("osv_ids", []) or []
        osv_cves = osv_item.get("cve_ids", []) or []

        all_cves = sorted(set(audit_cves) | set(osv_cves))
        npq = npq_results.get(key)
        npq_issue_types = npq.issue_types if npq else []
        score = compute_risk_score(audit_count, audit_sev, len(osv_ids), len(all_cves), npq_issue_types)

        rows.append(
            ReportRow(
                package=pkg.name,
                version=pkg.version,
                dependency_type=pkg.dependency_type,
                npm_audit_vulnerability_count=audit_count,
                npm_audit_severity=audit_sev,
                npm_audit_cve_ids=audit_cves,
                osv_vulnerability_count=len(osv_ids),
                osv_ids=osv_ids,
                cve_ids=all_cves,
                npq_scanned=npq is not None,
                npq_return_code=npq.return_code if npq else None,
                npq_issue_types=npq_issue_types,
                npq_log_path=npq.raw_log_path if npq else "",
                risk_score=score,
                risk_level=risk_level(score),
            )
        )

    return sorted(rows, key=lambda r: (r.risk_score, r.package.lower()), reverse=True)


def write_csv(path: Path, rows: list[ReportRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = list(asdict(rows[0]).keys()) if rows else ["package"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            data = asdict(row)
            for key, value in data.items():
                if isinstance(value, list):
                    data[key] = "; ".join(map(str, value))
            writer.writerow(data)


def badge(text: str, cls: str = "") -> str:
    return f'<span class="badge {cls}">{html.escape(text)}</span>'


def html_list(items: list[str], empty: str = "-") -> str:
    if not items:
        return html.escape(empty)
    return "<br>".join(html.escape(str(item)) for item in items)


def rel_path(path_str: str, base: Path) -> str:
    if not path_str:
        return ""
    try:
        return str(Path(path_str).resolve().relative_to(base.resolve()))
    except Exception:
        return path_str


def generate_html_report(
    path: Path,
    rows: list[ReportRow],
    packages: list[PackageRecord],
    audit: dict[str, Any],
    cve_enrichment: dict[str, Any],
    npq_results: dict[str, NpqResult],
    metadata: dict[str, Any],
) -> None:
    total = len(rows)
    direct_count = sum(1 for p in packages if p.dependency_type != "transitive")
    cve_count = len({cve for row in rows for cve in row.cve_ids})
    osv_count = len({osv for row in rows for osv in row.osv_ids})
    audit_vuln_packages = sum(1 for row in rows if row.npm_audit_vulnerability_count > 0)
    npq_issue_packages = sum(1 for row in rows if row.npq_issue_types)
    high_count = sum(1 for row in rows if row.risk_level == "High")
    med_count = sum(1 for row in rows if row.risk_level == "Medium")

    table_rows = []
    for row in rows:
        level_class = row.risk_level.lower()
        npq_log = rel_path(row.npq_log_path, path.parent)
        npq_log_html = f'<code>{html.escape(npq_log)}</code>' if npq_log else "-"
        table_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(row.package)}</strong><br><code>{html.escape(row.version)}</code></td>"
            f"<td>{html.escape(row.dependency_type)}</td>"
            f"<td><span class='risk {level_class}'>{html.escape(row.risk_level)}</span><br><small>{row.risk_score}/100</small></td>"
            f"<td>{row.npm_audit_vulnerability_count}<br><small>{html.escape(row.npm_audit_severity)}</small></td>"
            f"<td>{row.osv_vulnerability_count}<br><small>{html_list(row.osv_ids)}</small></td>"
            f"<td>{html_list(row.cve_ids)}</td>"
            f"<td>{'yes' if row.npq_scanned else 'no'}<br><small>{html_list(row.npq_issue_types)}</small></td>"
            f"<td>{npq_log_html}</td>"
            "</tr>"
        )

    nvd_rows = []
    for cve_id, item in sorted((cve_enrichment.get("nvd_by_cve", {}) or {}).items()):
        if not isinstance(item, dict):
            continue
        nvd_rows.append(
            "<tr>"
            f"<td><strong>{html.escape(cve_id)}</strong></td>"
            f"<td>{html.escape(str(item.get('cvss_severity') or '-'))}<br><small>{html.escape(str(item.get('cvss_score') or '-'))}</small></td>"
            f"<td>{html_list(item.get('cwe_ids', []) or [])}</td>"
            f"<td>{html.escape(str(item.get('published') or '-'))}</td>"
            f"<td>{html.escape(str(item.get('description') or item.get('error') or '-'))}</td>"
            "</tr>"
        )

    npm_audit_meta = audit.get("metadata", {}) if isinstance(audit, dict) else {}

    doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>npm Supply Chain Risk Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #f7f8fb; color: #222; }}
    header {{ background: #17202a; color: white; padding: 28px 36px; }}
    main {{ padding: 28px 36px; }}
    h1 {{ margin: 0 0 8px; }}
    h2 {{ margin-top: 34px; }}
    .muted {{ color: #667085; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin-top: 20px; }}
    .card {{ background: white; border: 1px solid #e7eaf0; border-radius: 14px; padding: 18px; box-shadow: 0 4px 14px rgba(0,0,0,0.04); }}
    .metric {{ font-size: 30px; font-weight: 700; margin-bottom: 4px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 14px; overflow: hidden; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid #e7eaf0; vertical-align: top; text-align: left; }}
    th {{ background: #2c3e50; color: white; position: sticky; top: 0; }}
    code {{ background: #f1f3f5; padding: 2px 5px; border-radius: 5px; word-break: break-all; }}
    small {{ color: #667085; }}
    .risk {{ display: inline-block; padding: 4px 9px; border-radius: 999px; font-weight: 700; font-size: 12px; }}
    .risk.high {{ background: #ffe4e4; color: #a40000; }}
    .risk.medium {{ background: #fff2cc; color: #805b00; }}
    .risk.low {{ background: #e8f2ff; color: #004b8d; }}
    .risk.none {{ background: #e8f7ee; color: #146c2e; }}
    .note {{ background: #fff; border-left: 5px solid #c0392b; padding: 14px 16px; border-radius: 10px; }}
    .footer {{ margin-top: 28px; color: #667085; font-size: 13px; }}
  </style>
</head>
<body>
<header>
  <h1>npm Supply Chain Risk Report</h1>
  <div>Generated at {html.escape(metadata.get('generated_at', ''))}</div>
  <div class="muted">Project: <code>{html.escape(metadata.get('project_dir', ''))}</code></div>
</header>
<main>
  <div class="note">
    <strong>Interpretation:</strong> This scanner does not prove a package is malicious. It separates
    <strong>known vulnerability evidence</strong> from <strong>supply-chain risk signals</strong> such as missing provenance,
    provenance regression, archived repositories, old packages, and install scripts.
  </div>

  <section class="grid">
    <div class="card"><div class="metric">{total}</div><div>Total packages</div></div>
    <div class="card"><div class="metric">{direct_count}</div><div>Direct dependencies</div></div>
    <div class="card"><div class="metric">{audit_vuln_packages}</div><div>npm audit vulnerable packages</div></div>
    <div class="card"><div class="metric">{osv_count}</div><div>Unique OSV vulnerabilities</div></div>
    <div class="card"><div class="metric">{cve_count}</div><div>Unique CVE ids</div></div>
    <div class="card"><div class="metric">{npq_issue_packages}</div><div>Packages with npq signals</div></div>
    <div class="card"><div class="metric">{high_count}</div><div>High risk rows</div></div>
    <div class="card"><div class="metric">{med_count}</div><div>Medium risk rows</div></div>
  </section>

  <h2>Package-level Report</h2>
  <table>
    <thead>
      <tr>
        <th>Package</th>
        <th>Type</th>
        <th>Risk</th>
        <th>npm audit</th>
        <th>OSV</th>
        <th>CVE</th>
        <th>npq check-only</th>
        <th>Raw log</th>
      </tr>
    </thead>
    <tbody>
      {''.join(table_rows)}
    </tbody>
  </table>

  <h2>CVE / NVD Enrichment</h2>
  <p class="muted">NVD enrichment is optional. Run with <code>--enable-nvd</code> to fetch CVSS, CWE, dates, and CVE descriptions.</p>
  <table>
    <thead>
      <tr><th>CVE</th><th>CVSS</th><th>CWE</th><th>Published</th><th>Description</th></tr>
    </thead>
    <tbody>
      {''.join(nvd_rows) if nvd_rows else '<tr><td colspan="5">No NVD data in this run.</td></tr>'}
    </tbody>
  </table>

  <h2>Run Metadata</h2>
  <div class="card">
    <p><strong>npq mode:</strong> <code>npq &lt;package&gt;@&lt;version&gt; --plain</code>. This is check-only mode; the scanner does not call <code>npq install</code>.</p>
    <p><strong>Lockfile generation:</strong> <code>npm install --package-lock-only --ignore-scripts --audit=false</code>. This may contact the npm registry for metadata, but should not create <code>node_modules</code> and should not run lifecycle scripts.</p>
    <p><strong>npm audit metadata:</strong> <code>{html.escape(json.dumps(npm_audit_meta, ensure_ascii=False)[:1000])}</code></p>
    <p><strong>npq scanned packages:</strong> {len(npq_results)}</p>
    <p><strong>NVD enabled:</strong> {html.escape(str(cve_enrichment.get('nvd_enabled', False)))}</p>
  </div>

  <div class="footer">Generated by npm-supply-chain-scanner.</div>
</main>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan npm dependencies for known vulnerabilities and supply-chain risk signals.")
    parser.add_argument("--project", required=True, help="Path to npm project containing package.json")
    parser.add_argument("--out", required=True, help="Output directory for report files")
    parser.add_argument(
        "--npq-scope",
        choices=["none", "direct", "all"],
        default="direct",
        help="Which packages to check with npq. Default: direct dependencies only.",
    )
    parser.add_argument("--max-npq-packages", type=int, default=50, help="Maximum packages to check with npq. Use 0 for unlimited.")
    parser.add_argument("--command-timeout", type=int, default=180, help="Timeout for npm commands in seconds.")
    parser.add_argument("--npq-timeout", type=int, default=60, help="Timeout for each npq check in seconds.")
    parser.add_argument("--enable-nvd", action="store_true", help="Fetch CVE details from NVD API. Slower, rate-limited.")
    parser.add_argument("--nvd-sleep-seconds", type=float, default=6.0, help="Sleep between NVD API calls.")
    parser.add_argument("--keep-workspace", action="store_true", help="Keep temporary workspace for debugging.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_dir = Path(args.project).resolve()
    out_dir = Path(args.out).resolve()
    raw_dir = out_dir / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "generated_at": now_iso(),
        "project_dir": str(project_dir),
        "out_dir": str(out_dir),
        "npq_scope": args.npq_scope,
        "enable_nvd": args.enable_nvd,
    }
    write_json(raw_dir / "run-metadata.json", metadata)

    workspace = prepare_workspace(project_dir, raw_dir)
    try:
        generate_lockfile(workspace, raw_dir, timeout=args.command_timeout)
        audit = run_npm_audit(workspace, raw_dir, timeout=args.command_timeout)
        packages = load_packages_from_lockfile(workspace)
        write_json(raw_dir / "packages.json", [asdict(p) for p in packages])

        osv_batch = query_osv_batch(packages, raw_dir=raw_dir)
        cve_enrichment = enrich_osv_results_with_cves(
            osv_batch,
            enable_nvd=args.enable_nvd,
            nvd_sleep_seconds=args.nvd_sleep_seconds,
        )
        write_json(raw_dir / "cve-enrichment.json", cve_enrichment)

        npq_results = run_npq_scan(
            packages,
            raw_dir=raw_dir,
            scope=args.npq_scope,
            max_packages=args.max_npq_packages,
            timeout=args.npq_timeout,
        )
        write_json(raw_dir / "npq-summary.json", {k: asdict(v) for k, v in npq_results.items()})

        audit_by_name = parse_audit_by_package(audit)
        osv_mapping = osv_by_package(packages, osv_batch, cve_enrichment)
        rows = build_report_rows(packages, audit_by_name, osv_mapping, npq_results)

        write_json(out_dir / "report.json", [asdict(r) for r in rows])
        write_csv(out_dir / "report.csv", rows)
        generate_html_report(
            out_dir / "report.html",
            rows=rows,
            packages=packages,
            audit=audit,
            cve_enrichment=cve_enrichment,
            npq_results=npq_results,
            metadata=metadata,
        )

        print(f"Scan finished: {out_dir / 'report.html'}")
        print(f"Packages: {len(packages)}")
        print(f"npq checked: {len(npq_results)}")
        print(f"CVE ids found: {len(cve_enrichment.get('cve_ids', []))}")
    finally:
        if args.keep_workspace:
            print(f"Temporary workspace kept: {workspace}")
        else:
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    main()
