from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests

from models import OSV_BATCH_URL, PROJECT_DIR, RAW_DIR, PackageInfo


# ── Helpers ───────────────────────────────────────────────────────────────────

def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_command(
    args: list[str],
    cwd: Path | None,
    output_path: Path,
    timeout: int = 120,
) -> tuple[int, str]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CI": "true", "NPM_CONFIG_FUND": "false"}

    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            env=env,
        )
        output = result.stdout or ""
        output_path.write_text(output, encoding="utf-8", errors="replace")
        return result.returncode, output

    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout if isinstance(exc.stdout, str) else "") + "\n[TIMEOUT]\n"
        output_path.write_text(output, encoding="utf-8", errors="replace")
        return 124, output


# ── Lockfile ──────────────────────────────────────────────────────────────────

def load_packages_from_lockfile() -> list[PackageInfo]:
    lockfile = read_json(PROJECT_DIR / "package-lock.json")
    packages: list[PackageInfo] = []

    for lock_path, meta in (lockfile.get("packages") or {}).items():
        if not lock_path.startswith("node_modules/"):
            continue
        package = lock_path.split("node_modules/")[-1]
        version = str(meta.get("version") or "")
        if package:
            packages.append(PackageInfo(package=package, version=version))

    return sorted(packages, key=lambda p: p.package.lower())


# ── npm audit ─────────────────────────────────────────────────────────────────

def run_npm_audit() -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="npm-audit-") as tmp:
        temp_dir = Path(tmp)
        for filename in ("package.json", "package-lock.json"):
            shutil.copy2(PROJECT_DIR / filename, temp_dir / filename)

        code, output = run_command(
            ["npm", "audit", "--json", "--package-lock-only"],
            cwd=temp_dir,
            output_path=RAW_DIR / "npm-audit.json",
            timeout=120,
        )

    try:
        audit = json.loads(output)
    except json.JSONDecodeError:
        return {"__tool_error__": f"tool error: npm audit did not return JSON, exit code={code}"}

    results: dict[str, str] = {}
    for name, item in (audit.get("vulnerabilities") or {}).items():
        if isinstance(item, dict):
            severity = item.get("severity", "unknown")
            via_count = len(item.get("via") or [])
            results[name] = f"flagged: {via_count} issue(s), severity={severity}"

    return results


# ── OSV ───────────────────────────────────────────────────────────────────────

def run_osv(packages: list[PackageInfo]) -> dict[str, str]:
    versioned = [p for p in packages if p.version]
    results: dict[str, str] = {
        p.package: "not checked: missing version" for p in packages if not p.version
    }

    if not versioned:
        return results

    queries = [
        {"version": p.version, "package": {"name": p.package, "ecosystem": "npm"}}
        for p in versioned
    ]

    try:
        response = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=60)
        response.raise_for_status()
        data = response.json()
        write_json(RAW_DIR / "osv-querybatch.json", data)
    except Exception as exc:
        return {p.package: f"tool error: {exc}" for p in packages}

    for package, query_result in zip(versioned, data.get("results") or []):
        vulns = query_result.get("vulns", []) if isinstance(query_result, dict) else []
        vuln_ids = [v["id"] for v in vulns if isinstance(v, dict) and v.get("id")]
        results[package.package] = (
            "flagged: " + ", ".join(vuln_ids[:8]) if vuln_ids else "not flagged"
        )

    return results


# ── npq ───────────────────────────────────────────────────────────────────────

_NPQ_SIGNAL_WORDS = {
    "error", "warning", "vulnerability", "cve",
    "supply chain", "provenance", "package health",
}


def run_npq(packages: list[PackageInfo]) -> dict[str, str]:
    if shutil.which("npq") is None:
        return {"__tool_error__": "tool error: npq is not installed"}

    results: dict[str, str] = {}

    for package in packages:
        if not package.version:
            results[package.package] = "not checked: missing version"
            continue

        spec = f"{package.package}@{package.version}"
        log_name = package.package.replace("/", "_").replace("@", "")
        log_path = RAW_DIR / "npq" / f"{log_name}.txt"

        code, output = run_command(
            ["npq", spec, "--plain"], cwd=None, output_path=log_path, timeout=60
        )

        if code == 0:
            results[package.package] = "not flagged"
            continue

        lower = output.lower()
        if "not found" in lower or "404" in lower:
            results[package.package] = "not checked: package not found in npm registry"
            continue

        signal_lines = [
            line.strip()
            for line in output.splitlines()
            if line.strip() and any(w in line.lower() for w in _NPQ_SIGNAL_WORDS)
        ]
        results[package.package] = (
            "flagged: " + " | ".join(signal_lines[:3])
            if signal_lines
            else f"flagged: exit code {code}"
        )

    return results
