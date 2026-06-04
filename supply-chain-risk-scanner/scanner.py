from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import requests

from models import (
    OSV_BATCH_URL,
    PROJECT_DIR,
    RAW_DIR,
    PackageInfo,
)


# ── 取得套件「源碼目錄」(GuardDog 要掃的對象)──────────────────────────────
#
# 關鍵修正:不要掃 node_modules(npm install 後的產物,常常少檔案),
# 而是把套件源碼抓到本地暫存目錄再掃:
#   - github: 來源  → git clone
#   - registry 來源 → npm pack 後解開 tarball
#   - local/file:   → 直接用原目錄

def _github_parts(resolved: str):
    m = re.search(
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/#]+?)(?:\.git)?(?:#(?P<ref>.+))?$",
        resolved,
    )
    if not m:
        return None
    return m.group("owner"), m.group("repo"), m.group("ref") or "HEAD"


def fetch_source_dir(package: PackageInfo, dest_root: Path) -> Path | None:
    """把套件源碼抓到 dest_root 下,回傳含 package.json 的目錄。失敗回 None。"""
    resolved = package.resolved or ""
    low = resolved.lower()
    dest = dest_root / package.package.replace("/", "__").replace("@", "")
    dest.mkdir(parents=True, exist_ok=True)

    # 1) local / file:
    if low.startswith("file:"):
        src = (PROJECT_DIR / resolved.removeprefix("file:")).resolve()
        return src if (src / "package.json").exists() else None

    # 2) github:
    if "github" in low:
        parts = _github_parts(resolved)
        if parts:
            owner, repo, ref = parts
            url = f"https://github.com/{owner}/{repo}.git"
            for args in (["--depth", "1", "--branch", ref, url, str(dest)],
                         ["--depth", "1", url, str(dest)]):
                subprocess.run(["git", "clone", *args],
                               capture_output=True, text=True, timeout=120)
                if (dest / "package.json").exists():
                    return dest
        return None

    # 3) npm registry → npm pack
    spec = f"{package.package}@{package.version}" if package.version else package.package
    out = subprocess.run(["npm", "pack", spec, "--silent"],
                         cwd=dest, capture_output=True, text=True, timeout=120)
    tgz = (out.stdout or "").strip().splitlines()
    if tgz:
        subprocess.run(["tar", "-xzf", tgz[-1], "--strip-components=1"],
                       cwd=dest, capture_output=True, text=True)
    return dest if (dest / "package.json").exists() else None


# ── GuardDog 靜態分析(現成工具,核心偵測欄位)──────────────────────────────

def _parse_guarddog_output(raw: str, stderr: str) -> str:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        if "not found" in stderr.lower() or "404" in stderr.lower():
            return "not checked: package not found"
        return "tool error: invalid JSON output"

    if data.get("issues", 0) == 0:
        return "not flagged"

    hits: list[str] = []
    for _pkg, findings in (data.get("results") or {}).items():
        if isinstance(findings, dict):
            for rule_id, locs in findings.items():
                if locs:
                    hits.append(f"{rule_id}({len(locs) if isinstance(locs, list) else 1})")
    return "flagged: " + ", ".join(hits[:5]) if hits else f"flagged: {data['issues']} issue(s)"


def run_guarddog(packages: list[PackageInfo]) -> dict[str, str]:
    if shutil.which("guarddog") is None:
        return {"__tool_error__": "tool error: guarddog is not installed"}

    results: dict[str, str] = {}
    raw_dir = RAW_DIR / "guarddog"
    raw_dir.mkdir(parents=True, exist_ok=True)
    src_root = Path(tempfile.mkdtemp(prefix="guarddog-src-"))

    try:
        for pkg in packages:
            safe = pkg.package.replace("/", "__").replace("@", "")
            log_path = raw_dir / f"{safe}.json"

            src_dir = fetch_source_dir(pkg, src_root)
            if src_dir is None:
                results[pkg.package] = "not checked: could not fetch package source"
                continue

            cmd = ["guarddog", "npm", "scan", str(src_dir), "--output-format", "json"]
            try:
                r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, timeout=180)
                raw = r.stdout or ""
                log_path.write_text(raw, encoding="utf-8", errors="replace")
                results[pkg.package] = _parse_guarddog_output(raw, r.stderr or "")
            except subprocess.TimeoutExpired:
                results[pkg.package] = "tool error: guarddog timeout"
            except Exception as exc:
                results[pkg.package] = f"tool error: {exc}"
    finally:
        shutil.rmtree(src_root, ignore_errors=True)

    return results


# ── 基礎工具 ──────────────────────────────────────────────────────────────────

def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run_command(args, cwd, output_path: Path, timeout: int = 120):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["CI"] = "true"
    env["NPM_CONFIG_FUND"] = "false"
    try:
        c = subprocess.run(args, cwd=str(cwd) if cwd else None,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout, env=env)
        out = c.stdout or ""
        output_path.write_text(out, encoding="utf-8", errors="replace")
        return c.returncode, out
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout if isinstance(exc.stdout, str) else "") + "\n[TIMEOUT]\n"
        output_path.write_text(out, encoding="utf-8", errors="replace")
        return 124, out


# ── Lockfile 解析 ─────────────────────────────────────────────────────────────

def load_packages_from_lockfile() -> list[PackageInfo]:
    lockfile = read_json(PROJECT_DIR / "package-lock.json")
    packages: list[PackageInfo] = []
    for lock_path, meta in (lockfile.get("packages") or {}).items():
        if not lock_path.startswith("node_modules/"):
            continue
        name = lock_path.split("node_modules/")[-1]
        if name:
            packages.append(PackageInfo(
                package=name,
                version=str(meta.get("version") or ""),
                resolved=str(meta.get("resolved") or ""),
            ))
    return sorted(packages, key=lambda p: p.package.lower())


# ── npm audit ─────────────────────────────────────────────────────────────────

def run_npm_audit() -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="npm-audit-") as tmp:
        tdir = Path(tmp)
        shutil.copy2(PROJECT_DIR / "package.json", tdir / "package.json")
        shutil.copy2(PROJECT_DIR / "package-lock.json", tdir / "package-lock.json")
        code, output = run_command(
            ["npm", "audit", "--json", "--package-lock-only"],
            cwd=tdir, output_path=RAW_DIR / "npm-audit.json", timeout=120,
        )
    try:
        audit = json.loads(output)
    except json.JSONDecodeError:
        return {"__tool_error__": f"tool error: npm audit non-JSON, exit={code}"}
    results: dict[str, str] = {}
    for name, item in (audit.get("vulnerabilities") or {}).items():
        if isinstance(item, dict):
            sev = item.get("severity", "unknown")
            via = len(item.get("via") or [])
            results[name] = f"flagged: {via} issue(s), severity={sev}"
    return results


# ── OSV ───────────────────────────────────────────────────────────────────────

def run_osv(packages: list[PackageInfo]) -> dict[str, str]:
    versioned = [p for p in packages if p.version]
    results = {p.package: "not checked: missing version" for p in packages if not p.version}
    if not versioned:
        return results
    queries = [{"version": p.version, "package": {"name": p.package, "ecosystem": "npm"}}
               for p in versioned]
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        write_json(RAW_DIR / "osv-querybatch.json", data)
    except Exception as exc:
        return {p.package: f"tool error: {exc}" for p in packages}
    for pkg, qr in zip(versioned, data.get("results") or []):
        vulns = qr.get("vulns", []) if isinstance(qr, dict) else []
        ids = [v["id"] for v in vulns if isinstance(v, dict) and v.get("id")]
        results[pkg.package] = "flagged: " + ", ".join(ids[:8]) if ids else "not flagged"
    return results


# ── npq ───────────────────────────────────────────────────────────────────────

_NPQ_SIGNALS = {"error", "warning", "vulnerability", "cve",
                "supply chain", "provenance", "package health"}


def run_npq(packages: list[PackageInfo]) -> dict[str, str]:
    if shutil.which("npq") is None:
        return {"__tool_error__": "tool error: npq is not installed"}
    results: dict[str, str] = {}
    for pkg in packages:
        if not pkg.version:
            results[pkg.package] = "not checked: missing version"
            continue
        spec = f"{pkg.package}@{pkg.version}"
        log_name = pkg.package.replace("/", "_").replace("@", "")
        code, output = run_command(["npq", spec, "--plain"], None,
                                   RAW_DIR / "npq" / f"{log_name}.txt", timeout=60)
        low = output.lower()
        if code == 0:
            results[pkg.package] = "not flagged"
        elif "not found" in low or "404" in low:
            results[pkg.package] = "not checked: package not found"
        else:
            lines = [l.strip() for l in output.splitlines()
                     if l.strip() and any(w in l.lower() for w in _NPQ_SIGNALS)]
            results[pkg.package] = ("flagged: " + " | ".join(lines[:3])
                                    if lines else f"flagged: exit code {code}")
    return results
