from __future__ import annotations

import os
import re
import time
from typing import Any

import requests


OSV_API_BASE = "https://api.osv.dev/v1"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def extract_cve_ids_from_text(value: Any) -> list[str]:
    """Extract CVE identifiers from arbitrary JSON-like data."""
    text = value if isinstance(value, str) else repr(value)
    return sorted(set(CVE_RE.findall(text)))


def fetch_osv_vulnerability(osv_id: str, timeout: int = 30) -> dict[str, Any]:
    """Fetch a full OSV vulnerability object by OSV/GHSA/CVE id."""
    response = requests.get(f"{OSV_API_BASE}/vulns/{osv_id}", timeout=timeout)
    response.raise_for_status()
    return response.json()


def extract_cve_ids_from_osv_vulnerability(vuln: dict[str, Any]) -> list[str]:
    """Extract CVE ids from OSV fields such as id, aliases, related, details."""
    cve_ids: set[str] = set()

    for field in ["id", "aliases", "related", "details", "summary"]:
        value = vuln.get(field)
        if value is None:
            continue
        cve_ids.update(extract_cve_ids_from_text(value))

    return sorted(cve_ids)


def extract_osv_summary(vuln: dict[str, Any]) -> dict[str, Any]:
    """Keep only fields that are useful for reports."""
    affected_packages = []
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        ranges = affected.get("ranges", []) or []
        affected_packages.append(
            {
                "ecosystem": pkg.get("ecosystem"),
                "name": pkg.get("name"),
                "ranges": ranges,
            }
        )

    severity = vuln.get("severity") or []
    cvss = []
    for item in severity:
        if isinstance(item, dict):
            cvss.append(
                {
                    "type": item.get("type"),
                    "score": item.get("score"),
                }
            )

    return {
        "id": vuln.get("id"),
        "aliases": vuln.get("aliases", []) or [],
        "related": vuln.get("related", []) or [],
        "summary": vuln.get("summary", ""),
        "details": vuln.get("details", ""),
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
        "database_specific": vuln.get("database_specific", {}) or {},
        "cvss": cvss,
        "affected_packages": affected_packages,
        "cve_ids": extract_cve_ids_from_osv_vulnerability(vuln),
    }


def fetch_nvd_cve(cve_id: str, api_key: str | None = None, timeout: int = 30) -> dict[str, Any] | None:
    """Fetch CVE details from the NVD CVE API."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=headers,
        timeout=timeout,
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def extract_nvd_summary(nvd_result: dict[str, Any]) -> dict[str, Any]:
    """Normalize useful NVD fields into a small object."""
    vulnerabilities = nvd_result.get("vulnerabilities", []) or []
    if not vulnerabilities:
        return {}

    cve = vulnerabilities[0].get("cve", {}) or {}
    descriptions = cve.get("descriptions", []) or []
    english_description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            english_description = desc.get("value", "")
            break

    metrics = cve.get("metrics", {}) or {}
    cvss_score = None
    cvss_severity = None
    cvss_vector = None

    for metric_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_key, []) or []
        if metric_list:
            first = metric_list[0]
            cvss_data = first.get("cvssData", {}) or {}
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = first.get("baseSeverity") or cvss_data.get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break

    cwe_ids = []
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            if desc.get("lang") == "en" and desc.get("value"):
                cwe_ids.append(desc["value"])

    references = []
    for ref in cve.get("references", {}).get("referenceData", []) or []:
        if ref.get("url"):
            references.append(ref["url"])

    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": english_description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "cwe_ids": sorted(set(cwe_ids)),
        "source_identifier": cve.get("sourceIdentifier"),
        "references": references[:10],
    }


def enrich_osv_results_with_cves(
    osv_batch_result: dict[str, Any],
    enable_nvd: bool = False,
    nvd_sleep_seconds: float = 6.0,
) -> dict[str, Any]:
    """
    Enrich OSV batch results with full OSV objects and optional NVD CVE metadata.

    This is API enrichment, not HTML scraping.
    - OSV gives package/version vulnerability matches.
    - Full OSV objects often contain aliases such as CVE-* and GHSA-*.
    - NVD can optionally add CVSS, CWE, publish dates, and descriptions.
    """
    all_osv_ids: set[str] = set()
    for result in osv_batch_result.get("results", []) or []:
        for vuln in result.get("vulns", []) or []:
            if vuln.get("id"):
                all_osv_ids.add(vuln["id"])

    full_osv_by_id: dict[str, Any] = {}
    cve_ids: set[str] = set()

    for osv_id in sorted(all_osv_ids):
        try:
            full_vuln = fetch_osv_vulnerability(osv_id)
            summary = extract_osv_summary(full_vuln)
            full_osv_by_id[osv_id] = summary
            cve_ids.update(summary.get("cve_ids", []))
        except Exception as exc:  # keep scanning even if one lookup fails
            full_osv_by_id[osv_id] = {"id": osv_id, "error": str(exc)}

    nvd_by_cve: dict[str, Any] = {}
    if enable_nvd:
        api_key = os.getenv("NVD_API_KEY")
        for cve_id in sorted(cve_ids):
            try:
                raw = fetch_nvd_cve(cve_id, api_key=api_key)
                if raw:
                    nvd_by_cve[cve_id] = extract_nvd_summary(raw)
                else:
                    nvd_by_cve[cve_id] = {"cve_id": cve_id, "error": "not found"}
            except Exception as exc:
                nvd_by_cve[cve_id] = {"cve_id": cve_id, "error": str(exc)}

            # NVD public API is rate-limited. Keep this conservative by default.
            time.sleep(max(0.0, nvd_sleep_seconds))

    return {
        "osv_ids": sorted(all_osv_ids),
        "cve_ids": sorted(cve_ids),
        "osv_by_id": full_osv_by_id,
        "nvd_by_cve": nvd_by_cve,
        "nvd_enabled": enable_nvd,
    }
