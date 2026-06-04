from dataclasses import dataclass
from pathlib import Path

PROJECT_DIR = Path("/project") if Path("/project/package.json").exists() else Path("examples/demo-project")
RESULTS_DIR = Path("/results") if Path("/results").exists() else Path("results")
RAW_DIR = RESULTS_DIR / "raw"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


@dataclass
class PackageInfo:
    package: str
    version: str
    resolved: str


@dataclass
class ReportRow:
    package: str
    version: str
    npm_audit_result: str
    osv_result: str
    npq_result: str
    guarddog_result: str   # GuardDog Semgrep 靜態行為分析(核心偵測欄位)
