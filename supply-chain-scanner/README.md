# npm Supply Chain Risk Scanner

A lightweight Docker-based scanner for npm projects.

It separates two different kinds of risk:

1. **Known vulnerabilities**
   - `npm audit --json`
   - OSV API query by package/version
   - CVE enrichment from OSV aliases
   - Optional NVD API enrichment for CVSS/CWE/descriptions

2. **Potential supply-chain risk signals**
   - `npq` check-only scan
   - Missing / unverifiable provenance
   - Provenance regression
   - Archived repository
   - Old package
   - Install scripts
   - Package health warnings

This project does **not** prove a package is malicious. It produces a risk report for human review.

---

## Important safety design

The scanner avoids installing scanned packages.

### npm lockfile generation

The scanner runs this inside a temporary workspace:

```bash
npm install --package-lock-only --ignore-scripts --fund=false --audit=false
```

Meaning:

- It may contact the npm registry for metadata.
- It should not create `node_modules`.
- It should not execute lifecycle scripts such as `preinstall`, `install`, or `postinstall`.
- It writes the generated `package-lock.json` only inside a temporary folder, not your mounted project.

### npq check-only mode

The scanner runs:

```bash
npq <package>@<version> --plain
```

It does **not** run:

```bash
npq install <package>
```

So `npq` is used as a scanner, not as an installer.

---

## Project structure

```text
npm-supply-chain-scanner/
├── Dockerfile
├── README.md
├── requirements.txt
├── scanner.py
├── cve_enricher.py
├── .gitignore
└── examples/
    └── demo-project/
        └── package.json
```

---

## Build Docker image

```bash
docker build -t npm-supply-chain-scanner .
```

---

## Run the built-in demo

Linux / macOS / Git Bash:

```bash
docker run --rm \
  -v "$PWD/examples/demo-project:/project:ro" \
  -v "$PWD/results:/results" \
  npm-supply-chain-scanner \
  --project /project \
  --out /results \
  --npq-scope direct
```

Windows PowerShell:

```powershell
docker run --rm `
  -v "${PWD}/examples/demo-project:/project:ro" `
  -v "${PWD}/results:/results" `
  npm-supply-chain-scanner `
  --project /project `
  --out /results `
  --npq-scope direct
```

Open the report:

```text
results/report.html
```

---

## Scan your own npm project

Suppose your npm project is here:

```text
C:\Users\User\Desktop\some-npm-project
```

PowerShell:

```powershell
docker run --rm `
  -v "C:/Users/User/Desktop/some-npm-project:/project:ro" `
  -v "${PWD}/results:/results" `
  npm-supply-chain-scanner `
  --project /project `
  --out /results `
  --npq-scope direct
```

---

## Output files

```text
results/
├── report.html              # Main human-readable report
├── report.csv               # Spreadsheet-friendly result
├── report.json              # Structured package-level result
└── raw/
    ├── npm-audit.json
    ├── osv-querybatch-combined.json
    ├── cve-enrichment.json
    ├── npq-summary.json
    └── npq/
        └── <package-version>.txt
```

---

## CLI options

```bash
python3 scanner.py \
  --project /project \
  --out /results \
  --npq-scope direct \
  --max-npq-packages 50
```

### `--npq-scope`

```text
none    Do not run npq
        Only run npm audit + OSV/CVE logic

direct  Run npq only on direct dependencies
        Recommended default

all     Run npq on all packages from package-lock.json
        Slower; may produce many logs
```

### `--enable-nvd`

By default, the scanner extracts CVE ids from OSV results.

If you want CVSS score, CWE, publish date, and CVE descriptions from NVD:

```bash
docker run --rm \
  -v "$PWD/examples/demo-project:/project:ro" \
  -v "$PWD/results:/results" \
  npm-supply-chain-scanner \
  --project /project \
  --out /results \
  --npq-scope direct \
  --enable-nvd
```

NVD is rate-limited. The scanner sleeps between NVD API calls. You can set:

```bash
--nvd-sleep-seconds 6
```

If you have an NVD API key:

```bash
docker run --rm \
  -e NVD_API_KEY="your_api_key" \
  -v "$PWD/examples/demo-project:/project:ro" \
  -v "$PWD/results:/results" \
  npm-supply-chain-scanner \
  --project /project \
  --out /results \
  --enable-nvd
```

---

## Suggested research framing

A safer title than "Detecting malicious packages" is:

> Detecting Known Vulnerabilities and Supply Chain Risk Signals in npm Dependencies

Because this scanner reports:

```text
Known vulnerability evidence:
- npm audit
- OSV vulnerability ids
- CVE ids
- Optional NVD CVSS/CWE metadata

Potential supply-chain risk signals:
- npq provenance warnings
- provenance regression
- archived repository
- old package
- install script warning
- package health warning
```

A clean explanation for presentation:

> CVE means the disease has already been recorded in a database.  
> npq risk signals are more like abnormal health-check numbers.  
> They are not proof of malware, but they are reasons to stop and review before installing.

---

## Limitations

- It does not prove whether a package is malicious.
- It depends on public vulnerability databases and registry metadata.
- NVD enrichment can be slow because of rate limits.
- `npq` output is text-based, so issue classification is heuristic.
- Lockfile generation may contact npm registry for metadata, but the scanner avoids installing package contents and avoids lifecycle scripts.
