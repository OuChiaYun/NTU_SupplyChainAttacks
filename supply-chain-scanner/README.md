# npm Supply Chain Risk Scanner

A Docker-based scanner for npm projects.

It checks:

- known vulnerabilities: `npm audit`, OSV, CVE
- supply-chain risk signals: `npq`
- output report: `results/report.html`

The scanner does not install scanned packages.

---

## Test Repo

Example repo:

```text
https://github.com/justadudewhohacks/face-recognition.js
```

---

## How to Check a Repo

Find the repo's `package.json`, then copy it into:

```text
examples/demo-project/package.json
```

In other words, replace the demo project's `package.json` with the one you want to scan.

---

## Usage

In Git Bash / WSL / Linux:

```bash
chmod +x run.sh clean.sh
```

Run scanner:

```bash
./run.sh
```

Clean generated results:

```bash
./clean.sh
```

---

## Output

After running, open:

```text
results/report.html
```

Other generated files:

```text
results/report.csv
results/report.json
results/raw/
```