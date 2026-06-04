
# NTU_SupplyChainAttacks

This repository is for studying **software supply chain attacks** and building a small demo tool to analyze npm package risks.

## What is a Supply Chain Attack?

A software supply chain attack targets the software development or distribution process instead of directly attacking the application code.

For example, an attacker may compromise:

- a third-party package
- a package maintainer account
- a build / CI pipeline
- a dependency update process
- a package registry release

Then, developers may unknowingly install or use malicious code through normal commands such as:

```bash
npm install
pip install
mvn install
````

In short:

> A supply chain attack abuses the trust between developers, dependencies, build systems, and package registries.

---

## Repository Structure

```text
NTU_SupplyChainAttacks/
├── supply-chain-scanner/
└── survey_log/
```

## `supply-chain-scanner`

This folder contains a Docker-based npm supply chain risk scanner.

It is used to check npm projects for:

* known vulnerabilities from `npm audit`, OSV, and CVE records
* potential supply-chain risk signals from `npq`
* package-level risk summary reports

The scanner generates an HTML report:

```text
results/report.html
```

The scanner is designed for inspection and reporting. It does not prove that a package is malicious.

## `survey_log`

This folder stores survey notes, discussion records, experiment logs, and research observations related to software supply chain attacks.

It is used to keep track of our findings during the project.