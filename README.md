Maintained by: Sujot Sasane
GitHub: https://github.com/sujotsasane

# SecFlow (Lite) — Developer-First Security Scanner Orchestrator (Python)

SecFlow is a lightweight CLI that **orchestrates multiple security scanners** and **normalizes results** into a single output,
so developers can get security feedback **as code** (locally + in CI), not as tickets.

This is intentionally designed as a **Meesho-style Product Security tooling project**:
- SAST / Secrets / Dependency / Container scan **orchestration**
- One-command local runs for developers
- CI mode (GitHub Actions) to enforce **security gates**
- Noise reduction via baseline/allowlist

## Why this helps for Product Security roles
- Shows builder mindset (security as an engineering problem)
- Demonstrates DevSecOps & CI integration
- Shows practical understanding of SAST/DAST/SCA + secrets scanning workflows

## Features (current)
- `secflow scan` runs enabled tools (if installed) and collects outputs
- Normalizes findings into `secflow-report.json`
- Optional `--fail-on` to make CI fail on HIGH/CRITICAL findings
- `baseline` support to suppress known findings (reduces noise)

## Tools supported (optional, detected if installed)
- Semgrep (SAST): `semgrep --json`
- Trivy (SCA/Container): `trivy fs --format json` and/or `trivy image --format json`
- Gitleaks (secrets): `gitleaks detect --report-format json`
- Nuclei (DAST-ish for templates): `nuclei -jsonl` (optional)

> Note: This repo **does not bundle** scanners; it calls them if they are available.

## Quick Start
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -r requirements.txt

# Run a scan on current folder
python -m secflow scan --path . --out secflow-report.json

# CI-like gate
python -m secflow scan --path . --fail-on high
```

## GitHub Actions
A sample workflow is provided in `.github/workflows/secflow.yml`.

## Roadmap ideas (great interview talking points)
- SARIF output for GitHub Security tab
- Finding correlation (dedupe across tools)
- Fast "diff scan" for PRs only
- Secret verification heuristics (reduce false positives)
- Dashboard exporter (e.g., push to ELK/OpenSearch)

