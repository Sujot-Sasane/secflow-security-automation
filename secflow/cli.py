import json
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table

from .models import Report, Finding
from .utils import which, run_cmd
from .parsers import parse_semgrep_json, parse_gitleaks_json, parse_trivy_fs_json

app = typer.Typer(add_completion=False, help="SecFlow: developer-first security scanner orchestrator")
console = Console()

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("suppress", []))
    except Exception:
        return set()

def save_baseline(path: Path, suppress: List[str]) -> None:
    path.write_text(json.dumps({"suppress": sorted(set(suppress))}, indent=2), encoding="utf-8")

def summarize(findings: List[Finding]) -> dict:
    s = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        s[f.severity] = s.get(f.severity, 0) + 1
    return s

def should_fail(findings: List[Finding], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = SEV_ORDER.get(fail_on.lower(), 3)
    return any(SEV_ORDER.get(f.severity, 0) >= threshold for f in findings)

@app.command()
def scan(
    path: str = typer.Option(".", "--path", help="Target path to scan"),
    out: str = typer.Option("secflow-report.json", "--out", help="Output report path (JSON)"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Fail if any finding >= severity (low/medium/high/critical)"),
    baseline: str = typer.Option(".secflow-baseline.json", "--baseline", help="Baseline suppress file"),
    update_baseline: bool = typer.Option(False, "--update-baseline", help="Write current findings into baseline suppress list"),
):
    """Run enabled scanners (if installed) and write a normalized report."""
    target = str(Path(path).resolve())
    baseline_path = Path(baseline)
    suppressed = load_baseline(baseline_path)

    findings: List[Finding] = []

    # Semgrep (SAST)
    if which("semgrep"):
        code, out_s, err = run_cmd(["semgrep", "--json", "--quiet", path])
        if out_s.strip():
            try:
                findings.extend(parse_semgrep_json(out_s))
            except Exception as e:
                console.print(f"[yellow]Semgrep parse error:[/] {e}")
    else:
        console.print("[dim]semgrep not found; skipping SAST[/]")

    # Gitleaks (secrets)
    if which("gitleaks"):
        code, out_s, err = run_cmd(["gitleaks", "detect", "--source", path, "--report-format", "json", "--no-git"])
        if out_s.strip():
            try:
                findings.extend(parse_gitleaks_json(out_s))
            except Exception as e:
                console.print(f"[yellow]Gitleaks parse error:[/] {e}")
    else:
        console.print("[dim]gitleaks not found; skipping secrets scan[/]")

    # Trivy (SCA-ish)
    if which("trivy"):
        code, out_s, err = run_cmd(["trivy", "fs", "--format", "json", "--quiet", path])
        if out_s.strip():
            try:
                findings.extend(parse_trivy_fs_json(out_s))
            except Exception as e:
                console.print(f"[yellow]Trivy parse error:[/] {e}")
    else:
        console.print("[dim]trivy not found; skipping dependency scan[/]")

    # Suppress baseline
    kept: List[Finding] = []
    suppressed_ids: List[str] = []
    for f in findings:
        sig = f"{f.tool}:{f.rule_id}:{f.file}:{f.line}"
        if sig in suppressed:
            suppressed_ids.append(sig)
            continue
        kept.append(f)

    if update_baseline:
        # Write all current findings (including suppressed) into baseline for future noise reduction
        all_sigs = sorted({f"{f.tool}:{f.rule_id}:{f.file}:{f.line}" for f in findings})
        save_baseline(baseline_path, all_sigs)
        console.print(f"[green]Baseline updated:[/] {baseline_path} ({len(all_sigs)} signatures)")

    rep = Report(
        generated_at=__import__("datetime").datetime.utcnow().isoformat() + "Z",
        target=target,
        findings=kept,
        summary=summarize(kept),
    )

    Path(out).write_text(rep.model_dump_json(indent=2), encoding="utf-8")

    # Pretty output
    table = Table(title="SecFlow Summary")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ["critical", "high", "medium", "low", "info"]:
        table.add_row(sev, str(rep.summary.get(sev, 0)))
    console.print(table)
    console.print(f"[bold]Report:[/] {out}  |  [dim]Suppressed:[/] {len(suppressed_ids)}")

    if should_fail(kept, fail_on):
        raise typer.Exit(code=2)

if __name__ == "__main__":
    app()
