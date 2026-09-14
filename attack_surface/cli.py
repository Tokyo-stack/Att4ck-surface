"""Command line interface for ATT4ck Surface (Click based).

Commands::

    att4ck scan <path>       run the static analysis scan (default command)
    att4ck surfaces          list the 40 attack surfaces
    att4ck rules             list the detection rules
    att4ck crawl <url>       optional live-target crawl + XSS probing
    att4ck version           print version information
"""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from attack_surface.banner import (
    PROJECT_TAGLINE,
    print_banner,
    print_environment,
    print_footer,
    print_startup,
)
from attack_surface.exporter import export_results
from attack_surface.models import ScanConfig, Severity, Status
from attack_surface.rules import (
    SURFACE_COUNT,
    SURFACES,
    load_rules,
    resolve_surface_keys,
    rules_by_surface,
    rules_for_surfaces,
)
from attack_surface.scanner import SurfaceScanner
from attack_surface.version import __version__

console = Console()
err_console = Console(stderr=True)

SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "green",
    "INFO": "dim",
}
SEVERITY_CHOICES = [s.value for s in Severity]
FORMAT_CHOICES = ["json", "csv", "sqlite", "html"]


def _configure_logging(verbose: bool, debug: bool) -> None:
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)


# --------------------------------------------------------------------------- #
# root group
# --------------------------------------------------------------------------- #


class _DefaultGroup(click.Group):
    """Group that runs the ``scan`` subcommand when the first token is a path."""

    def resolve_command(self, ctx: click.Context, args: list[str]):  # type: ignore[override]
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["scan", *args]
        return super().resolve_command(ctx, args)


@click.group(cls=_DefaultGroup, context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.version_option(__version__, "-V", "--version", prog_name="ATT4ck Surface")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """ATT4ck Surface - Attack Surface Mapping & Security Review Framework."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("-o", "--output-dir", type=click.Path(path_type=Path), default="output", show_default=True,
              help="Directory for the generated reports.")
@click.option("-s", "--surfaces", "surfaces_opt", multiple=True,
              help="Limit to specific surfaces (key, number 1-40, or package). Repeatable / comma-separated.")
@click.option("-x", "--exclude", multiple=True, help="Glob pattern to exclude. Repeatable.")
@click.option("-f", "--format", "formats", multiple=True, type=click.Choice(FORMAT_CHOICES),
              help="Output format(s). Default: all four.")
@click.option("--json", "json_only", is_flag=True, help="Shortcut for --format json.")
@click.option("--html", "html_only", is_flag=True, help="Shortcut for --format html.")
@click.option("-t", "--risk-threshold", type=click.Choice(SEVERITY_CHOICES, case_sensitive=False),
              default="INFO", show_default=True, help="Minimum severity to report.")
@click.option("-w", "--workers", type=int, default=0, help="Worker count (0 = auto).")
@click.option("--processes", is_flag=True, help="Use a process pool instead of threads (CPU-bound large trees).")
@click.option("--hide-mitigated", is_flag=True, help="Omit findings that appear to be mitigated.")
@click.option("--max-file-size", type=int, default=5 * 1024 * 1024, show_default=True,
              help="Skip files larger than this many bytes.")
@click.option("--respect-gitignore", is_flag=True, help="Also honour .gitignore patterns.")
@click.option("--no-hidden", is_flag=True, help="Skip hidden files and directories.")
@click.option("--fail-on", type=click.Choice(SEVERITY_CHOICES, case_sensitive=False), default=None,
              help="Exit non-zero if a finding at or above this severity is present.")
@click.option("--baseline", type=click.Path(path_type=Path), default=None,
              help="Suppress findings already recorded in this baseline file (report only new ones).")
@click.option("--update-baseline", type=click.Path(path_type=Path), default=None,
              help="Write current findings to this baseline file and exit 0.")
@click.option("--no-banner", is_flag=True, help="Do not print the ASCII banner.")
@click.option("--no-export", is_flag=True, help="Analyse only; do not write report files.")
@click.option("-q", "--quiet", is_flag=True, help="Only print the summary line.")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
@click.option("--debug", is_flag=True, help="Debug logging.")
def scan(
    path: Path,
    output_dir: Path,
    surfaces_opt: tuple[str, ...],
    exclude: tuple[str, ...],
    formats: tuple[str, ...],
    json_only: bool,
    html_only: bool,
    risk_threshold: str,
    workers: int,
    processes: bool,
    hide_mitigated: bool,
    max_file_size: int,
    respect_gitignore: bool,
    no_hidden: bool,
    fail_on: str | None,
    baseline: Path | None,
    update_baseline: Path | None,
    no_banner: bool,
    no_export: bool,
    quiet: bool,
    verbose: bool,
    debug: bool,
) -> None:
    """Scan PATH (a file or directory) for vulnerabilities across the 40 surfaces."""
    _configure_logging(verbose, debug)
    if not no_banner and not quiet:
        print_banner()
        print_startup()

    try:
        selected = resolve_surface_keys(surfaces_opt or None)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--surfaces") from exc

    config = ScanConfig(
        target=path,
        surfaces=tuple(surfaces_opt),
        exclude=tuple(exclude),
        workers=workers,
        max_file_size=max_file_size,
        respect_gitignore=respect_gitignore,
        include_hidden=not no_hidden,
        process_pool=processes,
        risk_threshold=Severity.parse(risk_threshold),
        hide_mitigated=hide_mitigated,
        verbose=verbose,
        debug=debug,
    )

    rules = rules_for_surfaces(selected)
    if not quiet:
        console.print(
            f"[bold]Scanning[/bold] [cyan]{path}[/cyan]  "
            f"[dim]{len(rules)} rules across {len(selected)}/{SURFACE_COUNT} surfaces[/dim]"
        )

    scanner, result = _run_scan(config, rules, quiet)

    if update_baseline is not None:
        from attack_surface.baseline import write_baseline

        dest = write_baseline(result.findings, update_baseline, target=str(path))
        console.print(f"[green]Baseline written:[/green] {dest} ({len(result.findings)} findings recorded)")
        return

    if baseline is not None:
        from attack_surface.baseline import apply_baseline, load_baseline
        from attack_surface.risk_engine import prioritize, summarize

        try:
            known = load_baseline(baseline)
        except ValueError as exc:
            raise click.BadParameter(str(exc), param_hint="--baseline") from exc
        new_findings, suppressed = apply_baseline(result.findings, known)
        result.findings = prioritize(new_findings)
        result.summary = summarize(result.findings, result.surfaces_run, rules, result.stats.files_scanned)
        if not quiet:
            console.print(
                f"[dim]Baseline {baseline}: suppressed {suppressed} known finding(s), "
                f"{len(result.findings)} new.[/dim]"
            )

    if not quiet:
        _render_summary(result)
        _render_top_findings(result)

    if not no_export and result.findings is not None:
        chosen = list(formats)
        if json_only:
            chosen.append("json")
        if html_only:
            chosen.append("html")
        chosen = chosen or FORMAT_CHOICES
        written = export_results(result, output_dir, formats=dict.fromkeys(chosen))
        if not quiet:
            console.print()
            console.print("[bold green]Reports written:[/bold green]")
            for fmt, dest in written.items():
                console.print(f"  [green]•[/green] {fmt.upper():6s} [cyan]{dest}[/cyan]")

    if quiet:
        s = result.summary
        console.print(
            f"{s['total_findings']} findings "
            f"(C:{s['by_severity']['CRITICAL']} H:{s['by_severity']['HIGH']} "
            f"M:{s['by_severity']['MEDIUM']} L:{s['by_severity']['LOW']} I:{s['by_severity']['INFO']})"
        )

    if not no_banner and not quiet:
        print_footer()

    if fail_on:
        from attack_surface.risk_engine import severity_at_or_above

        threshold = Severity.parse(fail_on)
        hits = severity_at_or_above(result.findings, threshold, include_mitigated=False)
        if hits:
            err_console.print(f"[red]FAIL:[/red] {hits} finding(s) at or above {threshold.value}.")
            sys.exit(2)


def _run_scan(config: ScanConfig, rules, quiet: bool):
    scanner = SurfaceScanner(config, rules=rules)
    if quiet:
        result = scanner.scan()
        return scanner, result

    columns = (
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )
    with Progress(*columns, console=console, transient=True) as progress:
        discover_task = progress.add_task("Discovering files...", total=None)
        entries = scanner.discover()
        progress.update(discover_task, total=1, completed=1)
        scan_task = progress.add_task("Analysing", total=len(entries))

        done = 0

        def on_file(entry, count):  # noqa: ANN001
            nonlocal done
            done += 1
            progress.update(scan_task, completed=done)

        scanner.on_file = on_file
        # Re-run analysis with progress; discover() already populated stats.
        result = _scan_with_progress(scanner, entries, progress, scan_task)
    return scanner, result


def _scan_with_progress(scanner: SurfaceScanner, entries, progress, task):  # noqa: ANN001
    """Drive SurfaceScanner while feeding the progress bar via on_file."""
    import datetime as _dt

    from attack_surface.models import ScanResult
    from attack_surface.risk_engine import dedupe, filter_by_threshold, prioritize, summarize

    started = _dt.datetime.now(_dt.UTC)
    t0 = time.perf_counter()
    workers = scanner.config.workers or max(2, min(32, __import__("os").cpu_count() or 4))
    raw = []
    if entries:
        if scanner.use_processes(len(entries)):
            raw = scanner._run_process_pool(entries, workers)
        else:
            raw = scanner._run_thread_pool(entries, workers)
    progress.update(task, completed=len(entries))
    findings = prioritize(filter_by_threshold(dedupe(raw), scanner.config.risk_threshold, scanner.config.hide_mitigated))
    scanner.findings = findings
    scanner.stats.duration_seconds = time.perf_counter() - t0
    finished = _dt.datetime.now(_dt.UTC)
    summary = summarize(findings, scanner.surfaces, scanner.rules, scanner.stats.files_scanned)
    return ScanResult(
        target=str(Path(scanner.config.target).resolve()),
        started_at=started.isoformat(timespec="seconds"),
        finished_at=finished.isoformat(timespec="seconds"),
        findings=findings,
        stats=scanner.stats,
        surfaces_run=scanner.surfaces,
        summary=summary,
    )


def _render_summary(result) -> None:  # noqa: ANN001
    s = result.summary
    stats = result.stats
    console.print()
    table = Table(title="Scan Summary", title_style="bold cyan", border_style="bright_black", expand=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    cov = s["coverage"]
    table.add_row("Files scanned", f"{stats.files_scanned:,}")
    table.add_row("Files skipped", f"{stats.files_skipped_binary + stats.files_skipped_size + stats.files_skipped_error:,} "
                                   f"[dim](binary {stats.files_skipped_binary}, size {stats.files_skipped_size}, error {stats.files_skipped_error})[/dim]")
    table.add_row("Rules executed", str(cov["rules_executed"]))
    table.add_row("Surface coverage", f"{cov['surfaces_scanned']}/{cov['surfaces_total']} ({cov['coverage_percent']}%)")
    table.add_row("Duration", f"{stats.duration_seconds:.2f}s")
    table.add_row("Total findings", f"[bold]{s['total_findings']}[/bold]")
    overall = s["overall_risk"]
    table.add_row("Overall risk", Text(overall, style=SEVERITY_STYLE.get(overall, "green")))
    console.print(table)

    sev_table = Table(show_header=True, border_style="bright_black")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev_table.add_column(sev, justify="center", style=SEVERITY_STYLE[sev])
    sev_table.add_row(*[str(s["by_severity"][k]) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")])
    console.print(sev_table)

    top = s.get("top_surfaces", [])
    if top:
        surf_table = Table(title="Top Risk Surfaces", title_style="bold cyan", border_style="bright_black")
        surf_table.add_column("#", justify="right", style="dim")
        surf_table.add_column("Surface")
        surf_table.add_column("Findings", justify="right")
        surf_table.add_column("Max", justify="center")
        surf_table.add_column("Risk", justify="right")
        for row in top[:8]:
            surf_table.add_row(
                str(row["number"]), row["name"], str(row["findings"]),
                Text(row["max_severity"] or "-", style=SEVERITY_STYLE.get(row["max_severity"] or "INFO", "dim")),
                f"{row['risk']:.1f}",
            )
        console.print(surf_table)


def _render_top_findings(result, limit: int = 15) -> None:  # noqa: ANN001
    findings = result.findings
    if not findings:
        console.print("\n[bold green]No findings above the configured threshold. ✅[/bold green]")
        return
    console.print()
    table = Table(title=f"Top {min(limit, len(findings))} Findings", title_style="bold cyan", border_style="bright_black")
    table.add_column("Sev", justify="center")
    table.add_column("Surface", style="cyan", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Location", style="dim", no_wrap=True)
    table.add_column("St", justify="center")
    for f in findings[:limit]:
        status = "[green]mit[/green]" if f.status is Status.POTENTIALLY_MITIGATED else "[red]vuln[/red]"
        table.add_row(
            Text(f.severity.value[:4], style=SEVERITY_STYLE[f.severity.value]),
            f.surface,
            f.name,
            f"{f.file}:{f.line}",
            status,
        )
    console.print(table)
    if len(findings) > limit:
        console.print(f"[dim]... and {len(findings) - limit} more (see the exported reports).[/dim]")


def _render_live_findings(findings) -> None:  # noqa: ANN001
    if not findings:
        console.print("[bold green]Live posture: no issues detected. ✅[/bold green]")
        return
    from attack_surface.risk_engine import prioritize

    ordered = prioritize(findings)
    table = Table(title="Live HTTP Posture Findings", title_style="bold cyan", border_style="bright_black")
    table.add_column("Sev", justify="center")
    table.add_column("Surface", style="cyan", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Location", style="dim", overflow="fold")
    for f in ordered:
        table.add_row(
            Text(f.severity.value[:4], style=SEVERITY_STYLE[f.severity.value]),
            f.surface,
            f.name,
            f.file,
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# surfaces / rules
# --------------------------------------------------------------------------- #


@cli.command(name="surfaces")
@click.option("--json", "as_json", is_flag=True, help="Emit the catalogue as JSON.")
def list_surfaces(as_json: bool) -> None:
    """List the 40 attack surfaces and their rule counts."""
    grouped = rules_by_surface()
    if as_json:
        import json as _json

        console.print_json(
            _json.dumps([
                {"number": s.number, "key": s.key, "name": s.name, "package": s.package,
                 "cwe": s.cwe, "severity": s.default_severity.value, "rules": len(grouped[s.key]),
                 "description": s.description}
                for s in SURFACES
            ])
        )
        return
    table = Table(title=f"ATT4ck Surface - {SURFACE_COUNT} Attack Surfaces", title_style="bold red", border_style="bright_black")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Key", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Pkg", style="magenta")
    table.add_column("Sev", justify="center")
    table.add_column("CWE", style="dim")
    table.add_column("R", justify="right")
    table.add_column("Description")
    for s in SURFACES:
        table.add_row(
            str(s.number), s.key, s.name, s.package,
            Text(s.default_severity.value[:4], style=SEVERITY_STYLE[s.default_severity.value]),
            s.cwe, str(len(grouped[s.key])), s.description,
        )
    console.print(table)


@cli.command(name="rules")
@click.option("-s", "--surface", "surface_filter", default=None, help="Show rules for one surface (key/number).")
@click.option("--json", "as_json", is_flag=True, help="Emit rules as JSON.")
def list_rules(surface_filter: str | None, as_json: bool) -> None:
    """List the detection rules."""
    keys = resolve_surface_keys([surface_filter] if surface_filter else None)
    rules = rules_for_surfaces(keys)
    if as_json:
        import json as _json

        console.print_json(
            _json.dumps([
                {"id": r.id, "surface": r.surface, "name": r.name, "severity": r.severity.value,
                 "cwe": r.cwe, "confidence": r.confidence, "description": r.description}
                for r in rules
            ])
        )
        return
    table = Table(title=f"{len(rules)} Detection Rules", title_style="bold red", border_style="bright_black")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Surface", style="magenta")
    table.add_column("Sev", justify="center")
    table.add_column("CWE", style="dim")
    table.add_column("Conf", justify="right")
    table.add_column("Name")
    for r in rules:
        table.add_row(
            r.id, r.surface,
            Text(r.severity.value[:4], style=SEVERITY_STYLE[r.severity.value]),
            r.cwe, f"{r.confidence}%", r.name,
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# crawl (optional live target)
# --------------------------------------------------------------------------- #


@cli.command()
@click.argument("url")
@click.option("--max-pages", type=int, default=50, show_default=True, help="Maximum pages to crawl.")
@click.option("--xss", is_flag=True, help="Probe discovered parameters for reflected XSS.")
@click.option("--audit/--no-audit", default=True, show_default=True,
              help="Analyse live HTTP security posture (headers, CORS, cookies, SRI).")
@click.option("-o", "--output-dir", type=click.Path(path_type=Path), default="output", show_default=True)
def crawl(url: str, max_pages: int, xss: bool, audit: bool, output_dir: Path) -> None:
    """Crawl a live URL, enumerate endpoints, audit HTTP posture and optionally probe for XSS.

    Requires the optional 'live' extra (requests, beautifulsoup4).
    """
    try:
        from attack_surface.web_crawler import WebCrawler
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise click.ClickException(
            "The crawl command needs the optional live extra: pip install 'att4ck-surface[live]'"
        ) from exc

    print_banner()
    console.print(f"[bold]Crawling[/bold] [cyan]{url}[/cyan] (max {max_pages} pages)")
    crawler = WebCrawler(url, max_pages=max_pages)
    crawl_result = crawler.crawl()

    pages = crawl_result.get("pages", [])
    endpoints = crawl_result.get("endpoints", [])
    js_files = crawl_result.get("js_files", [])
    console.print(
        f"[green]Discovered[/green] {len(pages)} pages, {len(endpoints)} endpoints, {len(js_files)} JS files."
    )

    from rich.table import Table

    if endpoints:
        table = Table(title="Endpoints (with parameters / forms)", show_lines=False)
        table.add_column("#", justify="right", style="dim")
        table.add_column("URL", overflow="fold")
        for i, ep in enumerate(endpoints, 1):
            table.add_row(str(i), ep)
        console.print(table)

    live_findings: list = []
    if audit:
        from attack_surface.live_analysis import analyze_records

        console.print("[bold]Auditing live HTTP security posture...[/bold]")
        live_findings = analyze_records(crawler.records, base_domain=crawler.base_domain)
        _render_live_findings(live_findings)

    xss_findings: list[dict] = []
    if xss:
        from attack_surface.xss_scanner import XSSScanner

        console.print("[bold]Probing for reflected XSS...[/bold]")
        scanner = XSSScanner()
        findings = scanner.scan_urls(endpoints)
        xss_findings = [f.to_dict() for f in findings]
        console.print(f"[red]{len(findings)}[/red] potential reflected-XSS finding(s).")
        for f in findings:
            console.print(
                f"  [red]![/red] param [bold]{f.parameter}[/bold] reflected raw at [cyan]{f.url}[/cyan]"
            )
            console.print(f"    payload: {f.payload}")
            console.print(f"    evidence: [dim]{f.evidence.strip()[:160]}[/dim]")

    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "crawl.json"
    payload = {
        "target": url,
        "max_pages": max_pages,
        "pages": pages,
        "endpoints": endpoints,
        "js_files": js_files,
        "live_findings": [f.to_dict() for f in live_findings],
        "xss_findings": xss_findings,
    }
    out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[green]Crawl results written:[/green] {out_file}")

    if live_findings:
        from datetime import UTC, datetime

        from attack_surface.exporter import export_results
        from attack_surface.models import ScanResult, ScanStats
        from attack_surface.risk_engine import prioritize, summarize

        ordered = prioritize(live_findings)
        surfaces_run = tuple(sorted({f.surface for f in ordered}))
        stats = ScanStats(files_scanned=len(pages), rules_loaded=len({f.rule_id for f in ordered}))
        now = datetime.now(UTC).isoformat(timespec="seconds")
        scan_result = ScanResult(
            target=url,
            started_at=now,
            finished_at=now,
            findings=ordered,
            stats=stats,
            surfaces_run=surfaces_run,
            summary=summarize(ordered, surfaces_run, (), len(pages)),
        )
        written = export_results(scan_result, output_dir, formats=dict.fromkeys(("json", "csv", "sqlite", "html")))
        for fmt, path in written.items():
            console.print(f"  • {fmt.upper():6} {path}")


# --------------------------------------------------------------------------- #
# version / info
# --------------------------------------------------------------------------- #


@cli.command()
def version() -> None:
    """Print version and environment information."""
    print_banner()
    print_environment()
    console.print(f"[dim]{PROJECT_TAGLINE}[/dim]")
    console.print(f"Detection rules loaded: [bold]{len(load_rules())}[/bold] across [bold]{SURFACE_COUNT}[/bold] surfaces.")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by the console script and ``python -m attack_surface``."""
    try:
        cli.main(args=list(argv) if argv is not None else None, standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    except click.Abort:
        err_console.print("[red]Aborted.[/red]")
        return 130
    except SystemExit as exc:  # fail-on / --version
        return int(exc.code or 0)
    except KeyboardInterrupt:  # pragma: no cover
        err_console.print("\n[red]Interrupted.[/red]")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
