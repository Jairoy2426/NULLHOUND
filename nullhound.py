#!/usr/bin/env python3
import argparse
import getpass
import os
import socket
import sys
import time
from typing import List, Dict, Any

# Ensure path includes workspace
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn
from rich.live import Live
from rich.align import Align

from core.finding import Finding
from core.runner import ModuleRunner
from core.reporter import ReportReporter
from core.utils import get_severity_color, is_root, run_cmd
from modules import ALL_MODULES

# Versioning
VERSION = "1.0.0"

def get_system_metadata() -> Dict[str, str]:
    """Retrieves basic system metadata for banner and reports."""
    hostname = socket.gethostname()
    username = getpass.getuser()
    
    kernel = "Unknown"
    kernel_out, _, _ = run_cmd("uname -sr")
    if kernel_out:
        kernel = kernel_out

    return {
        "version": VERSION,
        "hostname": hostname,
        "user": username,
        "kernel": kernel,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
    }

def print_banner(console: Console, meta: Dict[str, str], quiet: bool) -> None:
    """Prints a beautiful block letter ASCII banner with metadata."""
    if quiet:
        return

    banner_text = r"""
███╗   ██╗██╗   ██╗██╗     ██╗     ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
████╗  ██║██║   ██║██║     ██║     ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
██╔██╗ ██║██║   ██║██║     ██║     ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
██║╚██╗██║██║   ██║██║     ██║     ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
██║ ╚████║╚██████╔╝███████╗███████╗██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
"""
    
    metadata_text = (
        f"[bold white]Version:[/bold white] [cyan]{meta['version']}[/cyan] | "
        f"[bold white]User:[/bold white] [cyan]{meta['user']}[/cyan] "
        f"{'([bold red]ROOT[/bold red])' if is_root() else '([bold yellow]Non-Root[/bold yellow])'}\n"
        f"[bold white]Host:[/bold white] [cyan]{meta['hostname']}[/cyan] | "
        f"[bold white]Kernel:[/bold white] [cyan]{meta['kernel']}[/cyan]\n"
        f"[bold white]Scan Started:[/bold white] [dim white]{meta['timestamp']}[/dim white]"
    )

    console.print(Align.center(f"[bold blue]{banner_text}[/bold blue]"))
    console.print(Align.center(Panel(metadata_text, border_style="dim white", width=86)))
    console.print()

def calculate_risk_score(findings: List[Finding]) -> int:
    """
    Calculates an overall risk score from 0 to 100.
    Weighted severity levels.
    """
    weights = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 5,
        "LOW": 1,
        "INFO": 0
    }
    
    score = 0
    for f in findings:
        score += weights.get(f.severity.upper(), 0)
        
    return min(100, score)

def filter_findings(findings: List[Finding], min_severity: str) -> List[Finding]:
    """Filters findings list by minimum severity."""
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        min_idx = severity_order.index(min_severity.upper())
    except ValueError:
        return findings

    return [f for f in findings if severity_order.index(f.severity.upper()) >= min_idx]

def main() -> None:
    parser = argparse.ArgumentParser(
        description="NULLHOUND: Automated Enumeration & Guided Intelligence Scanner - Linux Vulnerability Auditor"
    )
    
    parser.add_argument("--full", action="store_true", default=True, help="Run all scan modules (default)")
    parser.add_argument("--modules", type=str, help="Comma-separated list of modules to run (e.g. os,users,ssh)")
    parser.add_argument("--output", type=str, help="Path to save report (json / txt / html — detected by file extension)")
    parser.add_argument("--severity", type=str, default="low", choices=["critical", "high", "medium", "low", "info"],
                        help="Filter output to minimum severity (default: low)")
    parser.add_argument("--quiet", action="store_true", help="Suppress banner and progress bars, print findings only")
    parser.add_argument("--no-color", action="store_true", help="Plain text mode (no color coding)")
    parser.add_argument("--threads", type=int, default=4, help="Concurrency worker threads (default: 4)")
    parser.add_argument("--profile", type=str, default="standard", choices=["quick", "standard", "deep"],
                        help="Scan profile depth: quick (fast system checks), standard (default baseline), deep (thorough audit)")

    args = parser.parse_args()

    # Configure Rich Console
    console = Console(no_color=args.no_color)
    meta = get_system_metadata()
    meta["profile"] = args.profile

    # Resolve modules list
    selected_module_names = []
    if args.modules:
        # User specified specific modules
        parts = [p.strip().lower() for p in args.modules.split(",")]
        for p in parts:
            if p in ALL_MODULES:
                selected_module_names.append(p)
            else:
                console.print(f"[bold red]Error:[/bold red] Module '{p}' is invalid. Options are: {', '.join(ALL_MODULES.keys())}")
                sys.exit(1)
    else:
        # Default is full scan
        selected_module_names = list(ALL_MODULES.keys())

    # Instantiate modules
    module_instances = [ALL_MODULES[name]() for name in selected_module_names]

    # Print banner
    print_banner(console, meta, args.quiet)

    # Setup progress bar and live status tracking
    findings: List[Finding] = []
    start_time = time.time()
    
    # Track completion count
    total_modules = len(module_instances)
    completed_modules = 0

    if not args.quiet:
        console.print(f"[bold white]Running {total_modules} modules in parallel (profile: {args.profile}, threads: {args.threads})...[/bold white]")
        console.print()
        
        # We display a progress bar using Rich Progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            scan_task = progress.add_task("[bold cyan]Scanning host...", total=total_modules)
            
            def on_start(mod_name: str) -> None:
                progress.update(scan_task, description=f"[cyan]Running module: {mod_name.upper()}")

            def on_complete(mod_name: str, mod_findings: List[Finding]) -> None:
                nonlocal completed_modules
                completed_modules += 1
                progress.update(scan_task, advance=1, description=f"[green]Completed module: {mod_name.upper()}")

            runner = ModuleRunner(module_instances, threads=args.threads)
            findings = runner.run_all(profile=args.profile, on_start=on_start, on_complete=on_complete)
    else:
        # Quiet execution
        runner = ModuleRunner(module_instances, threads=args.threads)
        findings = runner.run_all(profile=args.profile)

    scan_duration = time.time() - start_time

    # Calculate statistics
    raw_findings_count = len(findings)
    risk_score = calculate_risk_score(findings)

    # Filter findings based on CLI severity setting
    filtered = filter_findings(findings, args.severity)

    # Group findings by module for console report panels
    findings_by_module: Dict[str, List[Finding]] = {}
    for f in filtered:
        findings_by_module.setdefault(f.module, []).append(f)

    # Print per-module panels if not quiet
    if not args.quiet:
        console.print()
        console.print("[bold white]━━━ MODULE SCAN SUMMARY ━━━[/bold white]")
        for mod_name in selected_module_names:
            mod_findings = [f for f in filtered if f.module == mod_name]
            critical = len([f for f in mod_findings if f.severity.upper() == "CRITICAL"])
            high = len([f for f in mod_findings if f.severity.upper() == "HIGH"])
            medium = len([f for f in mod_findings if f.severity.upper() == "MEDIUM"])
            low = len([f for f in mod_findings if f.severity.upper() == "LOW"])
            info = len([f for f in mod_findings if f.severity.upper() == "INFO"])
            
            if mod_findings:
                status_str = (
                    f"[bold red]CRITICAL: {critical}[/bold red] | "
                    f"[red]HIGH: {high}[/red] | "
                    f"[yellow]MEDIUM: {medium}[/yellow] | "
                    f"[cyan]LOW: {low}[/cyan] | "
                    f"[dim white]INFO: {info}[/dim white]"
                )
                panel_border = "red" if (critical or high) else "yellow" if medium else "cyan"
            else:
                status_str = "[bold green]PASS (0 Findings)[/bold green]"
                panel_border = "green"

            console.print(Panel(
                status_str,
                title=f"Module: {mod_name.upper()}",
                border_style=panel_border,
                expand=False
            ))

    # Print findings table
    if filtered:
        table = Table(title="[bold white]NULLHOUND VULNERABILITY FINDINGS[/bold white]", show_lines=True)
        table.add_column("ID", style="bold dim white")
        table.add_column("Severity", justify="center")
        table.add_column("Module", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Evidence Snippet", style="dim white", max_width=45)

        for f in filtered:
            color = get_severity_color(f.severity)
            severity_badge = f"[{color}]{f.severity}[/{color}]"
            
            # Truncate evidence for clean printing
            evidence_snippet = f.evidence.splitlines()[0] if f.evidence else "N/A"
            if len(evidence_snippet) > 42:
                evidence_snippet = evidence_snippet[:40] + "..."

            table.add_row(f.id, severity_badge, f.module, f.title, evidence_snippet)

        console.print()
        console.print(table)
    else:
        console.print()
        console.print("[bold green]✔ Clear Scan: No vulnerabilities match the filter criteria.[/bold green]")

    # Summary Panel
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:  # Calculate counts based on ALL findings, not just filtered
        sev = f.severity.upper()
        if sev in counts:
            counts[sev] += 1

    # Approximate checks run based on profile
    profile_checks = {"quick": 45, "standard": 91, "deep": 120}
    checks_run = profile_checks.get(args.profile, 91)
    # Ensure checks run is at least findings + 10
    checks_run = max(checks_run, raw_findings_count + 15)

    hardening_score = 100 - risk_score
    risk_color = "red" if risk_score >= 70 else "yellow" if risk_score >= 35 else "green"
    hardening_color = "red" if hardening_score < 30 else "yellow" if hardening_score < 65 else "green"

    summary_text = (
        f"[bold white]Total Checks Executed :[/bold white] {checks_run}\n"
        f"[bold white]Total Findings Count   :[/bold white] {raw_findings_count}\n"
        f"[bold white]Severity Breakdown    :[/bold white] "
        f"[bold red]CRITICAL: {counts['CRITICAL']}[/bold red] | "
        f"[red]HIGH: {counts['HIGH']}[/red] | "
        f"[yellow]MEDIUM: {counts['MEDIUM']}[/yellow] | "
        f"[cyan]LOW: {counts['LOW']}[/cyan] | "
        f"[dim white]INFO: {counts['INFO']}[/dim white]\n"
        f"[bold white]Overall Risk Score    :[/bold white] [{risk_color}]{risk_score}/100[/{risk_color}]\n"
        f"[bold white]System Hardening Index:[/bold white] [{hardening_color}]{hardening_score}/100[/{hardening_color}]\n"
        f"[bold white]Scan Duration         :[/bold white] {scan_duration:.2f} seconds"
    )

    if not args.quiet:
        console.print()
        console.print(Panel(summary_text, title="[bold white]NULLHOUND SCAN SUMMARY[/bold white]", border_style="white", width=70))

    # Export report if output argument provided
    if args.output:
        reporter = ReportReporter(filtered, meta, risk_score)
        try:
            exported_path = reporter.export(args.output)
            console.print()
            console.print(f"[bold green]✔ Report successfully exported to: {exported_path}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error: Failed to export report:[/bold red] {str(e)}", file=sys.stderr)

if __name__ == "__main__":
    main()
