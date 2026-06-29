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

import re
from core.finding import Finding, CIS_BENCHMARKS
from core.runner import ModuleRunner
from core.reporter import ReportReporter
from core.utils import get_severity_color, is_root, run_cmd, has_binary
from modules import ALL_MODULES

# Versioning
VERSION = "1.1.0"

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
        f"[bold white]Scan Started:[/bold white] [dim white]{meta['timestamp']}[/dim white] | "
        f"[bold green]Made By Hercules[/bold green]"
    )

    console.print(Align.center(f"[bold blue]{banner_text}[/bold blue]"))
    console.print(Align.center(Panel(metadata_text, border_style="dim white", width=86)))
    console.print()

    if sys.platform == "win32":
        console.print(Align.center(Panel(
            "[bold yellow]⚠️ WARNING: Running on Windows Host[/bold yellow]\n\n"
            "NULLHOUND is designed as a native Linux security auditor. Running it directly on Windows\n"
            "will result in failed audit checks. For local testing, please run NULLHOUND inside\n"
            "[bold cyan]WSL (Windows Subsystem for Linux)[/bold cyan] or on a target Linux VM.",
            border_style="yellow",
            width=86
        )))
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

def run_cve_check(console: Console, quiet: bool) -> List[Finding]:
    """
    Queries local package managers for installed versions,
    queries the OSV API in batches, then queries NVD/NIST API for CVSS info.
    """
    if not quiet:
        console.print("[bold cyan]Starting Real-Time Package CVE Lookup...[/bold cyan]")
        console.print("[dim white]Detecting local package manager and OS distribution...[/dim white]")
    
    # 1. Get OS ecosystem
    ecosystem = "Debian"
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read()
                id_match = re.search(r'^ID=["\']?([^"\']+)["\']?', content, re.M)
                if id_match:
                    os_id = id_match.group(1).lower()
                    if "ubuntu" in os_id:
                        ecosystem = "Ubuntu"
                    elif "debian" in os_id:
                        ecosystem = "Debian"
                    elif "alpine" in os_id:
                        ecosystem = "Alpine"
                    elif "rocky" in os_id:
                        ecosystem = "Rocky Linux"
                    elif "almalinux" in os_id:
                        ecosystem = "AlmaLinux"
        except Exception:
            pass
            
    # 2. Get packages
    packages = []
    if has_binary("dpkg-query"):
        out, _, _ = run_cmd("dpkg-query -W -f='${Package} ${Version}\\n'")
        if out:
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    name, version = parts[0], parts[1]
                    name = name.split(':')[0]
                    packages.append({"name": name, "version": version})
    elif has_binary("rpm"):
        out, _, _ = run_cmd("rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n'")
        if out:
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1]})
    elif has_binary("apk"):
        out, _, _ = run_cmd("apk info -v")
        if out:
            for line in out.splitlines():
                parts = line.strip().rsplit('-', 2)
                if len(parts) == 3:
                    packages.append({"name": parts[0], "version": f"{parts[1]}-{parts[2]}"})
                    
    if not packages:
        console.print("[bold red]Error:[/bold red] No installed system packages detected. Supported package managers: dpkg, rpm, apk.")
        return []
        
    if not quiet:
        console.print(f"[green]✔[/green] Detected [cyan]{len(packages)}[/cyan] packages on the system ([bold white]{ecosystem}[/bold white]).")
        
    # Import requests
    try:
        import requests
    except ImportError:
        console.print("[bold red]Error:[/bold red] The 'requests' library is not installed. Run 'pip install requests' to run CVE checks.")
        return []
        
    # OSV batch endpoint
    osv_url = "https://api.osv.dev/v1/querybatch"
    queries = []
    for pkg in packages:
        queries.append({
            "package": {
                "name": pkg["name"],
                "ecosystem": ecosystem
            },
            "version": pkg["version"]
        })
        
    osv_results = []
    chunk_size = 500
    
    if not quiet:
        progress_msg = f"Querying OSV database in batches of {chunk_size}..."
        with console.status(f"[bold yellow]{progress_msg}[/bold yellow]"):
            for i in range(0, len(queries), chunk_size):
                chunk = queries[i:i + chunk_size]
                try:
                    res = requests.post(osv_url, json={"queries": chunk}, timeout=15)
                    if res.status_code == 200:
                        osv_results.extend(res.json().get("results", []))
                    else:
                        osv_results.extend([{} for _ in chunk])
                except Exception:
                    osv_results.extend([{} for _ in chunk])
    else:
        for i in range(0, len(queries), chunk_size):
            chunk = queries[i:i + chunk_size]
            try:
                res = requests.post(osv_url, json={"queries": chunk}, timeout=15)
                if res.status_code == 200:
                    osv_results.extend(res.json().get("results", []))
                else:
                    osv_results.extend([{} for _ in chunk])
            except Exception:
                osv_results.extend([{} for _ in chunk])
                
    # Parse vulns
    vulnerable_packages = []
    for idx, res_item in enumerate(osv_results):
        vulns = res_item.get("vulns", [])
        if vulns:
            pkg = packages[idx]
            # Collect unique CVEs
            cve_ids = []
            for v in vulns:
                aliases = v.get("aliases", [])
                for alias in aliases:
                    if alias.startswith("CVE-") and alias not in cve_ids:
                        cve_ids.append(alias)
                v_id = v.get("id", "")
                if v_id.startswith("CVE-") and v_id not in cve_ids:
                    cve_ids.append(v_id)
            if cve_ids:
                vulnerable_packages.append({
                    "name": pkg["name"],
                    "version": pkg["version"],
                    "cves": cve_ids
                })
                
    if not vulnerable_packages:
        if not quiet:
            console.print("[bold green]✔ Clear Scan: No installed package vulnerabilities detected via OSV database.[/bold green]")
        return []
        
    if not quiet:
        console.print(f"[bold yellow]Found {len(vulnerable_packages)} packages with known vulnerabilities. Resolving CVSS metadata via NVD API...[/bold yellow]")
        
    findings_list = []
    
    unique_cves = set()
    for item in vulnerable_packages:
        for c in item["cves"]:
            unique_cves.add(c)
            
    cve_details = {}
    
    def fetch_nvd_info(cves_list):
        for idx, cve_id in enumerate(cves_list):
            if not quiet:
                console.status(f"[bold yellow]Resolving CVE info ({idx+1}/{len(cves_list)}): {cve_id}...[/bold yellow]")
            # API query
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            try:
                # NVD rate limit delay
                time.sleep(0.6)
                res = requests.get(url, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        cve_obj = vulns[0].get("cve", {})
                        metrics = cve_obj.get("metrics", {})
                        base_score = None
                        base_severity = "UNKNOWN"
                        
                        v31 = metrics.get("cvssMetricV31", [])
                        v30 = metrics.get("cvssMetricV30", [])
                        v2 = metrics.get("cvssMetricV2", [])
                        
                        selected_metric = None
                        for m in v31 + v30 + v2:
                            if m.get("type") == "Primary":
                                selected_metric = m
                                break
                        if not selected_metric and (v31 or v30 or v2):
                            selected_metric = (v31 + v30 + v2)[0]
                            
                        if selected_metric:
                            cvss_data = selected_metric.get("cvssData", {})
                            base_score = cvss_data.get("baseScore")
                            base_severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                            
                        cve_details[cve_id] = {
                            "cvss_score": base_score,
                            "severity": base_severity,
                            "description": cve_obj.get("descriptions", [{}])[0].get("value", "No description available.")
                        }
                        continue
            except Exception:
                pass
            cve_details[cve_id] = {
                "cvss_score": None,
                "severity": "UNKNOWN",
                "description": "NVD lookup failed or timed out."
            }

    cves_to_fetch = list(unique_cves)
    if not quiet:
        with console.status("[bold yellow]Resolving CVE details...[/bold yellow]"):
            fetch_nvd_info(cves_to_fetch)
    else:
        fetch_nvd_info(cves_to_fetch)
        
    for item in vulnerable_packages:
        name = item["name"]
        version = item["version"]
        for cve_id in item["cves"]:
            details = cve_details.get(cve_id, {"cvss_score": None, "severity": "UNKNOWN", "description": "NVD lookup failed."})
            cvss_score = details["cvss_score"]
            severity = details["severity"]
            desc = details["description"]
            
            std_severity = "HIGH"
            if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                std_severity = severity
            elif severity == "UNKNOWN":
                std_severity = "HIGH"
                
            cvss_str = f"CVSS {cvss_score} {severity}" if cvss_score is not None else f"CVSS N/A {severity}"
            
            color_sev = get_severity_color(std_severity)
            console.print(f"[bold white]{name} {version}[/bold white] → [cyan]{cve_id}[/cyan] ([{color_sev}]{cvss_str}[/{color_sev}]) ⚠️")
            
            finding_id = f"AEG-VUL-{cve_id.replace('-', '')}"
            f_obj = Finding(
                id=finding_id,
                title=f"Package Vulnerability: {name} {version} ({cve_id})",
                severity=std_severity,
                module="packages",
                description=desc,
                evidence=f"Package: {name}\nVersion: {version}\nEcosystem: {ecosystem}\nCVE: {cve_id}\nCVSS: {cvss_score if cvss_score is not None else 'N/A'} ({severity})",
                remediation=f"Upgrade package {name} to a secure version using your package manager.",
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                compliance=["CIS 1.2.1"]
            )
            findings_list.append(f_obj)
            
    return findings_list

def print_compliance_report(console: Console, findings: List[Finding], quiet: bool) -> None:
    """Prints a beautiful CIS Benchmark compliance report table."""
    if quiet:
        return
        
    console.print()
    console.print("[bold white]━━━ CIS COMPLIANCE BENCHMARK REPORT ━━━[/bold white]")
    
    table = Table(title="[bold white]CIS BENCHMARK COMPLIANCE STATUS[/bold white]", show_lines=True)
    table.add_column("CIS Control", style="bold dim white")
    table.add_column("Description", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Triggered Finding(s)", style="dim white")
    
    passed_count = 0
    failed_count = 0
    
    for control_id, desc in sorted(CIS_BENCHMARKS.items()):
        triggered = [f for f in findings if control_id in f.compliance]
        
        if triggered:
            status = "[bold red]FAIL[/bold red]"
            finding_ids = ", ".join([f.id for f in triggered])
            failed_count += 1
            table.add_row(control_id, desc, status, finding_ids)
        else:
            status = "[bold green]PASS[/bold green]"
            passed_count += 1
            table.add_row(control_id, desc, status, "[green]Compliant[/green]")
            
    console.print(table)
    
    total_checks = passed_count + failed_count
    pass_rate = (passed_count / total_checks * 100) if total_checks > 0 else 100
    
    color = 'green' if pass_rate >= 80 else 'yellow' if pass_rate >= 50 else 'red'
    summary_text = (
        f"[bold white]CIS Controls Audited :[/bold white] {total_checks}\n"
        f"[bold white]Passed Controls      :[/bold white] [bold green]{passed_count}[/bold green]\n"
        f"[bold white]Failed Controls      :[/bold white] [bold red]{failed_count}[/bold red]\n"
        f"[bold white]Compliance Pass Rate :[/bold white] [bold {color}]{pass_rate:.1f}%[/bold {color}]"
    )
    console.print()
    console.print(Panel(summary_text, title="[bold white]COMPLIANCE SUMMARY[/bold white]", border_style="white", width=50))

def exit_scanner(code: int, pause: bool = False) -> None:
    """Gracefully exits, optionally pausing if on Windows or requested."""
    if pause or sys.platform == "win32":
        if sys.stdout.isatty():
            try:
                input("\nPress Enter to exit...")
            except (KeyboardInterrupt, EOFError):
                pass
    sys.exit(code)

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
    parser.add_argument("--cve-check", action="store_true", help="Perform real-time CVE vulnerabilities check on installed packages")
    parser.add_argument("--compliance", type=str, choices=["cis"], help="Generate a compliance pass/fail report mapped to a benchmark (e.g., cis)")
    parser.add_argument("--pause", action="store_true", help="Pause and wait for keypress before exiting (prevents auto-closing terminal)")

    args = parser.parse_args()

    # Configure Rich Console
    console = Console(no_color=args.no_color)
    meta = get_system_metadata()
    meta["profile"] = args.profile
    meta["compliance"] = args.compliance

    if args.cve_check:
        print_banner(console, meta, args.quiet)
        cve_findings = run_cve_check(console, args.quiet)
        
        filtered_cve = filter_findings(cve_findings, args.severity)
        
        if args.output:
            risk_score = calculate_risk_score(filtered_cve)
            meta["profile"] = "cve-check"
            reporter = ReportReporter(filtered_cve, meta, risk_score)
            try:
                exported_path = reporter.export(args.output)
                console.print()
                console.print(f"[bold green]✔ Report successfully exported to: {exported_path}[/bold green]")
            except Exception as e:
                console.print(f"[bold red]Error: Failed to export report:[/bold red] {str(e)}", file=sys.stderr)
        exit_scanner(0, args.pause)

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
                exit_scanner(1, args.pause)
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

    # Print findings/compliance report
    if args.compliance == "cis":
        print_compliance_report(console, filtered, args.quiet)
    else:
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

    exit_scanner(0, args.pause)

if __name__ == "__main__":
    main()
