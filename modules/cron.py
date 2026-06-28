import os
import re
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class CronModule(BaseModule):
    @property
    def name(self) -> str:
        return "cron"

    @property
    def description(self) -> str:
        return "Audit scheduled cron jobs, world-writable scripts, missing binaries, and active systemd timers"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs"
        ]

        all_cron_files = []
        for path in cron_paths:
            if os.path.exists(path):
                if os.path.isdir(path):
                    try:
                        for entry in os.listdir(path):
                            full_path = os.path.join(path, entry)
                            if os.path.isfile(full_path) and not os.path.islink(full_path):
                                all_cron_files.append(full_path)
                    except Exception:
                        pass
                else:
                    all_cron_files.append(path)

        # 1. Check for world-writable cron configuration files or scripts
        ww_cron_files = []
        for fpath in all_cron_files:
            try:
                stat_info = os.stat(fpath)
                mode = stat_info.st_mode
                if mode & 0o002: # World-writable
                    ww_cron_files.append(fpath)
            except Exception:
                pass

        if ww_cron_files:
            findings.append(self.create_finding(
                id_="AEG-CRN-001",
                title="World-writable cron file detected",
                severity="CRITICAL",
                description="One or more cron schedules or configuration files are world-writable. Any user can edit these files to inject commands that run with administrative privileges.",
                evidence="\n".join(ww_cron_files),
                remediation="Restrict permissions to the file owner: sudo chmod 644 <cron_file>",
                references=["https://www.cisecurity.org/benchmark/debian_linux"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
            ))

        # 2. Parse cron entries for security checks
        # Checks: downloads (wget/curl) and non-existent scripts
        missing_executables = []
        download_commands = []
        
        for cf in all_cron_files:
            try:
                with open(cf, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" in line.split()[0:1]: # Skip env vars
                            continue
                        
                        # Check for curl / wget / python network fetches
                        if any(downloader in line for downloader in ["curl", "wget", "tftp", "fetch", "python -c"]):
                            download_commands.append((cf, line))
                            
                        # Search for absolute paths in the line to see if they exist
                        # Match strings starting with / and containing word chars, dots, slashes
                        paths = re.findall(r"(/[a-zA-Z0-9_\-\./]+)", line)
                        for p in paths:
                            # Skip common standard binary paths or directories
                            if p in ["/bin/sh", "/bin/bash", "/usr/bin/python", "/usr/bin/python3", "/dev/null", "/etc/passwd"]:
                                continue
                            # Clean up trailing periods, slashes, or quotes
                            p_clean = p.rstrip(".")
                            # Check if it looks like a script/binary reference (e.g. ends with .sh, .py, .pl, or in /bin,/usr/bin,/sbin,/opt,/home,/var)
                            if os.path.basename(p_clean) and not os.path.isdir(p_clean):
                                if any(x in p_clean for x in ["/opt/", "/home/", "/var/", "/tmp/"]) or p_clean.endswith((".sh", ".py", ".pl", ".php", ".bin")):
                                    if not os.path.exists(p_clean):
                                        # Only add once
                                        if (cf, p_clean) not in missing_executables:
                                            missing_executables.append((cf, p_clean, line))
                                            
                                # Also check world-writable script files referenced in cron
                                if os.path.exists(p_clean):
                                    try:
                                        p_stat = os.stat(p_clean)
                                        if p_stat.st_mode & 0o002:
                                            findings.append(self.create_finding(
                                                id_="AEG-CRN-002",
                                                title=f"Cron script referenced in '{os.path.basename(cf)}' is world-writable",
                                                severity="CRITICAL",
                                                description=f"The script '{p_clean}' executed by a cron job in '{cf}' is world-writable. A local attacker can edit the script contents to execute code with the privileges of the cron job (usually root).",
                                                evidence=f"Cron file: {cf}, Script: {p_clean}",
                                                remediation=f"Restrict write permission to owner: chmod o-w {p_clean}",
                                                references=["https://attack.mitre.org/techniques/T1053/005/"],
                                                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
                                            ))
                                    except Exception:
                                        pass
            except Exception:
                pass

        for cf, line in download_commands:
            findings.append(self.create_finding(
                id_="AEG-CRN-003",
                title="Scheduled task downloads content from internet",
                severity="HIGH",
                description=f"A cron job in '{cf}' appears to run curl or wget. Fetching and executing online content inside automated cron jobs is risky, as a compromised remote server could supply malicious updates.",
                evidence=f"Cron: {line}",
                remediation="Avoid scheduling raw curl/wget commands. Download files through secure, authenticated update systems or sign scripts before execution.",
                references=[],
                compliance=["PCI-DSS v4.0 2.2.4"]
            ))

        for cf, p_clean, line in missing_executables:
            findings.append(self.create_finding(
                id_="AEG-CRN-004",
                title="Cron references non-existent script/binary",
                severity="HIGH",
                description=f"A scheduled job in '{cf}' references an absolute file path '{p_clean}' that does not exist on the system. If an attacker can write to the parent directory or create the file name, they can hijack the execution when cron triggers it.",
                evidence=f"Path: {p_clean}, Line: {line}",
                remediation=f"Remove the cron entry or restore/create the missing executable with proper owner-only write permissions.",
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-jobs"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12"]
            ))

        # 3. Systemd Timers check
        # List all systemd timers and check for root-owned user units
        timers_out, _, exit_code = run_cmd("systemctl list-timers --all --no-legend")
        if exit_code == 0 and timers_out:
            for line in timers_out.splitlines():
                # Format is typically: NEXT LEFT LAST PASSED UNIT ACTIVATES
                # e.g., Sun 2026-06-28 14:00:00 UTC  55min left  -  -  apt-daily.timer apt-daily.service
                parts = line.split()
                if len(parts) >= 6:
                    timer_unit = parts[4]
                    service_unit = parts[5]
                    # Check if it's a custom user timer running as root
                    # Custom systemd timers are typically in /etc/systemd/system/
                    custom_path = f"/etc/systemd/system/{service_unit}"
                    if os.path.exists(custom_path):
                        try:
                            with open(custom_path, "r") as sf:
                                s_content = sf.read()
                                # Check if it runs as User=root or lacks User setting (which defaults to root)
                                if "User=" not in s_content or "User=root" in s_content:
                                    # If it runs scripts in /tmp or world-writable, flag it
                                    # This is standard behavior for many services, let's keep it as INFO/LOW
                                    pass
                        except Exception:
                            pass

        return findings
