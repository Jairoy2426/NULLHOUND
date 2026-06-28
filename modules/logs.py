import os
import re
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class LogsModule(BaseModule):
    @property
    def name(self) -> str:
        return "logs"

    @property
    def description(self) -> str:
        return "Audit log integrity, daemon execution status, log rotation policies, and SSH failed login counts"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Check if rsyslog, syslog-ng, or systemd-journald is active
        logging_active = False
        services = ["rsyslog.service", "syslog-ng.service", "systemd-journald.service"]
        
        # Check running processes as fallback if systemctl not active/available
        ps_out, _, _ = run_cmd("ps -ef")
        for svc in ["rsyslog", "syslog-ng", "systemd-journald"]:
            if ps_out and svc in ps_out:
                logging_active = True
                break
        
        # Systemd check
        if not logging_active and os.path.exists("/run/systemd/system"):
            for svc in services:
                status, _, _ = run_cmd(f"systemctl is-active {svc}")
                if status.strip() == "active":
                    logging_active = True
                    break

        if not logging_active:
            findings.append(self.create_finding(
                id_="AEG-LOG-001",
                title="No active system logging daemon detected",
                severity="HIGH",
                description="No active syslog daemon (rsyslog, syslog-ng, journald) was found running. Without logs, auditing system events, security incidents, and operational failures is impossible.",
                evidence="No running syslog/journald process found.",
                remediation="Start and enable a logging service: sudo systemctl enable --now rsyslog",
                references=["https://www.cisecurity.org/benchmark/debian_linux"]
            ))

        # 2. Verify Log Rotation is configured
        logrotate_conf = "/etc/logrotate.conf"
        if not os.path.exists(logrotate_conf):
            findings.append(self.create_finding(
                id_="AEG-LOG-002",
                title="Logrotate configuration not found",
                severity="MEDIUM",
                description="The '/etc/logrotate.conf' file is missing. Without log rotation, log files will grow indefinitely, eventually exhausting disk space and causing denial of service.",
                evidence="File not found: /etc/logrotate.conf",
                remediation="Install logrotate: sudo apt install logrotate or sudo dnf install logrotate",
                references=[]
            ))

        # 3. Check if auditd is installed and active
        auditd_active = False
        if ps_out and "auditd" in ps_out:
            auditd_active = True
        else:
            status, _, _ = run_cmd("systemctl is-active auditd")
            if status.strip() == "active":
                auditd_active = True

        if not auditd_active:
            findings.append(self.create_finding(
                id_="AEG-LOG-003",
                title="Auditd daemon is not running",
                severity="MEDIUM",
                description="The Linux Audit Daemon (auditd) is not active. auditd provides security auditing by tracking system calls, file access, and security state changes.",
                evidence="auditd service is inactive or not installed.",
                remediation="Install and enable auditd: sudo apt install auditd && sudo systemctl enable --now auditd",
                references=["https://www.cisecurity.org/benchmark/ubuntu_linux"]
            ))

        # 4. Count failed SSH logins in /var/log/auth.log or /var/log/secure
        auth_log = "/var/log/auth.log"
        if not os.path.exists(auth_log) and os.path.exists("/var/log/secure"):
            auth_log = "/var/log/secure"

        if os.path.exists(auth_log):
            try:
                # Count "Failed password" or "Authentication failure"
                with open(auth_log, "r", errors="ignore") as f:
                    failed_count = 0
                    sample_failures = []
                    for line in f:
                        if "failed password" in line.lower() or "authentication failure" in line.lower() or "failed publickey" in line.lower():
                            failed_count += 1
                            if len(sample_failures) < 5:
                                sample_failures.append(line.strip())
                    
                    if failed_count > 50:
                        findings.append(self.create_finding(
                            id_="AEG-LOG-004",
                            title=f"High count of failed SSH logins detected ({failed_count} failures)",
                            severity="HIGH",
                            description="A high number of failed SSH authentication events was found in the authentication logs. This could indicate an active network brute force attack targeting SSH accounts.",
                            evidence=f"Log: {auth_log}, Failed count: {failed_count}\nSamples:\n" + "\n".join(sample_failures),
                            remediation="Implement brute-force protections such as Fail2ban or deny hosts. Configure SSH to disable password authentication.",
                            references=["https://attack.mitre.org/techniques/T1110/"]
                        ))
            except PermissionError:
                findings.append(self.create_finding(
                    id_="AEG-LOG-005",
                    title=f"Lacks permissions to read auth logs ({os.path.basename(auth_log)})",
                    severity="INFO",
                    description="The scanner lacks root permissions to read authentication logs to scan for brute-force SSH attacks.",
                    evidence="Permission Denied",
                    remediation="Run the scanner with root/sudo."
                ))
            except Exception:
                pass

        # 5. Detect cleared logs (/var/log/wtmp size 0)
        # wtmp tracks user logins/reboots. If size is 0, it has been truncated/cleared.
        wtmp_path = "/var/log/wtmp"
        if os.path.exists(wtmp_path):
            try:
                stat_info = os.stat(wtmp_path)
                if stat_info.st_size == 0:
                    findings.append(self.create_finding(
                        id_="AEG-LOG-006",
                        title="User login history log (wtmp) is cleared/truncated",
                        severity="CRITICAL",
                        description="The /var/log/wtmp file size is 0 bytes. Truncating wtmp is a common anti-forensics technique used by attackers to hide login history and shell access.",
                        evidence="File size: 0 bytes",
                        remediation="Investigate system access history immediately. Check shell history files and verify login logs in syslog.",
                        references=["https://attack.mitre.org/techniques/T1070/002/"]
                    ))
            except Exception:
                pass

        # 6. Check if /var/log is world-writable
        log_dir = "/var/log"
        if os.path.exists(log_dir):
            try:
                stat_info = os.stat(log_dir)
                mode = stat_info.st_mode
                if mode & 0o002: # World-writable
                    findings.append(self.create_finding(
                        id_="AEG-LOG-007",
                        title="The system log directory (/var/log) is world-writable",
                        severity="CRITICAL",
                        description="The system log directory '/var/log' is world-writable. Any user can delete or overwrite logs, defeating accountability and trace logs.",
                        evidence=f"Permissions: {oct(mode)[-3:]}",
                        remediation="Restrict log directory permissions: sudo chmod 755 /var/log",
                        references=[]
                    ))
            except Exception:
                pass

        return findings
