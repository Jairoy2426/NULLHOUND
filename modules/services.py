import os
import re
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class ServicesModule(BaseModule):
    @property
    def name(self) -> str:
        return "services"

    @property
    def description(self) -> str:
        return "Audit active systemd services, deprecated daemons, and orphaned processes"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # Check if systemd is available
        has_systemd = os.path.exists("/run/systemd/system") or os.path.exists("/usr/lib/systemd")
        
        running_services = []
        if has_systemd:
            units_out, _, exit_code = run_cmd("systemctl list-units --type=service --state=running --no-legend")
            if exit_code == 0 and units_out:
                for line in units_out.splitlines():
                    parts = line.split()
                    if parts:
                        running_services.append(parts[0])
        else:
            findings.append(self.create_finding(
                id_="AEG-SRV-001",
                title="Systemd not detected on this system",
                severity="INFO",
                description="The system does not appear to be using systemd for service management. Service audits will be limited.",
                evidence="No /run/systemd/system directory",
                remediation="If using another init system (SysVinit, OpenRC), inspect running services using 'ps' or 'service --status-all'."
            ))

        # 1. Flag deprecated/insecure services
        # Map service unit names to human-readable names
        deprecated_map = {
            "telnet.service": "Telnet server (unencrypted credentials)",
            "telnetd.service": "Telnet server (unencrypted credentials)",
            "rsh.service": "Remote Shell (unencrypted terminal)",
            "rlogin.service": "rlogin (unencrypted terminal access)",
            "vsftpd.service": "vsftpd (FTP server - unencrypted unless configured with TLS)",
            "proftpd.service": "proftpd (FTP server - unencrypted)",
            "pure-ftpd.service": "pure-ftpd (FTP server - unencrypted)",
            "rpcbind.service": "rpcbind (historically vulnerable RPC service mapping)",
            "fingerd.service": "finger daemon (information disclosure vulnerability)",
            "talk.service": "talk daemon (unencrypted legacy communication service)"
        }

        for svc in running_services:
            # Match service name
            for dep_svc, desc in deprecated_map.items():
                if dep_svc in svc or svc.startswith(dep_svc.split('.')[0]):
                    findings.append(self.create_finding(
                        id_="AEG-SRV-002",
                        title=f"Insecure service '{svc}' is running",
                        severity="HIGH",
                        description=f"The service '{svc}' ({desc}) is active. These legacy protocols transmit passwords and commands in cleartext, making the system vulnerable to credential sniffing and tampering.",
                        evidence=f"Service status: active/running",
                        remediation=f"Stop and disable the service: sudo systemctl disable --now {svc}",
                        references=["https://www.cisecurity.org/benchmark/ubuntu_linux"]
                    ))

        # 2. Forensic audit: orphaned services (process running but binary is deleted from disk)
        # Often occurs after package upgrade without service restart, OR is a sign of malware executing from a deleted path.
        orphaned_processes = []
        try:
            for pid in os.listdir("/proc"):
                if pid.isdigit():
                    try:
                        exe_link = os.readlink(f"/proc/{pid}/exe")
                        if " (deleted)" in exe_link:
                            # Read process name
                            with open(f"/proc/{pid}/comm", "r") as f:
                                comm = f.read().strip()
                            orphaned_processes.append((pid, comm, exe_link))
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        continue
        except Exception as e:
            pass

        if orphaned_processes:
            for pid, comm, exe in orphaned_processes:
                # System upgrades can trigger this (e.g. dbus, systemd-journald). Let's log as MEDIUM
                # If it's a suspicious name or in temp dir, it could be HIGH.
                severity = "MEDIUM"
                if "/tmp" in exe or "/dev/shm" in exe:
                    severity = "CRITICAL"
                
                findings.append(self.create_finding(
                    id_="AEG-SRV-003",
                    title=f"Process '{comm}' running from deleted binary",
                    severity=severity,
                    description=f"The process '{comm}' (PID {pid}) is executing from a binary that has been deleted from the filesystem ({exe}). While common during system upgrades before services are restarted, this is also a classic technique used by attackers to hide malware.",
                    evidence=f"PID: {pid}, Command: {comm}, Path: {exe}",
                    remediation=f"Restart the affected service: systemctl restart {comm} (or kill PID {pid} if unauthorized).",
                    references=["https://attack.mitre.org/techniques/T1070/004/"]
                ))

        # 3. Running as root check (specifically for non-system services that should run under dedicated users)
        # Cross reference running process list
        # E.g. nginx, apache2, bind9, redis-server, memcached, mysql, postgresql
        # Check if they are running *only* as root (i.e. child worker processes are also root)
        # Nginx/Apache parent run as root (normal to bind to port 80), but workers should run as www-data/nginx.
        # Redis/memcached/bind should not run as root at all.
        try:
            ps_out, _, _ = run_cmd("ps -ef")
            if ps_out:
                for line in ps_out.splitlines():
                    # root       1234     1  0 Jun28 ?        00:00:00 redis-server 127.0.0.1:6379
                    if "redis-server" in line and line.startswith("root"):
                        findings.append(self.create_finding(
                            id_="AEG-SRV-004",
                            title="Redis database server is running as root",
                            severity="HIGH",
                            description="The Redis server process is running as root. If Redis is compromised via command injection or file writing, the attacker will gain immediate root privileges on the host.",
                            evidence=line,
                            remediation="Modify the Redis service config (typically /etc/redis/redis.conf or systemd unit) to run under the dedicated 'redis' user.",
                            references=["https://redis.io/docs/management/security/"]
                        ))
                    if "memcached" in line and line.startswith("root"):
                        findings.append(self.create_finding(
                            id_="AEG-SRV-005",
                            title="Memcached cache server is running as root",
                            severity="HIGH",
                            description="Memcached is running as root. This increases exposure to remote code execution vulnerabilities.",
                            evidence=line,
                            remediation="Run memcached with the '-u memcache' parameter.",
                            references=[]
                        ))
        except Exception:
            pass

        # 4. Check for known bad configurations (rsync exposed without authentication)
        # Check if rsyncd.conf exists and check for "hosts allow" or auth configurations
        rsync_conf = "/etc/rsyncd.conf"
        if os.path.exists(rsync_conf):
            try:
                with open(rsync_conf, "r") as f:
                    content = f.read()
                    # Check if rsyncd has no auth users and no IP restrictions
                    if "secrets file" not in content and "auth users" not in content:
                        findings.append(self.create_finding(
                            id_="AEG-SRV-006",
                            title="Rsync daemon configured without authentication",
                            severity="HIGH",
                            description="The Rsync daemon configuration file (/etc/rsyncd.conf) does not specify authentication (auth users, secrets file). Anyone who can connect to the port can read and write files.",
                            evidence=content[:200],
                            remediation="Add 'auth users' and 'secrets file' directives to /etc/rsyncd.conf to restrict access.",
                            references=["https://book.hacktricks.xyz/pentesting/873-pentesting-rsync"]
                        ))
            except Exception:
                pass

        return findings
