import os
import re
import time
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd, is_root

class UsersModule(BaseModule):
    @property
    def name(self) -> str:
        return "users"

    @property
    def description(self) -> str:
        return "Audit system accounts, sudo privileges, shell policies, and home directories"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []
        
        # Helper to read /etc/passwd
        users = []
        if os.path.exists("/etc/passwd"):
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        if len(parts) >= 7:
                            users.append({
                                "username": parts[0],
                                "uid": int(parts[2]),
                                "gid": int(parts[3]),
                                "home": parts[5],
                                "shell": parts[6]
                            })
            except Exception as e:
                findings.append(self.create_finding(
                    id_="AEG-USR-002",
                    title="Unable to read /etc/passwd",
                    severity="HIGH",
                    description=f"Error parsing /etc/passwd: {str(e)}",
                    evidence="",
                    remediation="Check filesystem permissions on /etc/passwd."
                ))
        
        # 1. UID 0 accounts
        uid_0_users = [u["username"] for u in users if u["uid"] == 0]
        non_root_uid_0 = [u for u in uid_0_users if u != "root"]
        if non_root_uid_0:
            findings.append(self.create_finding(
                id_="AEG-USR-001",
                title="Non-root account with UID 0 detected",
                severity="CRITICAL",
                description="A non-root user account has been configured with UID 0 (root privileges). This is a strong indicator of backdoor presence or severe misconfiguration.",
                evidence=f"UID 0 accounts: {', '.join(uid_0_users)}",
                remediation="Immediately investigate and remove non-root accounts with UID 0.",
                references=["https://csrc.nist.gov/glossary/term/privilege_escalation"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.1"]
            ))

        # 2. Empty passwords in /etc/shadow
        shadow_accessible = False
        if os.path.exists("/etc/shadow"):
            try:
                with open("/etc/shadow", "r") as f:
                    shadow_accessible = True
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(":")
                        if len(parts) >= 2:
                            uname = parts[0]
                            passwd_hash = parts[1]
                            if passwd_hash == "":
                                findings.append(self.create_finding(
                                    id_="AEG-USR-003",
                                    title="Account with empty password hash",
                                    severity="CRITICAL",
                                    description=f"The account '{uname}' has an empty password in /etc/shadow, meaning anyone can log in to this account without a password.",
                                    evidence=f"User: {uname}, shadow entry: {line[:30]}...",
                                    remediation=f"Set a password for the account: passwd {uname}",
                                    references=["https://www.cisa.gov/resources-tools/resources/preventing-unauthorized-access-systems"],
                                    compliance=["PCI-DSS v4.0 8.2.1", "ISO27001:2022 A.5.15", "CIS-Control 5.2"]
                                ))
            except PermissionError:
                # This is normal if not running as root, we will log it as INFO
                findings.append(self.create_finding(
                    id_="AEG-USR-004",
                    title="Unable to read /etc/shadow (Permission Denied)",
                    severity="INFO",
                    description="The scanner lacks permissions to read /etc/shadow. Empty password detection could not be performed.",
                    evidence="Permission Denied",
                    remediation="Run the scanner as root/sudo to audit shadow password entries."
                ))
            except Exception as e:
                findings.append(self.create_finding(
                    id_="AEG-USR-005",
                    title="Error reading /etc/shadow",
                    severity="INFO",
                    description=f"An error occurred while parsing /etc/shadow: {str(e)}",
                    evidence="",
                    remediation="Check file integrity and permissions."
                ))

        # 3. System accounts with active shells
        # Shells that are considered interactive
        interactive_shells = {"/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh", "/bin/ksh", "/bin/tcsh"}
        for u in users:
            # Typically system accounts have UID < 1000 (excluding 0 for root, and 65534 for nobody)
            if u["uid"] < 1000 and u["uid"] != 0 and u["username"] != "nobody":
                if u["shell"] in interactive_shells:
                    findings.append(self.create_finding(
                        id_="AEG-USR-006",
                        title=f"System account '{u['username']}' has interactive login shell",
                        severity="MEDIUM",
                        description=f"The system account '{u['username']}' (UID {u['uid']}) is configured with an active login shell ({u['shell']}). System accounts should be locked and prevented from logging in directly.",
                        evidence=f"User: {u['username']}, Shell: {u['shell']}",
                        remediation=f"Change the user shell to a non-interactive shell: usermod -s /usr/sbin/nologin {u['username']}",
                        references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.3"]
                    ))

        # 4. Sudoers audits
        sudoers_files = ["/etc/sudoers"]
        if os.path.exists("/etc/sudoers.d"):
            try:
                for entry in os.listdir("/etc/sudoers.d"):
                    full_path = os.path.join("/etc/sudoers.d", entry)
                    if os.path.isfile(full_path) and not entry.startswith("."):
                        sudoers_files.append(full_path)
            except Exception:
                pass

        for sf in sudoers_files:
            if os.path.exists(sf):
                try:
                    with open(sf, "r") as f:
                        content = f.read()
                        # Clean up comments and empty lines
                        lines = [line.strip() for line in content.split("\n") if line.strip() and not line.strip().startswith("#")]
                        for line in lines:
                            if "NOPASSWD" in line:
                                findings.append(self.create_finding(
                                    id_="AEG-USR-007",
                                    title=f"NOPASSWD entry in sudoers file",
                                    severity="HIGH",
                                    description=f"A sudoers directive in '{sf}' allows command execution without password verification. This bypasses a major layer of privilege security.",
                                    evidence=line,
                                    remediation=f"Modify '{sf}' to require passwords for privilege elevation unless strictly necessary.",
                                    references=["https://www.cisecurity.org/benchmark/debian_linux"],
                                    compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
                                ))
                            # Wildcard commands in privilege specification (e.g. ALL or *)
                            if "ALL" in line and ("ALL:ALL" in line or "ALL=(ALL" in line) and "ALL" in line.split(")")[-1]:
                                # General administrator rule, but flag if not root/admin groups
                                parts = line.split()
                                if parts and not parts[0].startswith("%") and parts[0] not in ("root", "admin", "sudo"):
                                    findings.append(self.create_finding(
                                        id_="AEG-USR-008",
                                        title=f"Broad wildcard privilege grant in sudoers",
                                        severity="MEDIUM",
                                        description=f"A non-standard user or rule '{parts[0]}' is granted full ALL privileges in '{sf}'. Privilege configuration should follow the principle of least privilege.",
                                        evidence=line,
                                        remediation="Audit sudoers rules and specify explicit command lists instead of ALL where possible.",
                                        references=[]
                                    ))
                except PermissionError:
                    # Log once
                    if sf == "/etc/sudoers":
                        findings.append(self.create_finding(
                            id_="AEG-USR-009",
                            title="Unable to read /etc/sudoers (Permission Denied)",
                            severity="INFO",
                            description="Lacks permissions to read sudoers files for configuration auditing.",
                            evidence="Permission Denied",
                            remediation="Run the scanner with elevated privileges."
                        ))
                except Exception as e:
                    pass

        # 5. Password expiry (chage -l)
        # Check standard human users (UID >= 1000, excluding nobody)
        human_users = [u["username"] for u in users if u["uid"] >= 1000 and u["username"] != "nobody"]
        if profile != "quick":  # Skip on quick profile to save time
            for uname in human_users[:15]:  # Limit to first 15 to avoid long execution times
                chage_out, _, _ = run_cmd(f"chage -l {uname}")
                if chage_out:
                    if "Password expires\t\t: never" in chage_out or "Password expires : never" in chage_out:
                        findings.append(self.create_finding(
                            id_="AEG-USR-010",
                            title=f"User password set to never expire",
                            severity="LOW",
                            description=f"The account '{uname}' has its password expiration set to 'never'. Regular password rotation mitigates the risk of credential compromise.",
                            evidence=f"User: {uname}\n{chage_out.splitlines()[0] if chage_out.splitlines() else ''}",
                            remediation=f"Set maximum password age for the user: chage -M 90 {uname}",
                            references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                            compliance=["PCI-DSS v4.0 8.2.1", "ISO27001:2022 A.5.17"]
                        ))

        # 6. World-writable home directories
        for u in users:
            if u["uid"] >= 1000 and u["username"] != "nobody":
                hpath = u["home"]
                if os.path.exists(hpath):
                    try:
                        stat_info = os.stat(hpath)
                        mode = stat_info.st_mode
                        # Check write permission for "others" (world-writable)
                        if mode & 0o002:
                            findings.append(self.create_finding(
                                    id_="AEG-USR-011",
                                    title=f"World-writable home directory for user '{u['username']}'",
                                    severity="HIGH",
                                    description=f"The home directory '{hpath}' for user '{u['username']}' is world-writable. Any user or compromised process on the system can modify files in this directory (e.g. .ssh/authorized_keys) to hijack the user session.",
                                    evidence=f"Path: {hpath}, Permissions: {oct(mode)[-3:]}",
                                    remediation=f"Restrict home directory permissions: chmod 700 {hpath}",
                                    references=["https://www.cisecurity.org/benchmark/debian_linux"],
                                    compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12"]
                                ))
                    except Exception:
                        pass

        # 7. Inactive human users 90+ days / Last login
        # Look at lastlog
        if os.path.exists("/usr/bin/lastlog") or os.path.exists("/bin/lastlog"):
            lastlog_out, _, _ = run_cmd("lastlog")
            if lastlog_out:
                for line in lastlog_out.splitlines()[1:]:
                    parts = line.split()
                    if not parts:
                        continue
                    uname = parts[0]
                    if uname in human_users:
                        # Check if user has **Never logged in** or check dates
                        if "**Never logged in**" in line:
                            findings.append(self.create_finding(
                                id_="AEG-USR-012",
                                title=f"User '{uname}' has never logged in",
                                severity="LOW",
                                description=f"The active user account '{uname}' has never logged in. Unused accounts increase the system's attack surface.",
                                evidence=line,
                                remediation=f"Disable the account if not needed: usermod -L {uname}",
                                references=[]
                            ))
                        else:
                            # Parse last login date (lastlog format typically has date at the end, e.g. "pts/0     10.0.2.2         Sun Jun 28 12:00:00 +0000 2026")
                            # We can check if it contains years or month and check if old
                            # A simple check: if the year listed in the lastlog output is less than current year - 1, or is old.
                            # We can also check 90+ days via a regex on year if it was e.g. 2024, 2025.
                            # Let's check for an old year like 2023/2024/2025 in the string
                            current_year = time.localtime().tm_year
                            for yr in range(2010, current_year):
                                if str(yr) in line:
                                    findings.append(self.create_finding(
                                        id_="AEG-USR-013",
                                        title=f"User '{uname}' has not logged in for 90+ days",
                                        severity="LOW",
                                        description=f"The user account '{uname}' has been inactive since {yr}. Inactive accounts should be disabled or deleted to prevent misuse.",
                                        evidence=line,
                                        remediation=f"Lock the inactive user account: usermod -L {uname}",
                                        references=[]
                                    ))
                                    break
                                    
        return findings
