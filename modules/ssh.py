import os
import re
from typing import List, Dict, Tuple
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class SSHModule(BaseModule):
    @property
    def name(self) -> str:
        return "ssh"

    @property
    def description(self) -> str:
        return "Audit SSH configuration, sshd_config hardening settings, and user key permissions"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        config_path = "/etc/ssh/sshd_config"
        
        # 1. Parse sshd_config
        config_values: Dict[str, str] = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        # Ignore comments or empty lines
                        if not line or line.startswith("#"):
                            continue
                        # Split on first whitespace
                        parts = line.split(maxsplit=1)
                        if len(parts) == 2:
                            key = parts[0].lower()
                            val = parts[1].strip()
                            config_values[key] = val
            except PermissionError:
                findings.append(self.create_finding(
                    id_="AEG-SSH-002",
                    title="Unable to read sshd_config (Permission Denied)",
                    severity="INFO",
                    description="Lacks permissions to read /etc/ssh/sshd_config for configuration analysis.",
                    evidence="Permission Denied",
                    remediation="Run the scanner as root/sudo to audit SSH configuration."
                ))
            except Exception as e:
                pass
        else:
            findings.append(self.create_finding(
                id_="AEG-SSH-003",
                title="sshd_config not found",
                severity="INFO",
                description="The SSH server configuration file /etc/ssh/sshd_config was not found. SSH server may not be installed.",
                evidence="",
                remediation="Ensure openssh-server is installed and configured if SSH services are required."
            ))
            return findings

        # Define checks: (config_key, expected_val, severity, description, id)
        ssh_checks: List[Tuple[str, str, str, str, str]] = [
            ("permitrootlogin", "no", "HIGH", "Root login is permitted via SSH. Root logins should be disabled to prevent brute force targeting and ensure auditability.", "AEG-SSH-004"),
            ("passwordauthentication", "no", "MEDIUM", "Password authentication is enabled. SSH logins should rely on strong key-based authentication only.", "AEG-SSH-005"),
            ("permitemptypasswords", "no", "CRITICAL", "Empty passwords are permitted. Accounts with blank passwords can log in to the system via SSH.", "AEG-SSH-006"),
            ("x11forwarding", "no", "LOW", "X11 forwarding is enabled. Malicious local users can hijack remote graphical sessions.", "AEG-SSH-007"),
            ("protocol", "2", "HIGH", "SSH Protocol 1 is enabled or not explicitly restricted to Protocol 2. Protocol 1 contains cryptographic vulnerabilities.", "AEG-SSH-008"),
            ("allowagentforwarding", "no", "LOW", "Agent forwarding is enabled. Compromised target systems can hijack the local SSH agent.", "AEG-SSH-009"),
            ("usepam", "yes", "MEDIUM", "PAM (Pluggable Authentication Modules) is disabled. Disabling PAM prevents login restrictions and MFA options.", "AEG-SSH-010"),
            ("allowtcpforwarding", "no", "LOW", "TCP forwarding is enabled. Allows users to tunnel traffic, potentially bypassing firewall rules.", "AEG-SSH-011")
        ]

        compliance_map = {
            "AEG-SSH-004": ["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"],
            "AEG-SSH-005": ["PCI-DSS v4.0 8.2.1", "ISO27001:2022 A.5.15"],
            "AEG-SSH-006": ["PCI-DSS v4.0 8.2.1", "ISO27001:2022 A.5.15"],
            "AEG-SSH-007": ["PCI-DSS v4.0 2.2.4"],
            "AEG-SSH-008": ["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.24"],
            "AEG-SSH-009": ["PCI-DSS v4.0 2.2.4"],
            "AEG-SSH-010": ["PCI-DSS v4.0 2.2.4"],
            "AEG-SSH-011": ["PCI-DSS v4.0 2.2.4"],
            "AEG-SSH-012": ["PCI-DSS v4.0 8.2.1"],
            "AEG-SSH-013": ["PCI-DSS v4.0 2.2.4"],
            "AEG-SSH-014": ["PCI-DSS v4.0 8.2.1", "ISO27001:2022 A.5.17", "CIS-Control 4.3"],
            "AEG-SSH-015": ["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.24"],
            "AEG-SSH-016": ["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12"],
            "AEG-SSH-017": ["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.24"],
        }

        for key, expected, severity, desc, check_id in ssh_checks:
            val = config_values.get(key, "").lower()
            
            # Helper to check if configuration value is unsafe
            is_unsafe = False
            if key == "permitrootlogin" and val not in ("no", "prohibit-password", "forced-commands-only") and val != "":
                is_unsafe = True
            elif key == "passwordauthentication" and val == "yes":
                is_unsafe = True
            elif key == "permitemptypasswords" and val == "yes":
                is_unsafe = True
            elif key == "x11forwarding" and val == "yes":
                is_unsafe = True
            elif key == "protocol" and val == "1":
                is_unsafe = True
            elif key == "allowagentforwarding" and val == "yes":
                is_unsafe = True
            elif key == "usepam" and val == "no":
                is_unsafe = True
            elif key == "allowtcpforwarding" and val == "yes":
                is_unsafe = True

            if is_unsafe:
                findings.append(self.create_finding(
                    id_=check_id,
                    title=f"Insecure SSH config: {key} set to '{config_values.get(key)}'",
                    severity=severity,
                    description=desc,
                    evidence=f"sshd_config: {key} {config_values.get(key)}",
                    remediation=f"Edit {config_path}, modify the line to '{key} {expected}', and reload sshd: sudo systemctl reload sshd",
                    references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                    compliance=compliance_map.get(check_id, [])
                ))

        # MaxAuthTries check
        max_auth = config_values.get("maxauthtries", "")
        if max_auth:
            try:
                ma_val = int(max_auth)
                if ma_val > 4:
                    findings.append(self.create_finding(
                        id_="AEG-SSH-012",
                        title=f"Insecure SSH config: MaxAuthTries is set to {ma_val}",
                        severity="LOW",
                        description="MaxAuthTries is set to greater than 4. High authentication retry limits ease brute-forcing SSH credentials.",
                        evidence=f"sshd_config: MaxAuthTries {ma_val}",
                        remediation="Set 'MaxAuthTries 4' (or lower) in sshd_config.",
                        references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                        compliance=compliance_map.get("AEG-SSH-012", [])
                    ))
            except ValueError:
                pass

        # LoginGraceTime check
        grace_time = config_values.get("logingracetime", "")
        if grace_time:
            try:
                secs = 0
                if grace_time.endswith("m"):
                    secs = int(grace_time[:-1]) * 60
                else:
                    secs = int(grace_time)
                if secs > 60:
                    findings.append(self.create_finding(
                        id_="AEG-SSH-013",
                        title=f"Insecure SSH config: LoginGraceTime is set to {grace_time}",
                        severity="LOW",
                        description="LoginGraceTime is set to greater than 60 seconds. Long authentication grace windows hold connections open, exposing the daemon to denial of service attacks.",
                        evidence=f"sshd_config: LoginGraceTime {grace_time}",
                        remediation="Set 'LoginGraceTime 60' in sshd_config.",
                        references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                        compliance=compliance_map.get("AEG-SSH-013", [])
                    ))
            except ValueError:
                pass

        # ClientAliveInterval check
        alive_int = config_values.get("clientaliveinterval", "")
        if not alive_int or alive_int == "0":
            findings.append(self.create_finding(
                id_="AEG-SSH-014",
                title="SSH idle timeout is not configured",
                severity="LOW",
                description="ClientAliveInterval is disabled or not set. Inactive SSH sessions will remain open indefinitely, increasing the risk of unauthorized session hijacking on unattended terminals.",
                evidence="sshd_config: ClientAliveInterval is missing or 0",
                remediation="Configure 'ClientAliveInterval 300' and 'ClientAliveCountMax 3' in sshd_config.",
                references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                compliance=compliance_map.get("AEG-SSH-014", [])
            ))

        # 2. Check SSH Host Key types (DSA check)
        dsa_keys_found = []
        host_key_dir = "/etc/ssh"
        if os.path.exists(host_key_dir):
            try:
                for entry in os.listdir(host_key_dir):
                    if "ssh_host_dsa_key" in entry:
                        dsa_keys_found.append(os.path.join(host_key_dir, entry))
            except Exception:
                pass

        if dsa_keys_found:
            findings.append(self.create_finding(
                id_="AEG-SSH-015",
                title="Legacy DSA SSH host keys present",
                severity="CRITICAL",
                description="DSA (Digital Signature Algorithm) host keys are present in /etc/ssh. DSA relies on 1024-bit key sizes and contains cryptographic weaknesses. Modern clients reject DSA.",
                evidence="\n".join(dsa_keys_found),
                remediation="Remove DSA host keys and configure sshd to use RSA (3072+ bits) or ED25519 keys: sudo rm /etc/ssh/ssh_host_dsa_key*",
                references=["https://www.openssh.com/legacy.html"],
                compliance=compliance_map.get("AEG-SSH-015", [])
            ))

        # 3. Audit User ~/.ssh and authorized_keys permissions
        bad_ssh_perms = []
        try:
            import pwd
            for u in pwd.getpwall():
                if u.pw_uid >= 1000 and u.pw_name != "nobody":
                    hdir = u.pw_dir
                    ssh_dir = os.path.join(hdir, ".ssh")
                    if os.path.exists(ssh_dir):
                        try:
                            s_stat = os.stat(ssh_dir)
                            s_mode = s_stat.st_mode & 0o777
                            if s_mode != 0o700:
                                bad_ssh_perms.append((ssh_dir, s_mode, 0o700))
                            
                            auth_keys = os.path.join(ssh_dir, "authorized_keys")
                            if os.path.exists(auth_keys):
                                k_stat = os.stat(auth_keys)
                                k_mode = k_stat.st_mode & 0o777
                                if k_mode != 0o600:
                                    bad_ssh_perms.append((auth_keys, k_mode, 0o600))
                        except Exception:
                            continue
        except Exception:
            pass

        for path, mode, expected in bad_ssh_perms:
            findings.append(self.create_finding(
                id_="AEG-SSH-016",
                title=f"Insecure permissions on SSH directory/file '{os.path.basename(path)}'",
                severity="HIGH",
                description=f"The SSH security resource '{path}' is configured with insecure permissions ({oct(mode)[-3:]}). It must be restricted to owner-only access to prevent unauthorized manipulation.",
                evidence=f"Path: {path}, Permissions: {oct(mode)[-3:]} (Expected: {oct(expected)[-3:]})",
                remediation=f"Correct permissions: chmod {oct(expected)[-3:]} {path}",
                references=["https://www.cisecurity.org/benchmark/debian_linux"],
                compliance=compliance_map.get("AEG-SSH-016", [])
            ))

        # 4. Weak ciphers/MACs in sshd_config
        weak_crypto = []
        for key in ["ciphers", "macs"]:
            val = config_values.get(key, "")
            if val:
                for weak in ["md5", "sha1", "3des", "blowfish", "arcfour", "cbc"]:
                    if weak in val.lower():
                        weak_crypto.append((key, val))
                        break

        for key, val in weak_crypto:
            findings.append(self.create_finding(
                id_="AEG-SSH-017",
                title=f"Weak cryptographic algorithms in SSH {key}",
                severity="HIGH",
                description=f"The SSH server configuration '{key}' includes weak cryptographic ciphers or MAC algorithms (e.g. CBC ciphers, MD5, SHA1). Attackers could exploit these to execute man-in-the-middle or session decryption attacks.",
                evidence=f"{key}: {val}",
                remediation="Configure strong cryptographic algorithms in sshd_config (e.g. Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com and MACs hmac-sha2-512-etm@openssh.com).",
                references=["https://www.sshaudit.com/hardening_guides.html"],
                compliance=compliance_map.get("AEG-SSH-017", [])
            ))

        return findings
