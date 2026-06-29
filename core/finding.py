from dataclasses import dataclass, field
from typing import List

CIS_BENCHMARKS = {
    "CIS 1.1.1": "Ensure mounting of unneeded filesystems is disabled",
    "CIS 1.2.1": "Ensure package manager repositories are configured / security updates applied",
    "CIS 1.2.2": "Ensure updates are applied / system rebooted",
    "CIS 1.5.1": "Ensure core dumps are restricted",
    "CIS 1.6.1": "Ensure a MAC system (SELinux/AppArmor) is active",
    "CIS 1.6.2": "Ensure AppArmor / SELinux is properly configured",
    "CIS 1.7.1": "Ensure OS release info is readable",
    "CIS 2.2.1": "Ensure legacy / unnecessary services are disabled",
    "CIS 3.1.1": "Ensure packet forwarding is disabled",
    "CIS 3.2.1": "Ensure source routed packets are not accepted",
    "CIS 3.5.1": "Ensure host firewall (UFW/IPtables) is active",
    "CIS 4.1.1": "Ensure auditd is installed and active",
    "CIS 4.2.1": "Ensure rsyslog is configured",
    "CIS 5.1.1": "Ensure cron daemon is configured and permissions are secure",
    "CIS 5.2.1": "Ensure sudo / root privileges are restricted",
    "CIS 5.2.2": "Ensure SSH configuration file permissions are secure",
    "CIS 5.2.3": "Ensure SSH directory permissions are configured",
    "CIS 5.2.4": "Ensure legacy SSH host keys are removed",
    "CIS 5.2.7": "Ensure SSH MaxAuthTries is set to 4 or less",
    "CIS 5.2.8": "Ensure SSH LoginGraceTime is set to one minute or less",
    "CIS 5.2.10": "Ensure SSH Root Login is disabled",
    "CIS 5.2.11": "Ensure SSH PasswordAuthentication is disabled",
    "CIS 5.2.12": "Ensure SSH PermitEmptyPasswords is disabled",
    "CIS 5.2.13": "Ensure SSH X11Forwarding is disabled",
    "CIS 5.2.14": "Ensure SSH Protocol 1 is disabled",
    "CIS 5.2.15": "Ensure SSH AllowAgentForwarding is disabled",
    "CIS 5.2.16": "Ensure SSH UsePAM is enabled",
    "CIS 5.2.17": "Ensure SSH AllowTcpForwarding is disabled",
    "CIS 5.2.18": "Ensure only approved ciphers are used",
    "CIS 5.2.19": "Ensure SSH Idle Timeout Interval is configured",
    "CIS 5.4.1": "Ensure password expiration is configured",
    "CIS 5.6": "Ensure root is the only UID 0 account",
    "CIS 6.1.1": "Ensure file / directory permissions are configured"
}

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    module: str
    description: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)
    compliance: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.compliance is None:
            self.compliance = []
        
        # Mapping rules
        cis_map = {
            "AEG-OS-001": "CIS 5.2.1",
            "AEG-OS-002": "CIS 1.7.1",
            "AEG-OS-003": "CIS 1.2.1",
            "AEG-OS-004": "CIS 1.2.2",
            "AEG-OS-005": "CIS 1.6.2",
            "AEG-OS-006": "CIS 1.6.2",
            "AEG-OS-007": "CIS 1.6.1",
            
            "AEG-SSH-002": "CIS 5.2.2",
            "AEG-SSH-003": "CIS 5.2.1",
            "AEG-SSH-004": "CIS 5.2.10",
            "AEG-SSH-005": "CIS 5.2.11",
            "AEG-SSH-006": "CIS 5.2.12",
            "AEG-SSH-007": "CIS 5.2.13",
            "AEG-SSH-008": "CIS 5.2.14",
            "AEG-SSH-009": "CIS 5.2.15",
            "AEG-SSH-010": "CIS 5.2.16",
            "AEG-SSH-011": "CIS 5.2.17",
            "AEG-SSH-012": "CIS 5.2.7",
            "AEG-SSH-013": "CIS 5.2.8",
            "AEG-SSH-014": "CIS 5.2.19",
            "AEG-SSH-015": "CIS 5.2.4",
            "AEG-SSH-016": "CIS 5.2.3",
            "AEG-SSH-017": "CIS 5.2.18",

            "AEG-FW-001": "CIS 3.5.1",
            "AEG-FW-002": "CIS 3.5.1",
            "AEG-FW-003": "CIS 3.5.1",
            "AEG-FW-004": "CIS 3.5.1",
            "AEG-FW-005": "CIS 3.5.1",

            "AEG-LOG-001": "CIS 4.1.1",
            "AEG-LOG-002": "CIS 4.1.1",
            "AEG-LOG-003": "CIS 4.1.1",
            "AEG-LOG-004": "CIS 4.1.1",
            "AEG-LOG-005": "CIS 4.2.1",
            "AEG-LOG-006": "CIS 4.2.1",
            "AEG-LOG-007": "CIS 4.2.1",

            "AEG-PKG-001": "CIS 1.2.1",
            "AEG-PKG-002": "CIS 1.2.1",
            "AEG-PKG-003": "CIS 1.2.1",
            "AEG-PKG-004": "CIS 1.2.1",
            "AEG-PKG-005": "CIS 1.2.1",
            "AEG-PKG-006": "CIS 1.2.1",

            "AEG-SRV-001": "CIS 2.2.1",
            "AEG-SRV-002": "CIS 2.2.1",
            "AEG-SRV-003": "CIS 2.2.1",
            "AEG-SRV-004": "CIS 2.2.1",
            "AEG-SRV-005": "CIS 2.2.1",
            "AEG-SRV-006": "CIS 2.2.1",

            "AEG-DKR-001": "CIS 1.1",
            "AEG-DKR-002": "CIS 1.1",
            "AEG-DKR-003": "CIS 1.1",
            "AEG-DKR-004": "CIS 1.1",
            "AEG-DKR-005": "CIS 1.1",
            "AEG-DKR-006": "CIS 1.1",
            "AEG-DKR-007": "CIS 1.1",

            "AEG-KERN-CORE-DUMP": "CIS 1.5.1",
        }
        
        # 1. Exact match lookup
        if self.id in cis_map:
            tag = cis_map[self.id]
            if tag not in self.compliance:
                self.compliance.append(tag)
        # 2. Pattern matches
        elif self.id.startswith("AEG-CRN-"):
            tag = "CIS 5.1.1"
            if tag not in self.compliance:
                self.compliance.append(tag)
        elif self.id.startswith("AEG-FS-"):
            tag = "CIS 6.1.1"
            if tag not in self.compliance:
                self.compliance.append(tag)
        elif self.id.startswith("AEG-USR-"):
            if self.id in ["AEG-USR-001", "AEG-USR-002", "AEG-USR-003"]:
                tag = "CIS 5.6"
            else:
                tag = "CIS 5.4.1"
            if tag not in self.compliance:
                self.compliance.append(tag)
        elif self.id.startswith("AEG-KERN-MOD-"):
            tag = "CIS 1.1.1"
            if tag not in self.compliance:
                self.compliance.append(tag)
        elif self.id.startswith("AEG-KERN-NET-"):
            if "FORWARD" in self.id or "IP_FORWARD" in self.id:
                tag = "CIS 3.1.1"
            else:
                tag = "CIS 3.2.1"
            if tag not in self.compliance:
                self.compliance.append(tag)
        elif self.id.startswith("AEG-VUL-"):
            tag = "CIS 1.2.1"
            if tag not in self.compliance:
                self.compliance.append(tag)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "compliance": self.compliance,
        }
