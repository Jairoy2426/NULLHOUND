import os
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd, has_binary

class FirewallModule(BaseModule):
    @property
    def name(self) -> str:
        return "firewall"

    @property
    def description(self) -> str:
        return "Detect and audit active firewalls (UFW, iptables, firewalld, nftables) and filtering policies"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        firewall_active = False
        active_firewall_name = "None"
        evidence_lines = []

        # 1. Check UFW
        if has_binary("ufw"):
            ufw_out, _, _ = run_cmd("ufw status verbose")
            if "Status: active" in ufw_out or "status: active" in ufw_out:
                firewall_active = True
                active_firewall_name = "UFW"
                evidence_lines.append(ufw_out.splitlines()[0])
                
                # Check default policies in UFW status
                if "Default: deny (incoming)" not in ufw_out and "Default: reject (incoming)" not in ufw_out:
                    findings.append(self.create_finding(
                        id_="AEG-FW-002",
                        title="UFW default incoming policy is not DENY/REJECT",
                        severity="MEDIUM",
                        description="UFW is active, but the default incoming traffic policy is not set to deny or reject. This means traffic is allowed by default unless blocked by an explicit rule.",
                        evidence=ufw_out,
                        remediation="Set default UFW policy to deny incoming: sudo ufw default deny incoming",
                        references=[],
                        compliance=["PCI-DSS v4.0 1.2.1", "ISO27001:2022 A.8.20", "CIS-Control 4.4"]
                    ))

        # 2. Check Firewalld (common on RHEL/CentOS/Fedora)
        if not firewall_active and has_binary("firewall-cmd"):
            fw_state, _, _ = run_cmd("firewall-cmd --state")
            if fw_state.strip() == "running":
                firewall_active = True
                active_firewall_name = "Firewalld"
                evidence_lines.append(f"Firewalld state: {fw_state.strip()}")

        # 3. Check iptables rules count and default policy
        if not firewall_active and has_binary("iptables"):
            # Requires root permissions to read rules
            rules_out, rules_err, exit_code = run_cmd("iptables -S")
            if exit_code == 0 and rules_out:
                # If there are rules defined beyond basic default policies
                lines = rules_out.splitlines()
                # Check for default policies
                policy_accept = False
                policy_count = 0
                filter_rules = 0
                for line in lines:
                    if line.startswith("-P"):
                        policy_count += 1
                        if "ACCEPT" in line:
                            policy_accept = True
                    elif line.startswith("-A"):
                        filter_rules += 1
                
                if filter_rules > 0:
                    firewall_active = True
                    active_firewall_name = "iptables"
                    evidence_lines.append(f"iptables active with {filter_rules} custom rules.")
                
                if policy_accept and filter_rules == 0:
                    findings.append(self.create_finding(
                        id_="AEG-FW-003",
                        title="iptables default policy is ACCEPT with zero filtering rules",
                        severity="CRITICAL",
                        description="The system uses iptables, but the default policy for incoming chains (INPUT, FORWARD) is set to ACCEPT, and there are no active filtering rules configured. This is equivalent to having no firewall.",
                        evidence=rules_out,
                        remediation="Configure default drop policies and restrict incoming connections.",
                        references=["https://www.cisecurity.org/benchmark/debian_linux"],
                        compliance=["PCI-DSS v4.0 1.2.1", "ISO27001:2022 A.8.20", "CIS-Control 4.4"]
                    ))
            elif "permission denied" in rules_err.lower():
                findings.append(self.create_finding(
                    id_="AEG-FW-004",
                    title="Lacks root privileges to read iptables rules",
                    severity="INFO",
                    description="The scanner could not check iptables policies due to missing root permissions.",
                    evidence=rules_err,
                    remediation="Run the scanner with root/sudo to audit raw iptables policies."
                ))

        # 4. Check nftables (modern iptables successor)
        if not firewall_active and has_binary("nft"):
            nft_out, _, exit_code = run_cmd("nft list ruleset")
            if exit_code == 0 and nft_out.strip():
                firewall_active = True
                active_firewall_name = "nftables"
                evidence_lines.append("nftables config is populated.")

        # 5. If no active firewall found
        if not firewall_active:
            findings.append(self.create_finding(
                id_="AEG-FW-001",
                title="No active firewall detected",
                severity="CRITICAL",
                description="The system does not have an active firewall configuration (UFW, Firewalld, iptables, or nftables). An unprotected system exposes all running network services directly to the network, increasing the risk of unauthorized access.",
                evidence="No active firewall rules or processes running.",
                remediation="Install and enable a firewall management utility: 'sudo apt install ufw && sudo ufw enable' or 'sudo dnf install firewalld && sudo systemctl enable --now firewalld'.",
                references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                compliance=["PCI-DSS v4.0 1.2.1", "ISO27001:2022 A.8.20", "CIS-Control 4.4"]
            ))

        # 6. Check localhost bypasses / public bindings
        # If firewall is disabled or not found, check if services are bound to 0.0.0.0 (exposed)
        # We can run ss/netstat and flag if we see sensitive ports bound to * or 0.0.0.0
        if not firewall_active and profile != "quick":
            ports_out, _, _ = run_cmd("ss -tuln")
            if ports_out:
                exposed_services = []
                for line in ports_out.splitlines():
                    # Look for LISTEN on 0.0.0.0 or [::]
                    if "LISTEN" in line and ("0.0.0.0:" in line or "*:" in line or "[::]:" in line):
                        # Extract port
                        match = re.search(r'[:\]](\d+)\s+', line)
                        if match:
                            port = int(match.group(1))
                            # Ignore common low-risk ports or dns, but flag sensitive ones
                            if port in [21, 22, 23, 80, 443, 3306, 5432, 6379, 8080]:
                                exposed_services.append(str(port))
                
                if exposed_services:
                    findings.append(self.create_finding(
                        id_="AEG-FW-005",
                        title="Sensitive services exposed publicly with no active firewall",
                        severity="HIGH",
                        description=f"Sensitive service ports ({', '.join(exposed_services)}) are bound to public interfaces (0.0.0.0 / [::]) on a host with no active firewall filtering traffic.",
                        evidence=f"Listening ports: {', '.join(exposed_services)}\n{ports_out}",
                        remediation="Configure the services to bind to localhost (127.0.0.1) if only needed locally, or enable the firewall immediately.",
                        references=[],
                        compliance=["PCI-DSS v4.0 1.2.1", "ISO27001:2022 A.8.20"]
                    ))

        return findings
