import os
import re
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class NetworkModule(BaseModule):
    @property
    def name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Audit network interfaces, open ports, IP forwarding, ARP anomalies, and DNS resolution"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Open ports (parse ss -tulnp or netstat -tulnp)
        # Using ss since it's standard on modern Linux distros
        ports_out, ports_err, exit_code = run_cmd("ss -tulnp")
        if exit_code != 0:
            # Fallback to netstat
            ports_out, ports_err, exit_code = run_cmd("netstat -tulnp")

        dangerous_ports = {
            23: "Telnet (unencrypted terminal access)",
            512: "rexec (unencrypted remote execution)",
            513: "rlogin (unencrypted remote login)",
            514: "rsh (unencrypted remote shell)",
            2049: "NFS (Network File System - potentially unauthenticated)",
            6000: "X11 (unencrypted X Window System graphics access)"
        }

        found_ports = []
        if ports_out:
            lines = ports_out.splitlines()
            for line in lines[1:]:
                # Parse port from line
                # e.g., tcp LISTEN 0 128 0.0.0.0:22 ... or 127.0.0.1:23 ... or [::1]:23
                # We can use regex to find all port numbers after colons
                match = re.search(r'[:\]](\d+)\s+', line)
                if match:
                    port = int(match.group(1))
                    if port in dangerous_ports:
                        found_ports.append((port, line))
        
        # If ss/netstat not found or failed due to permission
        if "not found" in ports_err or "permission denied" in ports_err.lower():
            findings.append(self.create_finding(
                id_="AEG-NET-002",
                title="Could not audit open ports (command missing or permission denied)",
                severity="INFO",
                description="Unable to run 'ss' or 'netstat' with process listing. Open ports analysis was limited.",
                evidence=ports_err,
                remediation="Run the scanner as root to allow 'ss -tulnp' to read process bindings."
            ))

        for port, line in found_ports:
            findings.append(self.create_finding(
                id_=f"AEG-NET-001",
                title=f"Dangerous open port {port} ({dangerous_ports[port]}) detected",
                severity="HIGH",
                description=f"A historically insecure or dangerous port is open and listening. These services pass credentials in cleartext or have weak default authentication controls.",
                evidence=line,
                remediation=f"Disable the service binding to port {port} or configure it to listen on localhost only.",
                references=["https://www.rapid7.com/db/modules/"],
                compliance=["PCI-DSS v4.0 1.2.1", "ISO27001:2022 A.8.20", "CIS-Control 4.1"]
            ))

        # 2. IP Forwarding Check
        ip_fwd_path = "/proc/sys/net/ipv4/ip_forward"
        if os.path.exists(ip_fwd_path):
            try:
                with open(ip_fwd_path, "r") as f:
                    val = f.read().strip()
                    if val == "1":
                        findings.append(self.create_finding(
                            id_="AEG-NET-003",
                            title="IPv4 forwarding is enabled",
                            severity="MEDIUM",
                            description="IP forwarding is enabled. This allows the system to act as a router and route packets between different interfaces, which can be leveraged in man-in-the-middle attacks or network pivoting.",
                            evidence=f"ip_forward = {val}",
                            remediation="Disable IP forwarding by setting net.ipv4.ip_forward = 0 in /etc/sysctl.conf and running 'sysctl -p'.",
                            references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                            compliance=["PCI-DSS v4.0 1.2.1", "ISO27001:2022 A.8.20"]
                        ))
            except Exception:
                pass

        # 3. ARP cache anomalies (Duplicate MACs)
        arp_path = "/proc/net/arp"
        if os.path.exists(arp_path):
            try:
                macs = {}
                with open(arp_path, "r") as f:
                    lines = f.readlines()
                    # IP address       HW type     Flags       HW address            Mask     Device
                    # 10.0.2.2         0x1         0x2         52:54:00:12:35:02     *        eth0
                    for line in lines[1:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3]
                            if mac != "00:00:00:00:00:00":
                                if mac in macs:
                                    macs[mac].append(ip)
                                else:
                                    macs[mac] = [ip]
                
                # Check for duplicates
                for mac, ips in macs.items():
                    if len(ips) > 1:
                        findings.append(self.create_finding(
                            id_="AEG-NET-004",
                            title="Duplicate MAC address in ARP cache (possible ARP Spoofing)",
                            severity="HIGH",
                            description=f"The MAC address '{mac}' is associated with multiple IP addresses: {', '.join(ips)}. This could indicate an active ARP spoofing/poisoning attack on the local network.",
                            evidence=f"MAC {mac} mapped to IPs: {ips}",
                            remediation="Investigate network traffic for unauthorized ARP replies. Configure static ARP tables or implement Dynamic ARP Inspection (DAI) on the switch.",
                            references=["https://en.wikipedia.org/wiki/ARP_spoofing"]
                        ))
            except Exception:
                pass

        # 4. DNS config check (/etc/resolv.conf permissions and resolvers)
        resolv_path = "/etc/resolv.conf"
        if os.path.exists(resolv_path):
            try:
                stat_info = os.stat(resolv_path)
                mode = stat_info.st_mode
                if mode & 0o002: # World-writable
                    findings.append(self.create_finding(
                        id_="AEG-NET-005",
                        title="DNS configuration file is world-writable",
                        severity="CRITICAL",
                        description=f"'/etc/resolv.conf' is world-writable. Any local user can change the system's DNS servers to point to a rogue DNS resolver, leading to traffic interception.",
                        evidence=f"Permissions: {oct(mode)[-3:]}",
                        remediation="Change permissions to 644: chmod 644 /etc/resolv.conf",
                        references=[],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 4.3"]
                    ))

                # Check resolvers
                with open(resolv_path, "r") as f:
                    resolvers = []
                    for line in f:
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                resolvers.append(parts[1])
                    
                    if not resolvers:
                        findings.append(self.create_finding(
                            id_="AEG-NET-006",
                            title="No DNS resolvers configured",
                            severity="LOW",
                            description="No active nameservers were found in /etc/resolv.conf. System may not be able to resolve domain names.",
                            evidence="No 'nameserver' lines found",
                            remediation="Add valid nameservers to /etc/resolv.conf."
                        ))
            except Exception:
                pass

        # 5. Check /etc/hosts for suspicious mappings
        hosts_path = "/etc/hosts"
        if os.path.exists(hosts_path):
            try:
                with open(hosts_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            hostnames = parts[1:]
                            # Check if localhost is mapped to an external IP
                            if "localhost" in hostnames and not (ip.startswith("127.") or ip == "::1"):
                                findings.append(self.create_finding(
                                    id_="AEG-NET-007",
                                    title="Localhost mapped to non-loopback IP in hosts file",
                                    severity="HIGH",
                                    description=f"The host name 'localhost' is mapped to an external or non-loopback IP address '{ip}'. This can redirect local service traffic over the network or cause authentication failures.",
                                    evidence=line,
                                    remediation=f"Edit /etc/hosts and ensure localhost points to 127.0.0.1 or ::1.",
                                    references=[]
                                ))
            except Exception:
                pass

        # 6. Active foreign IP connections on sensitive ports
        # E.g. ESTABLISHED connections to public IPs on ports like 22, 23, 4444 (common metasploit), etc.
        if profile == "deep":
            conn_out, _, _ = run_cmd("ss -atn")
            if conn_out:
                for line in conn_out.splitlines():
                    if "ESTAB" in line:
                        # Check for suspicious outbound ports or reverse shells
                        # e.g., tcp ESTAB 0 0 10.0.2.15:39281 198.51.100.4:4444
                        parts = line.split()
                        if len(parts) >= 5:
                            local = parts[3]
                            foreign = parts[4]
                            # Check if foreign is non-private, and if port is typical for reverse shells
                            # E.g., if port is 4444, 1337, 6667
                            if ":4444" in foreign or ".4444" in foreign or ":1337" in foreign or ".1337" in foreign:
                                findings.append(self.create_finding(
                                    id_="AEG-NET-008",
                                    title="Suspicious active connection on shell port",
                                    severity="CRITICAL",
                                    description=f"An active connection was detected to a suspicious port (e.g. 4444, 1337). This is highly indicative of an active reverse shell or command & control channel.",
                                    evidence=line,
                                    remediation="Investigate the process holding this socket immediately: netstat -apn or lsof -i",
                                    references=[],
                                    compliance=["PCI-DSS v4.0 10.2.1", "ISO27001:2022 A.8.16"]
                                ))
                                
        return findings
