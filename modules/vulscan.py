import os
import re
import socket
from typing import List, Dict, Tuple, Any
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class VulscanModule(BaseModule):
    @property
    def name(self) -> str:
        return "vulscan"

    @property
    def description(self) -> str:
        return "Perform service version detection and match local listeners against vulnerability catalogs (Vulscan)"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Identify active local listening TCP ports
        ports = self._get_listening_ports()
        if not ports:
            # No open TCP ports detected
            return findings

        # Offline vulnerability database mapping product name and version ranges to CVEs
        # Mimicking the scipvuldb.csv and cve.csv database mappings of Nmap Vulscan
        offline_db: List[Dict[str, Any]] = [
            {
                "product": "openssh",
                "max_version": "9.8p1",
                "min_version": "8.5p1",
                "cve": "CVE-2024-6387",
                "title": "OpenSSH regreSSHion Remote Code Execution Vulnerability",
                "severity": "CRITICAL",
                "description": "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime. This can lead to remote code execution as root.",
                "remediation": "Upgrade OpenSSH to version 9.8p1 or newer, or set LoginGraceTime to 0 in sshd_config.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387", "https://www.qualys.com/regresshion-cve-2024-6387/"]
            },
            {
                "product": "openssh",
                "max_version": "9.3p1",
                "min_version": "0.0",
                "cve": "CVE-2023-38408",
                "title": "OpenSSH Remote Code Execution via Agent Forwarding",
                "severity": "HIGH",
                "description": "A security vulnerability in OpenSSH ssh-agent allows remote code execution when agent forwarding is active and specific libraries are present on the client system.",
                "remediation": "Upgrade OpenSSH to 9.3p2 or disable SSH agent forwarding (AllowAgentForwarding no).",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]
            },
            {
                "product": "openssh",
                "max_version": "8.4p1",
                "min_version": "0.0",
                "cve": "CVE-2021-41617",
                "title": "OpenSSH Privilege Escalation via Helper Executables",
                "severity": "MEDIUM",
                "description": "OpenSSH sshd failed to drop supplemental groups when executing AuthorizedKeysCommand or AuthorizedPrincipalsCommand helpers, leading to privilege escalation.",
                "remediation": "Upgrade OpenSSH to version 8.5p1 or newer.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41617"]
            },
            {
                "product": "nginx",
                "max_version": "1.20.0",
                "min_version": "0.0",
                "cve": "CVE-2021-23017",
                "title": "Nginx Resolver Off-by-One Buffer Overflow",
                "severity": "HIGH",
                "description": "An off-by-one write vulnerability in the nginx DNS resolver allows a remote attacker to cause a 1-byte memory overwrite, potentially leading to denial of service or remote code execution.",
                "remediation": "Upgrade nginx to version 1.20.1 or newer.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]
            },
            {
                "product": "apache",
                "max_version": "2.4.48",
                "min_version": "2.4.49",  # Only specific version
                "cve": "CVE-2021-41773",
                "title": "Apache HTTP Server Path Traversal and File Disclosure",
                "severity": "CRITICAL",
                "description": "A path traversal vulnerability was found in Apache HTTP Server 2.4.49. An attacker could use path traversal to map URLs to files outside the document root.",
                "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or newer.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
            },
            {
                "product": "vsftpd",
                "max_version": "2.3.4",
                "min_version": "2.3.4",
                "cve": "CVE-2011-2523",
                "title": "vsftpd 2.3.4 Backdoor Command Execution",
                "severity": "CRITICAL",
                "description": "The vsftpd-2.3.4.tar.gz archive was replaced with a version containing a backdoor that opens a shell on port 6200 when a username ends with a smiley face ':)'",
                "remediation": "Uninstall vsftpd 2.3.4 or upgrade to a clean vsftpd package.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"]
            }
        ]

        # Connect to each port to grab banner
        for port in ports:
            banner = self._grab_banner(port)
            if not banner:
                continue

            product, version = self._parse_banner(banner, port)
            if not product:
                continue

            # 2. Perform database lookup
            matched = False
            for entry in offline_db:
                if entry["product"] == product.lower():
                    # Parse version logic
                    if self._version_match(version, entry["min_version"], entry["max_version"]):
                        matched = True
                        findings.append(self.create_finding(
                            id_=f"AEG-VUL-{entry['cve'].replace('-', '')}",
                            title=f"Service Vulnerability: {entry['title']} ({product} {version})",
                            severity=entry["severity"],
                            description=entry["description"],
                            evidence=f"Port: {port}, Banner: {banner}\nMatched Product: {product}, Detected Version: {version}",
                            remediation=entry["remediation"],
                            references=entry["references"],
                            compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.15", "CIS-Control 7"]
                        ))

            # 3. OSV API Fallback check (if online)
            if not matched and profile == "deep":
                osv_cve = self._query_osv_service(product, version)
                for item in osv_cve:
                    findings.append(self.create_finding(
                        id_=f"AEG-VUL-{item['id'].replace('-', '')}",
                        title=f"OSV Advisory: {item['summary']} ({product} {version})",
                        severity="HIGH",
                        description=item["details"],
                        evidence=f"Port: {port}, Banner: {banner}\nProduct: {product}, Version: {version}",
                        remediation=f"Upgrade {product} to the latest security patch version.",
                        references=[f"https://osv.dev/vulnerability/{item['id']}"],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.15"]
                    ))

        return findings

    def _get_listening_ports(self) -> List[int]:
        """Detect local active TCP listening ports using ss."""
        ports = []
        out, _, _ = run_cmd("ss -tuln")
        if out:
            for line in out.splitlines():
                if "LISTEN" in line:
                    match = re.search(r'[:\]](\d+)\s+', line)
                    if match:
                        port = int(match.group(1))
                        # Only scan common user/service ports to prevent locking
                        if port in [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080] and port not in ports:
                            ports.append(port)
        return ports

    def _grab_banner(self, port: int) -> str:
        """Connect to local socket on port and try to read initial welcome banner."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)  # Keep connection quick
        banner = ""
        try:
            s.connect(("127.0.0.1", port))
            
            # For HTTP ports, send request to force Server header
            if port in [80, 443, 8080]:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                resp = s.recv(1024).decode("utf-8", errors="ignore")
                for line in resp.splitlines():
                    if line.startswith("Server:"):
                        banner = line
                        break
            else:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
        finally:
            s.close()
        return banner

    def _parse_banner(self, banner: str, port: int) -> Tuple[str, str]:
        """Parse banner string to extract product name and version."""
        banner_clean = banner.lower()
        
        # OpenSSH
        # SSH-2.0-OpenSSH_8.4p1 Debian-5
        if "openssh" in banner_clean:
            match = re.search(r"openssh_([0-9\.]+[a-zA-Z0-9\-]*)", banner_clean)
            if match:
                return "openssh", match.group(1)
            return "openssh", "unknown"
            
        # Nginx
        # Server: nginx/1.18.0
        if "nginx" in banner_clean:
            match = re.search(r"nginx/([0-9\.]+)", banner_clean)
            if match:
                return "nginx", match.group(1)
            return "nginx", "unknown"
            
        # Apache
        # Server: Apache/2.4.41 (Ubuntu)
        if "apache" in banner_clean or "httpd" in banner_clean:
            match = re.search(r"apache/([0-9\.]+)", banner_clean)
            if match:
                return "apache", match.group(1)
            return "apache", "unknown"

        # vsFTPd
        if "vsftpd" in banner_clean:
            match = re.search(r"vsftpd\s*([0-9\.]+)", banner_clean)
            if match:
                return "vsftpd", match.group(1)
            return "vsftpd", "unknown"

        # Postfix
        if "postfix" in banner_clean or "esmtp" in banner_clean:
            return "postfix", "unknown"

        return "", ""

    def _version_match(self, ver: str, min_v: str, max_v: str) -> bool:
        """Basic software version range comparer."""
        if ver == "unknown":
            return True
            
        # Helper to convert version string into numerical tuple
        def parse_v(v_str: str) -> Tuple[int, ...]:
            # extract only digits and dots
            cleaned = re.sub(r"[^0-9\.]", "", v_str)
            parts = [int(p) for p in cleaned.split(".") if p]
            return tuple(parts)
            
        try:
            v_tup = parse_v(ver)
            min_tup = parse_v(min_v)
            max_tup = parse_v(max_v)
            
            return min_tup <= v_tup <= max_tup
        except Exception:
            return False

    def _query_osv_service(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Fallback online OSV query for service vulnerabilities."""
        if version == "unknown":
            return []
            
        try:
            import requests
            # Query OSV API for PyPI or general ecosystem, but for Debian services we can use Debian ecosystem
            # To simplify, we can search for the package name in Debian
            payload = {
                "package": {
                    "name": product,
                    "ecosystem": "Debian"
                },
                "version": version
            }
            res = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=3)
            if res.status_code == 200:
                vulns = res.json().get("vulns", [])
                results = []
                for v in vulns[:3]: # Return up to 3
                    results.append({
                        "id": v.get("id"),
                        "summary": v.get("summary", "Security Vulnerability"),
                        "details": v.get("details", "No description provided.")
                    })
                return results
        except Exception:
            pass
        return []
