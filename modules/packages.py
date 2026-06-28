import os
import json
import re
from typing import List, Dict, Any
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd, has_binary

class PackagesModule(BaseModule):
    @property
    def name(self) -> str:
        return "packages"

    @property
    def description(self) -> str:
        return "Audit package updates, third-party repositories, dual-use tools, and pip vulnerabilities via OSV API"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Detect Package Manager & Security Updates
        pkg_manager = None
        upgradable_security_count = 0
        
        if has_binary("apt-get"):
            pkg_manager = "apt"
            # Fast check: run apt-get -s upgrade and look for security repository keywords
            # Using timeout=10 to avoid blocking
            apt_out, _, _ = run_cmd("apt-get -s dist-upgrade", timeout=10)
            if apt_out:
                # Count packages with 'security' or 'updates' in the repository origin
                # Standard upgradable line: Inst package (version [origin])
                # We count matches of security source
                security_matches = re.findall(r"^Inst\s+\S+\s+\[([^\]]+)\]", apt_out, re.M)
                for match in security_matches:
                    if "security" in match.lower() or "vuln" in match.lower():
                        upgradable_security_count += 1
        elif has_binary("dnf"):
            pkg_manager = "dnf"
            # dnf check-update --security returns 100 if updates are available, 0 if none, 1 on error
            dnf_out, _, code = run_cmd("dnf check-update --security", timeout=10)
            if code == 100 and dnf_out:
                # Count lines indicating security updates
                upgradable_security_count = len([line for line in dnf_out.splitlines() if line.strip() and not line.startswith("Last metadata")])
        elif has_binary("yum"):
            pkg_manager = "yum"
            yum_out, _, code = run_cmd("yum check-update --security", timeout=10)
            if code == 100 and yum_out:
                upgradable_security_count = len([line for line in yum_out.splitlines() if line.strip()])
        elif has_binary("pacman"):
            pkg_manager = "pacman"
            # Pacman does not classify updates by security specifically; check general upgrades
            pac_out, _, _ = run_cmd("pacman -Qu", timeout=10)
            if pac_out:
                upgradable_security_count = len(pac_out.splitlines())

        if upgradable_security_count > 0:
            findings.append(self.create_finding(
                id_="AEG-PKG-001",
                title=f"Pending security updates available ({upgradable_security_count})",
                severity="HIGH",
                description=f"The system has {upgradable_security_count} pending security updates. Failing to apply security updates exposes the system to known public exploits.",
                evidence=f"Package Manager: {pkg_manager}, Security Updates: {upgradable_security_count}",
                remediation=f"Apply system updates: " + ("sudo apt-get update && sudo apt-get upgrade -y" if pkg_manager == "apt" else "sudo dnf upgrade --security -y"),
                references=["https://www.cisa.gov/news-events/alerts/2023/10/24/cisa-releases-guidance-addressing-software-vulnerabilities"]
            ))

        # 2. Check for third-party / non-standard repositories (APT specific example)
        if pkg_manager == "apt":
            sources_d = "/etc/apt/sources.list.d"
            ppa_found = []
            if os.path.exists(sources_d):
                try:
                    for entry in os.listdir(sources_d):
                        if entry.endswith(".list") or entry.endswith(".sources"):
                            full_path = os.path.join(sources_d, entry)
                            with open(full_path, "r") as f:
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith("#"):
                                        if "ppa.launchpad" in line or "http" in line and not any(k in line for k in ["ubuntu.com", "debian.org", "canonical.com"]):
                                            ppa_found.append((entry, line))
                except Exception:
                    pass
            
            if ppa_found and profile != "quick":
                findings.append(self.create_finding(
                    id_="AEG-PKG-002",
                    title="Third-party package repositories configured",
                    severity="LOW",
                    description="The system configures third-party repositories or PPAs. Software installed from these repositories bypasses the core distribution's security vetting, exposing the system to supply chain attacks.",
                    evidence="\n".join([f"{f[0]}: {f[1][:80]}" for f in ppa_found[:5]]),
                    remediation="Audit configured software sources and remove unnecessary PPAs or external repositories.",
                    references=[]
                ))

        # 3. Detect known dangerous/dual-use tools
        dual_use_tools = {
            "nmap": "Network discovery and vulnerability scanning tool",
            "nc": "Netcat (arbitrary TCP/UDP connections and listening)",
            "netcat": "Netcat (arbitrary TCP/UDP connections and listening)",
            "socat": "Socket cat (multipurpose relay utility)",
            "john": "John the Ripper (password cracker)",
            "hydra": "THC-Hydra (network login cracker)",
            "tcpdump": "Network packet analyzer",
            "wireshark": "Graphical network packet analyzer",
            "sqlmap": "SQL injection exploit tool",
            "msfconsole": "Metasploit framework console"
        }

        installed_tools = []
        for tool, desc in dual_use_tools.items():
            if has_binary(tool):
                installed_tools.append((tool, desc))

        if installed_tools:
            findings.append(self.create_finding(
                id_="AEG-PKG-003",
                title="Dual-use or penetration testing tools present",
                severity="INFO",
                description="Penetration testing or dual-use network utility programs are installed on the system. While useful for administration, their presence can be leveraged by attackers who gain system access.",
                evidence="\n".join([f"{t[0]}: {t[1]}" for t in installed_tools]),
                remediation="Ensure these utilities are strictly restricted to system administrators or remove them if unused.",
                references=["https://attack.mitre.org/software/"]
            ))

        # 4. Pip scan via OSV API
        if has_binary("pip") or has_binary("pip3"):
            # Skip pip checks on quick profile, limit depth
            if profile != "quick":
                pip_bin = "pip" if has_binary("pip") else "pip3"
                pip_out, _, _ = run_cmd(f"{pip_bin} list --format=json", timeout=10)
                
                if pip_out:
                    try:
                        pip_pkgs = json.loads(pip_out)
                        # Build queries list for OSV querybatch
                        queries = []
                        for pkg in pip_pkgs:
                            name = pkg.get("name")
                            version = pkg.get("version")
                            if name and version:
                                queries.append({
                                    "package": {
                                        "name": name,
                                        "ecosystem": "PyPI"
                                    },
                                    "version": version
                                })

                        # Perform OSV query batch request (Max 100 packages to stay safe)
                        if queries:
                            queries = queries[:100]
                            try:
                                import requests
                                response = requests.post(
                                    "https://api.osv.dev/v1/querybatch",
                                    json={"queries": queries},
                                    headers={"Content-Type": "application/json"},
                                    timeout=10
                                )
                                if response.status_code == 200:
                                    results = response.json().get("results", [])
                                    vuln_count = 0
                                    vuln_details = []
                                    
                                    for idx, res in enumerate(results):
                                        vulns = res.get("vulns", [])
                                        if vulns:
                                            pkg_name = queries[idx]["package"]["name"]
                                            pkg_ver = queries[idx]["version"]
                                            vuln_count += len(vulns)
                                            # Grab CVE or OSV IDs
                                            for v in vulns[:2]: # Show up to 2 per package
                                                aliases = ", ".join(v.get("aliases", []))
                                                vuln_details.append(f"{pkg_name} ({pkg_ver}): {v.get('id')} ({aliases}) - {v.get('summary', 'No summary available')}")

                                    if vuln_count > 0:
                                        findings.append(self.create_finding(
                                            id_="AEG-PKG-004",
                                            title=f"Vulnerable python pip packages detected ({vuln_count} vulnerabilities)",
                                            severity="HIGH",
                                            description="One or more installed Python pip packages have known CVE security vulnerabilities listed in the OSV database.",
                                            evidence="\n".join(vuln_details[:10]),
                                            remediation="Upgrade vulnerable packages using 'pip install --upgrade <package_name>'.",
                                            references=["https://osv.dev"]
                                        ))
                            except ImportError:
                                findings.append(self.create_finding(
                                    id_="AEG-PKG-005",
                                    title="Pip CVE scan skipped (requests module missing)",
                                    severity="INFO",
                                    description="The 'requests' module is missing. NULLHOUND could not contact the OSV API to scan pip packages.",
                                    evidence="ImportError",
                                    remediation="Install the requests library: pip install requests"
                                ))
                            except Exception as e:
                                findings.append(self.create_finding(
                                    id_="AEG-PKG-006",
                                    title="OSV API connection failed",
                                    severity="INFO",
                                    description=f"Could not connect to OSV API: {str(e)}",
                                    evidence="API Request Error",
                                    remediation="Ensure internet connectivity and verify proxy settings."
                                ))
                    except Exception:
                        pass

        return findings
