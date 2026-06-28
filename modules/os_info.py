import os
import re
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd, is_root

class OSInfoModule(BaseModule):
    @property
    def name(self) -> str:
        return "os"

    @property
    def description(self) -> str:
        return "OS metadata, kernel updates, uptime and security context (SELinux/AppArmor)"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Check if scanner is running as root
        if not is_root():
            findings.append(self.create_finding(
                id_="AEG-OS-001",
                title="Scanner run without root privileges",
                severity="HIGH",
                description="The scanner is executed as a non-root user. Many system audits, configuration reviews, and security checks will fail or return incomplete results due to permission restrictions.",
                evidence=f"Running as UID {os.getuid()}",
                remediation="Run the vulnerability scanner with root privileges: sudo python3 nullhound.py",
                references=["https://github.com/nullhound-scanner/nullhound"],
                compliance=["PCI-DSS v4.0 2.2.3", "ISO27001:2022 A.8.12", "CIS-Control 5"]
            ))

        # 2. Parse OS Release Info
        distro, version, arch = "Unknown", "Unknown", "Unknown"
        arch_out, _, _ = run_cmd("uname -m")
        if arch_out:
            arch = arch_out

        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r") as f:
                    content = f.read()
                    name_match = re.search(r'^NAME=["\']?([^"\']+)["\']?', content, re.M)
                    ver_match = re.search(r'^VERSION_ID=["\']?([^"\']+)["\']?', content, re.M)
                    if name_match:
                        distro = name_match.group(1)
                    if ver_match:
                        version = ver_match.group(1)
            except Exception as e:
                findings.append(self.create_finding(
                    id_="AEG-OS-002",
                    title="Could not read /etc/os-release",
                    severity="INFO",
                    description=f"Error reading OS release file: {str(e)}",
                    evidence="",
                    remediation="Ensure permissions permit reading /etc/os-release.",
                    references=[]
                ))

        # 3. Kernel EOL check
        kernel_ver, _, _ = run_cmd("uname -r")
        if kernel_ver:
            # Check for EOL versions (e.g. < 4.19 are generally EOL or near EOL, or specific short-term versions)
            # Parse major.minor.patch
            match = re.match(r"^(\d+)\.(\d+)", kernel_ver)
            if match:
                major = int(match.group(1))
                minor = int(match.group(2))
                # Simple heuristic: version <= 4.14 is definitely EOL; version 5.x is LTS if 5.4, 5.10, 5.15. 
                # Let's say if major < 4 or (major == 4 and minor <= 14) or (major == 5 and minor in (1,2,3,5,6,7,8,9,11,12,13,14,16,17,18,19)):
                is_eol = False
                if major < 4:
                    is_eol = True
                elif major == 4 and minor < 19:
                    is_eol = True
                elif major == 5 and minor in {1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 18, 19}:
                    is_eol = True
                
                if is_eol:
                    findings.append(self.create_finding(
                        id_="AEG-OS-003",
                        title="End-of-Life (EOL) or non-LTS kernel detected",
                        severity="MEDIUM",
                        description=f"The current running Linux kernel version ({kernel_ver}) is obsolete, EOL, or a short-lived non-LTS release that no longer receives security updates.",
                        evidence=f"Kernel: {kernel_ver}",
                        remediation="Upgrade the system kernel to a supported Long-Term Support (LTS) release version (e.g. 5.15, 6.1, or 6.6+).",
                        references=["https://kernel.org/category/releases.html"],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.15", "CIS-Control 2.1"]
                    ))

        # 4. System Uptime and Reboot Status
        uptime_str, _, _ = run_cmd("uptime -p")
        last_reboot_str, _, _ = run_cmd("who -b")
        # If last reboot is older than e.g. 180 days, flag it
        uptime_sec = 0
        if os.path.exists("/proc/uptime"):
            try:
                with open("/proc/uptime", "r") as f:
                    uptime_sec = float(f.read().split()[0])
            except:
                pass
        
        if uptime_sec > (180 * 24 * 3600):  # 180 days
            findings.append(self.create_finding(
                id_="AEG-OS-004",
                title="System has very high uptime (reboot recommended)",
                severity="LOW",
                description="High system uptime indicates that security updates requiring a reboot (such as kernel updates or glibc updates) may have been applied but are not yet active.",
                evidence=f"Uptime: {uptime_str or (str(int(uptime_sec // 86400)) + ' days')}. Last reboot: {last_reboot_str}",
                remediation="Schedule a system reboot to apply pending kernel patches and library updates.",
                references=[],
                compliance=["PCI-DSS v4.0 2.2.4"]
            ))

        # 5. AppArmor / SELinux Status
        selinux_enabled = False
        apparmor_enabled = False
        
        # Check SELinux
        if os.path.exists("/usr/sbin/sestatus") or os.path.exists("/sbin/sestatus"):
            sel_out, _, _ = run_cmd("sestatus")
            if "enabled" in sel_out.lower():
                selinux_enabled = True
                if "permissive" in sel_out.lower():
                    findings.append(self.create_finding(
                        id_="AEG-OS-005",
                        title="SELinux in Permissive mode",
                        severity="MEDIUM",
                        description="SELinux is enabled but running in permissive mode, meaning violations are logged but not blocked. This weakens system sandboxing.",
                        evidence=sel_out,
                        remediation="Configure SELinux to Enforcing mode by editing /etc/selinux/config and running 'setenforce 1'.",
                        references=["https://wiki.gentoo.org/wiki/SELinux/Tutorials/Permissive_vs_Enforcing"],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.15", "CIS-Control 3"]
                    ))
        elif os.path.exists("/sys/fs/selinux"):
            # SELinux filesystem present
            selinux_enabled = True

        # Check AppArmor
        if os.path.exists("/sys/kernel/security/apparmor"):
            apparmor_enabled = True
            aa_status, _, _ = run_cmd("aa-status")
            if aa_status:
                if "0 profiles are in enforce mode" in aa_status or "apparmor module is loaded." in aa_status and "0 profiles" in aa_status:
                    findings.append(self.create_finding(
                        id_="AEG-OS-006",
                        title="AppArmor is enabled but has no active profiles",
                        severity="LOW",
                        description="AppArmor is loaded, but there are no profiles in enforce mode.",
                        evidence=aa_status.split('\n')[0] if aa_status else "",
                        remediation="Install or enable default profiles (e.g., sudo apt install apparmor-profiles).",
                        references=[],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.15"]
                    ))
            else:
                # AppArmor path exists but status check failed or missing tools
                pass
        
        if not selinux_enabled and not apparmor_enabled:
            findings.append(self.create_finding(
                id_="AEG-OS-007",
                title="No Mandatory Access Control (MAC) system is active",
                severity="HIGH",
                description="Neither AppArmor nor SELinux is active on this system. Mandatory Access Control limits the damage of potential compromises by strictly confining processes.",
                evidence="SELinux: Disabled, AppArmor: Disabled",
                remediation="Enable AppArmor (on Debian/Ubuntu systems) or SELinux (on RHEL/CentOS systems) through the kernel boot parameters or package manager.",
                references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.15", "CIS-Control 3.1"]
            ))

        return findings
