import os
from typing import List, Tuple
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class KernelModule(BaseModule):
    @property
    def name(self) -> str:
        return "kernel"

    @property
    def description(self) -> str:
        return "Evaluate kernel security flags, loaded modules, sysctl values, and core dump status"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Sysctl checks against CIS Benchmarks
        # Map parameter name to (proc_path, expected_value, comparison_operator, severity)
        sysctl_checks = [
            ("kernel.randomize_va_space", "kernel/randomize_va_space", 2, "==", "HIGH", 
             "Address Space Layout Randomization (ASLR) is disabled or not set to maximum randomization. This makes buffer overflow exploitation significantly easier."),
            ("kernel.dmesg_restrict", "kernel/dmesg_restrict", 1, "==", "MEDIUM", 
             "Unprivileged users can view kernel syslog messages (dmesg). This can leak kernel addresses or memory contents useful for local kernel exploits."),
            ("kernel.kptr_restrict", "kernel/kptr_restrict", 2, "==", "MEDIUM", 
             "Kernel pointer addresses are exposed to unprivileged users, defeating kernel ASLR."),
            ("kernel.yama.ptrace_scope", "kernel/yama/ptrace_scope", 1, ">=", "HIGH", 
             "Yama ptrace scope is set to unrestricted, allowing process memory reading/injection between users, enabling process hijacking."),
            ("net.ipv4.conf.all.rp_filter", "net/ipv4/conf/all/rp_filter", 1, "==", "MEDIUM", 
             "Reverse Path Filtering is disabled, making the system vulnerable to IP address spoofing attacks."),
            ("net.ipv4.tcp_syncookies", "net/ipv4/tcp_syncookies", 1, "==", "MEDIUM", 
             "TCP SYN cookies are disabled. The system is vulnerable to SYN flood denial of service attacks."),
            ("net.ipv4.conf.all.accept_redirects", "net/ipv4/conf/all/accept_redirects", 0, "==", "LOW", 
             "System accepts ICMP redirect messages, allowing attackers to route traffic via malicious routes."),
            ("net.ipv6.conf.all.accept_redirects", "net/ipv6/conf/all/accept_redirects", 0, "==", "LOW", 
             "IPv6 system accepts ICMP redirect messages, allowing routing redirection attacks."),
            ("net.ipv4.conf.all.send_redirects", "net/ipv4/conf/all/send_redirects", 0, "==", "LOW", 
             "System sends ICMP redirect messages. Hosts should only send redirects if they act as gateway routers."),
            ("fs.suid_dumpable", "fs/suid_dumpable", 0, "==", "LOW", 
             "SUID executables can write core dumps. Core dumps can contain plaintext passwords, API keys, or memory contents of sensitive processes.")
        ]

        for sysctl_name, proc_rel_path, expected, op, severity, desc in sysctl_checks:
            full_path = os.path.join("/proc/sys", proc_rel_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, "r") as f:
                        val_str = f.read().strip()
                        val = int(val_str)
                        
                        mismatch = False
                        if op == "==" and val != expected:
                            mismatch = True
                        elif op == ">=" and val < expected:
                            mismatch = True
                        
                        if mismatch:
                            findings.append(self.create_finding(
                                id_=f"AEG-KERN-{sysctl_name.replace('.', '-').upper()}",
                                title=f"Insecure kernel setting: {sysctl_name}",
                                severity=severity,
                                description=desc,
                                evidence=f"{sysctl_name} = {val} (Expected: {op} {expected})",
                                remediation=f"Add or update the setting in /etc/sysctl.conf: {sysctl_name} = {expected}, then load it: sudo sysctl -p",
                                references=["https://www.cisecurity.org/benchmark/ubuntu_linux"]
                            ))
                except Exception:
                    pass

        # 2. Check loaded kernel modules
        # Legacy/unsecure kernel modules that are frequently recommended to disable by CIS
        uncommon_modules = {
            "cramfs": "Obsolete compressed read-only filesystem, prone to privilege escalation",
            "freevxfs": "Legacy VxFS filesystem driver",
            "jffs2": "Obsolete flash memory filesystem driver",
            "hfs": "Legacy HFS filesystem driver",
            "hfsplus": "Legacy HFS+ filesystem driver",
            "udf": "Universal Disk Format driver (CD/DVD), rarely needed on secure servers",
            "dccp": "Datagram Congestion Control Protocol (potential network attack surface)",
            "sctp": "Stream Control Transmission Protocol (network attack surface if unused)",
            "rds": "Reliable Datagram Sockets driver (unneeded protocol)",
            "tipc": "Transparent Inter-Process Communication protocol (known remote kernel vulnerabilities)"
        }

        loaded_modules = []
        if os.path.exists("/proc/modules"):
            try:
                with open("/proc/modules", "r") as f:
                    for line in f:
                        parts = line.split()
                        if parts:
                            loaded_modules.append(parts[0])
            except Exception:
                pass

        for mod in loaded_modules:
            if mod in uncommon_modules:
                findings.append(self.create_finding(
                    id_=f"AEG-KERN-MOD-{mod.upper()}",
                    title=f"Uncommon/deprecated kernel module '{mod}' loaded",
                    severity="LOW",
                    description=f"The kernel module '{mod}' ({uncommon_modules[mod]}) is currently loaded. Disabling unused filesystems and network protocols limits the kernel's attack surface.",
                    evidence=f"Loaded module: {mod}",
                    remediation=f"Unload and blacklist the module: sudo modprobe -r {mod} && echo 'blacklist {mod}' | sudo tee /etc/modprobe.d/nullhound-{mod}.conf",
                    references=["https://www.cisecurity.org/benchmark/ubuntu_linux"]
                ))

        # 3. Check if core dumps are disabled in system limits
        core_dump_limited = False
        limits_conf = "/etc/security/limits.conf"
        if os.path.exists(limits_conf):
            try:
                with open(limits_conf, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        # Search for * hard core 0
                        if len(parts) >= 4 and parts[0] == "*" and parts[1] == "hard" and parts[2] == "core" and parts[3] == "0":
                            core_dump_limited = True
                            break
            except Exception:
                pass

        # If not disabled via limits, check if suid_dumpable was also not 0
        # If both are default/enabled, we flag
        if not core_dump_limited and profile != "quick":
            # Check if ulimit -c returns 0 (requires shell)
            ulimit_out, _, _ = run_cmd("ulimit -c")
            if ulimit_out and ulimit_out.strip() != "0":
                findings.append(self.create_finding(
                    id_="AEG-KERN-CORE-DUMP",
                    title="Core dumps are not restricted globally",
                    severity="LOW",
                    description="Core dumps are enabled for users. When an application crashes, it can write a dump containing sensitive memory contents to disk.",
                    evidence=f"ulimit -c: {ulimit_out.strip()}",
                    remediation="Restrict core dumps in /etc/security/limits.conf by adding: * hard core 0",
                    references=["https://www.cisecurity.org/benchmark/ubuntu_linux"]
                ))

        return findings
