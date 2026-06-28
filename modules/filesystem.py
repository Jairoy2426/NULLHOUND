import os
import stat
from typing import List, Tuple
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd

class FilesystemModule(BaseModule):
    @property
    def name(self) -> str:
        return "filesystem"

    @property
    def description(self) -> str:
        return "Audit file permissions, SUID/SGID binaries, sensitive file exposure, and mount options"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Check permissions on key files: passwd, shadow, sudoers
        self._check_file_perms(findings, "/etc/passwd", 0o644, "medium")
        self._check_file_perms(findings, "/etc/shadow", 0o640, "critical")
        self._check_file_perms(findings, "/etc/sudoers", 0o440, "high")
        self._check_file_perms(findings, "/etc/group", 0o644, "medium")
        self._check_file_perms(findings, "/etc/gshadow", 0o640, "high")

        # 2. Sticky bit check on /tmp and /var/tmp
        for tmp_dir in ["/tmp", "/var/tmp"]:
            if os.path.exists(tmp_dir):
                try:
                    stat_info = os.stat(tmp_dir)
                    mode = stat_info.st_mode
                    # Sticky bit is 0o1000
                    if not (mode & stat.S_ISVTX):
                        findings.append(self.create_finding(
                            id_="AEG-FS-001",
                            title=f"Missing sticky bit on '{tmp_dir}'",
                            severity="HIGH",
                            description=f"The temporary directory '{tmp_dir}' is writable by everyone but does not have the sticky bit set. This allows any user to delete or overwrite other users' files in this directory.",
                            evidence=f"Permissions: {oct(mode)[-3:]}",
                            remediation=f"Set the sticky bit: sudo chmod +t {tmp_dir}",
                            references=["https://www.cisecurity.org/benchmark/debian_linux"],
                            compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
                        ))
                except Exception:
                    pass

        # 3. Check /tmp mount options (noexec)
        # Parse /proc/mounts to find if /tmp is mounted with noexec, nosuid, nodev
        if os.path.exists("/proc/mounts"):
            try:
                with open("/proc/mounts", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[1] == "/tmp":
                            options = parts[3].split(",")
                            if "noexec" not in options:
                                findings.append(self.create_finding(
                                    id_="AEG-FS-002",
                                    title="/tmp partition is not mounted with 'noexec'",
                                    severity="LOW",
                                    description="The /tmp partition is not configured with 'noexec' in mount options. Staging and executing malware directly from temporary directories is a common attacker tactic.",
                                    evidence=line.strip(),
                                    remediation="Edit /etc/fstab and add 'noexec,nosuid,nodev' to the /tmp mount options, then remount.",
                                    references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                                    compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
                                ))
            except Exception:
                pass

        # 4. Scan for World-Writable files in system directories
        # To avoid performance issues, we scan only /etc, /usr/bin, /usr/sbin, /bin, /sbin
        # And limit recursion depth unless deep profile
        scan_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        ww_files = []
        try:
            for sdir in scan_dirs:
                if not os.path.exists(sdir):
                    continue
                # Traverse files
                for root, dirs, files in os.walk(sdir, followlinks=False):
                    # Limit depth for standard profiles to avoid hanging
                    depth = root.count(os.sep) - sdir.count(os.sep)
                    if profile == "quick" and depth > 1:
                        break
                    elif profile == "standard" and depth > 3:
                        break

                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            # Use lstat to avoid following symlinks
                            fstat = os.lstat(fpath)
                            if stat.S_ISREG(fstat.st_mode) and (fstat.st_mode & stat.S_IWOTH):
                                # World-writable regular file
                                ww_files.append((fpath, fstat.st_mode))
                        except Exception:
                            continue
        except Exception:
            pass

        if ww_files:
            # Group into a single finding to avoid spamming the table, but list the first few
            severity = "HIGH"
            etc_ww = [f[0] for f in ww_files if f[0].startswith("/etc")]
            if etc_ww:
                severity = "CRITICAL"
            
            findings.append(self.create_finding(
                id_="AEG-FS-003",
                title="World-writable system files detected",
                severity=severity,
                description="System binaries or configurations are world-writable. Any user can modify these files, leading to compromise of the system or local privilege escalation.",
                evidence=f"Total: {len(ww_files)} files. Sample files:\n" + "\n".join([f"{f[0]} ({oct(f[1])[-3:]})" for f in ww_files[:10]]),
                remediation="Remove write permissions for 'others' on these files: chmod o-w <file>",
                references=["https://www.cisecurity.org/benchmark/debian_linux"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
            ))

        # 5. SUID/SGID audit
        # Define a list of common/expected SUID binaries to reduce noise
        common_suids = {
            "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/chsh", "/usr/bin/chfn",
            "/usr/bin/gpasswd", "/usr/bin/newgrp", "/bin/ping", "/bin/mount",
            "/bin/umount", "/usr/lib/openssh/ssh-keysign", "/usr/bin/pkexec",
            "/usr/lib/policykit-1/polkit-agent-helper-1", "/usr/sbin/exim4",
            "/usr/bin/chage", "/usr/bin/expiry", "/usr/bin/sudoedit"
        }
        
        suid_found = []
        # Look in standard binary directories
        bin_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        for bdir in bin_dirs:
            if os.path.exists(bdir):
                try:
                    for entry in os.listdir(bdir):
                        fpath = os.path.join(bdir, entry)
                        if os.path.islink(fpath):
                            continue
                        try:
                            fstat = os.stat(fpath)
                            if stat.S_ISREG(fstat.st_mode):
                                if (fstat.st_mode & stat.S_ISUID) or (fstat.st_mode & stat.S_ISGID):
                                    if fpath not in common_suids:
                                        suid_found.append((fpath, fstat.st_mode))
                        except Exception:
                            continue
                except Exception:
                    pass

        if suid_found:
            findings.append(self.create_finding(
                id_="AEG-FS-004",
                title="Unusual SUID/SGID binary detected",
                severity="MEDIUM",
                description="An SUID or SGID binary was found that is not in the baseline of common/standard system binaries. SUID files run with owner permissions (often root) and are key targets for privilege escalation.",
                evidence="\n".join([f"{f[0]} (Perms: {oct(f[1])[-4:]})" for f in suid_found]),
                remediation="Verify if the SUID bit is necessary for these binaries. If not, remove it: sudo chmod u-s <file>",
                references=["https://attack.mitre.org/techniques/T1548/001/"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12"]
            ))

        # 6. Unowned files check (no user or group match)
        # Only check in /tmp and /var/tmp by default to prevent long sweeps
        unowned_dirs = ["/tmp", "/var/tmp"]
        if profile == "deep":
            unowned_dirs.extend(scan_dirs)
            
        unowned_found = []
        for udir in unowned_dirs:
            if os.path.exists(udir):
                try:
                    # Resolve system users/groups to check IDs
                    # We can use os.walk and look for files whose uid/gid do not exist
                    # Instead of parsing etc/passwd for every file, we can read all UIDs/GIDs once
                    import pwd, grp
                    all_uids = {u.pw_uid for u in pwd.getpwall()}
                    all_gids = {g.gr_gid for g in grp.getgrall()}
                    
                    for root, dirs, files in os.walk(udir):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            try:
                                fstat = os.lstat(fpath)
                                if fstat.st_uid not in all_uids or fstat.st_gid not in all_gids:
                                    unowned_found.append(fpath)
                            except Exception:
                                continue
                except Exception:
                    pass

        if unowned_found:
            findings.append(self.create_finding(
                id_="AEG-FS-005",
                title="Files with no owner or group configuration",
                severity="LOW",
                description="Files exist on the system whose UID or GID does not match any valid user or group. This can happen after deletion of users or extraction of tar archives, and can lead to access control issues if a new user is created with the old ID.",
                evidence=f"Total: {len(unowned_found)} files. Samples:\n" + "\n".join(unowned_found[:5]),
                remediation="Assign valid ownership to these files: chown root:root <file>",
                references=["https://www.cisecurity.org/benchmark/debian_linux"],
                compliance=["PCI-DSS v4.0 2.2.4"]
            ))

        # 7. Large files in /tmp (> 100MB)
        large_files = []
        if os.path.exists("/tmp"):
            try:
                for entry in os.listdir("/tmp"):
                    fpath = os.path.join("/tmp", entry)
                    try:
                        fstat = os.stat(fpath)
                        # 100MB is 100 * 1024 * 1024 bytes
                        if stat.S_ISREG(fstat.st_mode) and fstat.st_size > 100 * 1024 * 1024:
                            large_files.append((fpath, fstat.st_size))
                    except Exception:
                        continue
            except Exception:
                pass

        for lf, sz in large_files:
            findings.append(self.create_finding(
                id_="AEG-FS-006",
                title="Large file detected in /tmp partition",
                severity="LOW",
                description="A file larger than 100MB was found in /tmp. Large files in temporary directories can indicate staging of exfiltrated data or memory dumps containing sensitive info.",
                evidence=f"File: {lf}, Size: {sz // (1024*1024)} MB",
                remediation="Audit file contents to ensure they do not contain sensitive system data, and clean up if unnecessary.",
                references=[]
            ))

        # 8. Hidden directories in unusual locations (/, /etc, /usr, /boot)
        suspicious_hidden = []
        check_roots = ["/", "/etc", "/usr", "/boot"]
        for cr in check_roots:
            if os.path.exists(cr):
                try:
                    for entry in os.listdir(cr):
                        # Filter for directories starting with '.' and not '.' or '..'
                        if entry.startswith(".") and entry not in (".", "..", ".sys"):
                            dpath = os.path.join(cr, entry)
                            if os.path.isdir(dpath) and not os.path.islink(dpath):
                                suspicious_hidden.append(dpath)
                except Exception:
                    pass

        if suspicious_hidden:
            findings.append(self.create_finding(
                id_="AEG-FS-007",
                title="Hidden directory in sensitive path",
                severity="HIGH",
                description="A hidden directory was found directly in a sensitive root directory. Attackers often prefix backdoor folders with a '.' to hide them from simple listings.",
                evidence="\n".join(suspicious_hidden),
                remediation="Inspect the directory contents to ensure they are legitimate configurations or assets.",
                references=["https://attack.mitre.org/techniques/T1564/001/"],
                compliance=["PCI-DSS v4.0 2.2.4"]
            ))

        # 9. Legacy .rhosts or .netrc files in home directories
        # .rhosts enables host-based passwordless trust (highly insecure)
        # .netrc stores credentials in plaintext
        rhosts_netrc = []
        try:
            # Find human homes
            import pwd
            for u in pwd.getpwall():
                if u.pw_uid >= 1000 and u.pw_name != "nobody":
                    hdir = u.pw_dir
                    for bad_file in [".rhosts", ".netrc"]:
                        fpath = os.path.join(hdir, bad_file)
                        if os.path.exists(fpath):
                            rhosts_netrc.append((fpath, bad_file))
        except Exception:
            pass

        for fp, bf in rhosts_netrc:
            sev = "CRITICAL" if bf == ".rhosts" else "HIGH"
            desc = (
                "A legacy '.rhosts' file was found. This file permits authentication bypasses and host impersonation."
                if bf == ".rhosts" else
                "A '.netrc' file was found, containing plaintext credentials for FTP or auto-login protocols."
            )
            findings.append(self.create_finding(
                id_="AEG-FS-008",
                title=f"Legacy credential file {bf} present in home directory",
                severity=sev,
                description=desc,
                evidence=f"Path: {fp}",
                remediation=f"Delete the file immediately: rm {fp}",
                references=["https://en.wikipedia.org/wiki/Rhosts"],
                compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12"]
            ))

        # 10. World-readable sensitive files (private keys)
        # Search home directories for .pem, .key, id_rsa, id_dsa, id_ecdsa, id_ed25519
        keys_exposed = []
        try:
            import pwd
            for u in pwd.getpwall():
                if u.pw_uid >= 1000 and u.pw_name != "nobody":
                    hdir = u.pw_dir
                    ssh_dir = os.path.join(hdir, ".ssh")
                    if os.path.exists(ssh_dir):
                        for entry in os.listdir(ssh_dir):
                            fpath = os.path.join(ssh_dir, entry)
                            if os.path.isfile(fpath) and not os.path.islink(fpath):
                                # Check if it looks like a private key (doesn't end with .pub, not authorized_keys, not known_hosts)
                                if entry in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519") or entry.endswith(".key") or entry.endswith(".pem"):
                                    try:
                                        fstat = os.stat(fpath)
                                        # If readable by others
                                        if fstat.st_mode & 0o044:
                                            keys_exposed.append((fpath, fstat.st_mode))
                                    except Exception:
                                        continue
        except Exception:
            pass

        if keys_exposed:
            findings.append(self.create_finding(
                id_="AEG-FS-009",
                title="Exposed private key file (world-readable)",
                severity="CRITICAL",
                description="Private cryptographic keys (.key, .pem, or SSH private keys) are world-readable or group-readable. This allows local attackers to steal credentials and pivot to other systems.",
                evidence="\n".join([f"{f[0]} ({oct(f[1])[-3:]})" for f in keys_exposed]),
                remediation="Restrict permissions to the file owner: chmod 600 <key_file>",
                references=["https://csrc.nist.gov/glossary/term/private_key"],
                compliance=["PCI-DSS v4.0 8.2.1", "ISO27001:2022 A.8.24", "CIS-Control 5.4"]
            ))

        return findings

    def _check_file_perms(self, findings: List[Finding], path: str, max_mode: int, severity: str) -> None:
        if os.path.exists(path):
            try:
                stat_info = os.stat(path)
                mode = stat_info.st_mode & 0o777
                # If current mode has permissions not in max_mode
                # E.g. shadow is 644 (0o644) but max is 640 (0o640). 
                # (mode & ~max_mode) > 0 means there are extra permissions granted
                if (mode & ~max_mode) != 0:
                    findings.append(self.create_finding(
                        id_=f"AEG-FS-010",
                        title=f"Insecure permissions on '{path}'",
                        severity=severity.upper(),
                        description=f"The system configuration file '{path}' is configured with permissions {oct(mode)[-3:]}. The maximum secure value for this file is {oct(max_mode)[-3:]}. Overly permissive access allows unauthorized reading or tampering.",
                        evidence=f"Permissions: {oct(mode)[-3:]}, Expected: <= {oct(max_mode)[-3:]}",
                        remediation=f"Restore standard permissions: sudo chmod {oct(max_mode)[-3:]} {path}",
                        references=["https://www.cisecurity.org/benchmark/ubuntu_linux"],
                        compliance=["PCI-DSS v4.0 2.2.4", "ISO27001:2022 A.8.12", "CIS-Control 5.4"]
                    ))
            except Exception:
                pass
