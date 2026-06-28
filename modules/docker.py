import os
import json
from typing import List
from modules.base import BaseModule
from core.finding import Finding
from core.utils import run_cmd, has_binary

class DockerModule(BaseModule):
    @property
    def name(self) -> str:
        return "docker"

    @property
    def description(self) -> str:
        return "Audit container security, socket permissions, and container privilege isolation"

    def run(self, profile: str = "standard") -> List[Finding]:
        findings = []

        # 1. Skip gracefully if docker binary is not installed
        if not has_binary("docker"):
            return findings

        # 2. Check if Docker socket is accessible or daemon is running
        socket_path = "/var/run/docker.sock"
        if os.path.exists(socket_path):
            try:
                stat_info = os.stat(socket_path)
                mode = stat_info.st_mode
                # Check if writable by others (world-writable)
                if mode & 0o002:
                    findings.append(self.create_finding(
                        id_="AEG-DKR-001",
                        title="Docker socket is world-writable",
                        severity="CRITICAL",
                        description="The Docker socket (/var/run/docker.sock) is world-writable. Any local user can send raw API commands to the Docker daemon to spawn privileged containers and fully compromise the host system.",
                        evidence=f"Socket: {socket_path}, Permissions: {oct(mode)[-3:]}",
                        remediation="Restrict docker socket permissions to owner and docker group: sudo chmod 660 /var/run/docker.sock",
                        references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security"]
                    ))
            except Exception:
                pass

        # Check if daemon is active
        _, _, exit_code = run_cmd("docker info", timeout=5)
        if exit_code != 0:
            # Docker is installed but daemon is not running or current user lacks permissions
            findings.append(self.create_finding(
                id_="AEG-DKR-002",
                title="Docker daemon not running or inaccessible",
                severity="INFO",
                description="Docker binary is installed, but the daemon is not running or the current user cannot access it.",
                evidence="",
                remediation="Ensure Docker daemon is started: systemctl start docker (or run scanner as root/sudo)."
            ))
            return findings

        # 3. Inspect Running Containers
        # Fetch running container IDs
        container_ids_out, _, _ = run_cmd("docker ps -q")
        if container_ids_out:
            container_ids = container_ids_out.splitlines()
            
            # Inspect containers in detail
            # Limit depth for standard vs deep profiles
            max_containers = 10 if profile == "quick" else 50
            for cid in container_ids[:max_containers]:
                inspect_out, _, _ = run_cmd(f"docker inspect {cid}")
                if inspect_out:
                    try:
                        data = json.loads(inspect_out)
                        if data and isinstance(data, list):
                            container = data[0]
                            c_name = container.get("Name", "").lstrip("/")
                            
                            # A. Privileged Mode check
                            host_config = container.get("HostConfig", {})
                            if host_config.get("Privileged"):
                                findings.append(self.create_finding(
                                    id_="AEG-DKR-003",
                                    title=f"Container '{c_name}' running in privileged mode",
                                    severity="CRITICAL",
                                    description=f"The container '{c_name}' is running with privileged flag. This disables all namespace isolation and security profiles, allowing the container processes to escape to the host system.",
                                    evidence=f"Container: {c_name} (ID: {cid[:12]}), Privileged: True",
                                    remediation="Remove the '--privileged' flag from container startup options.",
                                    references=["https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities"]
                                ))

                            # B. Host Network Mode
                            net_mode = host_config.get("NetworkMode", "")
                            if net_mode == "host":
                                findings.append(self.create_finding(
                                    id_="AEG-DKR-004",
                                    title=f"Container '{c_name}' sharing host network namespace",
                                    severity="HIGH",
                                    description=f"The container '{c_name}' is running in host network mode. This exposes all network services of the host to the container and allows network sniffing of host traffic.",
                                    evidence=f"Container: {c_name}, NetworkMode: host",
                                    remediation="Use bridge networking or custom user-defined networks instead of '--net=host'.",
                                    references=["https://docs.docker.com/network/host/"]
                                ))

                            # C. Image 'latest' tag
                            image_name = container.get("Config", {}).get("Image", "")
                            if ":latest" in image_name or ":" not in image_name:
                                findings.append(self.create_finding(
                                    id_="AEG-DKR-005",
                                    title=f"Container '{c_name}' using unpinned 'latest' image tag",
                                    severity="LOW",
                                    description=f"The container '{c_name}' uses the image '{image_name}' which is not pinned to a specific version tag. This can pull untested updates, introducing vulnerabilities or breaking deployments.",
                                    evidence=f"Container: {c_name}, Image: {image_name}",
                                    remediation="Pin docker images to explicit version tags or digests (e.g. redis:7.0.12).",
                                    references=[]
                                ))

                            # D. Root user inside container
                            c_user = container.get("Config", {}).get("User", "")
                            # If blank, it defaults to the image default, which is usually root (UID 0)
                            if c_user in ("", "0", "root"):
                                findings.append(self.create_finding(
                                    id_="AEG-DKR-006",
                                    title=f"Container '{c_name}' executing as root user",
                                    severity="MEDIUM",
                                    description=f"The container '{c_name}' is running as the root user. If a process escape vulnerability occurs, the attacker immediately obtains root capabilities.",
                                    evidence=f"Container: {c_name}, Config.User: '{c_user}'",
                                    remediation="Configure the container to run under a non-privileged user (e.g. using USER node in Dockerfile or '--user 1000' at runtime).",
                                    references=["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"]
                                ))
                    except Exception:
                        pass

        # 4. Check if Docker remote daemon API is exposed without TLS
        # Inspect dockerd process parameters
        ps_out, _, _ = run_cmd("ps -ef")
        if ps_out:
            for line in ps_out.splitlines():
                if "dockerd" in line and "-H tcp://" in line:
                    if "tlsverify" not in line:
                        findings.append(self.create_finding(
                            id_="AEG-DKR-007",
                            title="Docker daemon remote API is exposed without TLS",
                            severity="CRITICAL",
                            description="The Docker daemon process appears to listen on a TCP port without TLS validation ('tlsverify'). Anyone on the network can execute commands, start containers, or compromise the host.",
                            evidence=line,
                            remediation="Enable TLS configuration: bind daemon with '--tlsverify' and supply certificates, or restrict listening to localhost.",
                            references=["https://docs.docker.com/engine/security/protect-access/"]
                        ))

        return findings
