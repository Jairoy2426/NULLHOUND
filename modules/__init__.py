from .os_info import OSInfoModule
from .users import UsersModule
from .network import NetworkModule
from .services import ServicesModule
from .filesystem import FilesystemModule
from .kernel import KernelModule
from .packages import PackagesModule
from .docker import DockerModule
from .cron import CronModule
from .ssh import SSHModule
from .firewall import FirewallModule
from .logs import LogsModule
from .vulscan import VulscanModule

ALL_MODULES = {
    "os": OSInfoModule,
    "users": UsersModule,
    "network": NetworkModule,
    "services": ServicesModule,
    "filesystem": FilesystemModule,
    "kernel": KernelModule,
    "packages": PackagesModule,
    "docker": DockerModule,
    "cron": CronModule,
    "ssh": SSHModule,
    "firewall": FirewallModule,
    "logs": LogsModule,
    "vulscan": VulscanModule,
}
