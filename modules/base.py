from abc import ABC, abstractmethod
from typing import List
from core.finding import Finding

class BaseModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Module system identifier name (e.g. 'os')"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """A friendly description of the scanning module."""
        pass

    @abstractmethod
    def run(self, profile: str = "standard") -> List[Finding]:
        """
        Executes vulnerability checks for this module.
        Profiles: 'quick', 'standard', 'deep'
        """
        pass

    def create_finding(
        self,
        id_: str,
        title: str,
        severity: str,
        description: str,
        evidence: str,
        remediation: str,
        references: List[str] = None,
        compliance: List[str] = None
    ) -> Finding:
        """Utility to construct a Finding bound to this module."""
        return Finding(
            id=id_,
            title=title,
            severity=severity,
            module=self.name,
            description=description,
            evidence=evidence,
            remediation=remediation,
            references=references or [],
            compliance=compliance or []
        )
