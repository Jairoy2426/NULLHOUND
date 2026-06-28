from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    id: str
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    module: str
    description: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)
    compliance: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "module": self.module,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "compliance": self.compliance,
        }
