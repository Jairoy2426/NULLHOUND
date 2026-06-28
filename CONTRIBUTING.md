# Contributing to NULLHOUND

Thank you for your interest in contributing to **NULLHOUND**! We welcome contributions that improve security auditing checks, enhance the user experience, fix bugs, or expand documentation.

---

## Table of Contents
1. [General Guidelines](#general-guidelines)
2. [How to Add a Scanning Module](#how-to-add-a-scanning-module)
3. [Coding Style & Best Practices](#coding-style--best-practices)
4. [Creating a Pull Request](#creating-a-pull-request)

---

## General Guidelines

- **Respect Scope**: NULLHOUND is designed as a localized Linux security auditor/configuration scanner. Network-wide scanning or heavy remote checks are out of scope.
- **Safety First**: Ensure your audits do not perform destructive actions on target hosts.
- **No Dependencies**: Keep external dependencies minimal. Use built-in modules or the standard library unless absolutely necessary.

---

## How to Add a Scanning Module

NULLHOUND is designed to be highly modular. Follow these steps to implement a new scan module:

### Step 1: Create the Module File
Create a new file in `modules/` (e.g., `modules/my_module.py`).

### Step 2: Implement the Module Class
Inherit from the `BaseModule` abstract base class and implement the required properties and methods:

```python
from typing import List
from modules.base import BaseModule
from core.finding import Finding

class MyCustomModule(BaseModule):
    @property
    def name(self) -> str:
        """The command line identifier for the module."""
        return "custom"

    @property
    def description(self) -> str:
        """A brief description of what this module audits."""
        return "Audits custom application security baselines"

    def run(self, profile: str = "standard") -> List[Finding]:
        """
        Executes audit checks.
        Profiles: 'quick', 'standard', or 'deep' control time limit/depth.
        """
        findings = []
        
        # Example check
        # status, stdout, stderr = run_cmd("some_command")
        # if is_vulnerable:
        #     findings.append(self.create_finding(
        #         id_="AEG-CST-001",
        #         title="Custom Vulnerability Found",
        #         severity="MEDIUM",
        #         description="Details about the vulnerability.",
        #         evidence="Raw evidence/output",
        #         remediation="Step to resolve the issue",
        #         references=["https://link-to-cve-or-reference"]
        #     ))
        
        return findings
```

### Step 3: Register the Module
Open `modules/__init__.py` and import/register your new class in the `ALL_MODULES` dictionary:

```python
from .my_module import MyCustomModule

ALL_MODULES = {
    # ... existing modules
    "custom": MyCustomModule
}
```

---

## Coding Style & Best Practices

- **Formatting**: Please adhere to standard PEP 8 formatting rules.
- **Type Hints**: Always use type annotations for arguments and return types.
- **Exception Safety**: Wrap commands or file readings in exception blocks (or use the built-in safety of helpers like `run_cmd`) to prevent crashes when directories/commands are missing.
- **No Hardcoded Credentials**: Do not include private tokens, keys, or credentials.

---

## Creating a Pull Request

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-new-module`.
3. Commit your changes: `git commit -m "feat: add custom vulnerability scanning module"`.
4. Push to the branch: `git push origin feature/my-new-module`.
5. Open a Pull Request on GitHub.
