# 🛡️ NULLHOUND (Automated Enumeration & Guided Intelligence Scanner)

> [!NOTE]
> **Strictly for Educational Purposes** — Developed as a cybersecurity portfolio demonstration.  
> **Author / Developer**: Made By Hercules

**NULLHOUND** is a professional, terminal-only Linux vulnerability scanner and security configuration auditor written in Python. It is designed to perform localized checks covering system configurations, network exposures, filesystem permissions, user access patterns, kernel settings, and running services against hardening standards like the CIS Benchmarks.

---

## 📸 Screenshots

### Interactive Terminal Audit Interface
![Interactive Terminal Audit](https://img.herculesdev.in/u/JzLy2R.png)

### Self-Contained HTML Security Report Dashboard
![HTML Security Report Dashboard](https://img.herculesdev.in/u/3i0b0d.png)

---

## 🚀 Key Features

*   **100% Terminal-Only & Interactive**: Utilizes `rich` for panels, live progress spinners, colored tables, and clean dashboard outputs.
*   **Fully Parallelized**: Threaded execution model runs audit checks in parallel with configurable concurrency.
*   **Robust & Exception Safe**: Handles missing binaries, permission denied errors, and timeouts without crashing.
*   **Flexible Reporting**: Generates reports in structured **JSON**, plain readable **TXT**, and premium self-contained **HTML** dashboards (with built-in dark mode).
*   **Check Profiles**: Run `quick`, `standard`, or `deep` sweeps controlling check depth and timeouts.

---

## 🛠️ Installation & Setup

1.  **Clone or Copy** the repository onto your target Linux host:
    ```bash
    git clone https://github.com/your-username/nullhound.git
    cd nullhound
    ```

2.  **Install dependencies** using pip:
    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Make the entry point executable**:
    ```bash
    chmod +x nullhound.py
    ```

---

## 📖 Usage Examples

Since some security auditing commands (e.g. inspecting `/etc/shadow`, parsing network interface binding processes) require root, running as root is highly recommended.

### 1. Standard Audit Scan (All Modules)
Runs the default suite of audits on the host using standard depth:
```bash
sudo ./nullhound.py
```

### 2. Specific Modules with High Concurrency
Audit only the SSH and network configurations using 8 worker threads:
```bash
sudo ./nullhound.py --modules ssh,network --threads 8
```

### 3. Generate HTML & JSON Security Reports
Generate an interactive, styled dark-mode HTML dashboard and structured JSON outputs:
```bash
sudo ./nullhound.py --output report.html
sudo ./nullhound.py --output report.json
```

### 4. Deep Profile, Quiet and Plain-Text (for CI/CD pipelines)
Quietly run a deep profile scan, filtering out anything below HIGH severity, disabled color codes, and redirect output to a file:
```bash
sudo ./nullhound.py --profile deep --severity high --quiet --no-color > audit_output.txt
```

---

## 📊 Comparison Table: NULLHOUND vs Lynis vs OpenVAS

| Feature | **NULLHOUND** (Custom) | **Lynis** | **OpenVAS** |
| :--- | :--- | :--- | :--- |
| **Audit Focus** | Local system hardening & configuration audit | Local system configuration audit | Remote network vulnerability scanning |
| **Installation** | Single directory, simple pip dependencies | Shell script, package manager | Heavy services setup, database, Redis |
| **Execution Speed** | Very Fast (Parallelized Threads) | Fast (Sequential Shell scripts) | Slow (Network sweeping & port scanning) |
| **Report UI** | High-fidelity interactive HTML/Console | Plain text log & report file | Web UI, PDF, XML reports |
| **Dependencies** | Python 3.8+, `rich`, `requests` | None (posix shell) | GVM, Greenbone, external databases |
| **Customization** | Object-oriented Python modules | Shell functions / Custom tests | NASL scripts (complex syntax) |

---

## 🛠️ How to Extend NULLHOUND (Adding New Modules)

NULLHOUND is built with modularity at its core. To add a new scanning module:

1.  Create a new file under `modules/` (e.g., `modules/my_module.py`).
2.  Inherit from the `BaseModule` abstract base class and implement the required abstract properties and `.run()` method:
    ```python
    from typing import List
    from modules.base import BaseModule
    from core.finding import Finding

    class MyCustomModule(BaseModule):
        @property
        def name(self) -> str:
            return "custom"

        @property
        def description(self) -> str:
            return "Audits custom application security baselines"

        def run(self, profile: str = "standard") -> List[Finding]:
            findings = []
            
            # Perform your checks here
            # Use self.create_finding(...) to build findings
            # Example check:
            # if is_vulnerable:
            #     findings.append(self.create_finding(
            #         id_="AEG-CST-001",
            #         title="Custom Vulnerability Found",
            #         severity="MEDIUM",
            #         description="Detail about vulnerability.",
            #         evidence="Raw configuration setting",
            #         remediation="Step to fix the configuration",
            #         references=["https://example.com/reference"]
            #     ))
            
            return findings
    ```
3.  Register the module in `modules/__init__.py`:
    ```python
    from .my_module import MyCustomModule
    
    ALL_MODULES = {
        # ... existing modules
        "custom": MyCustomModule
    }
    ```

---

## ⚖️ Ethical Use Disclaimer

> [!WARNING]
> This security auditing tool is created for educational, ethical hacking, and portfolio demonstration purposes only. Running security auditing tools against systems you do not own or do not have explicit written permission to audit is illegal and subject to criminal liability. The authors assume no liability for misuse of this tool.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
