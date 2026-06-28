import json
import os
import time
from typing import List, Dict, Any
from core.finding import Finding

class ReportReporter:
    def __init__(self, findings: List[Finding], meta: Dict[str, Any], risk_score: int):
        self.findings = findings
        self.meta = meta
        self.risk_score = risk_score

    def export(self, file_path: str) -> str:
        """
        Detects export format by file path extension and writes the report.
        Returns the path written, or raises error.
        """
        _, ext = os.path.splitext(file_path.lower())
        if ext == ".json":
            return self._export_json(file_path)
        elif ext == ".html":
            return self._export_html(file_path)
        else:
            # Default to TXT for other extensions (or plain .txt)
            return self._export_txt(file_path)

    def _export_json(self, file_path: str) -> str:
        data = {
            "meta": self.meta,
            "summary": {
                "risk_score": self.risk_score,
                "hardening_index": 100 - self.risk_score,
                "counts": self._get_counts()
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
        return file_path

    def _export_txt(self, file_path: str) -> str:
        counts = self._get_counts()
        lines = []
        lines.append("=" * 80)
        lines.append("                        NULLHOUND SECURITY AUDIT REPORT")
        lines.append("=" * 80)
        lines.append(f"Scanner Version : {self.meta.get('version')}")
        lines.append(f"Host Name       : {self.meta.get('hostname')}")
        lines.append(f"Kernel Version  : {self.meta.get('kernel')}")
        lines.append(f"Scan Time       : {self.meta.get('timestamp')}")
        lines.append(f"Executed User   : {self.meta.get('user')}")
        lines.append(f"Profile Level   : {self.meta.get('profile')}")
        lines.append("-" * 80)
        lines.append("SUMMARY STATS:")
        lines.append(f"  Overall Risk Score: {self.risk_score}/100")
        lines.append(f"  System Hardening Index: {100 - self.risk_score}/100")
        lines.append(f"  CRITICAL : {counts['CRITICAL']} | HIGH : {counts['HIGH']} | MEDIUM : {counts['MEDIUM']}")
        lines.append(f"  LOW      : {counts['LOW']} | INFO : {counts['INFO']}")
        lines.append("=" * 80)
        lines.append("")

        if not self.findings:
            lines.append("PASS: No system vulnerabilities were detected.")
        else:
            # Group by module
            grouped = {}
            for f in self.findings:
                grouped.setdefault(f.module, []).append(f)

            for mod, mod_findings in grouped.items():
                lines.append(f"MODULE: {mod.upper()}")
                lines.append("-" * 80)
                for f in mod_findings:
                    lines.append(f"[{f.severity}] {f.id}: {f.title}")
                    lines.append(f"  Description : {f.description}")
                    if f.evidence:
                        lines.append(f"  Evidence    : {f.evidence.replace(chr(10), f'{chr(10)}                ')}")
                    lines.append(f"  Remediation : {f.remediation}")
                    if f.compliance:
                        lines.append(f"  Compliance  : {', '.join(f.compliance)}")
                    if f.references:
                        lines.append(f"  References  : {', '.join(f.references)}")
                    lines.append("-" * 40)
                lines.append("")

        with open(file_path, "w") as f:
            f.write("\n".join(lines))
        return file_path

    def _export_html(self, file_path: str) -> str:
        counts = self._get_counts()
        
        # Color codes for HTML
        colors = {
            "CRITICAL": "#ef4444", # Red
            "HIGH": "#f97316",     # Orange
            "MEDIUM": "#eab308",   # Yellow
            "LOW": "#06b6d4",      # Cyan
            "INFO": "#94a3b8",     # Slate/Gray
        }

        # Generate HTML findings rows
        findings_html = []
        for idx, f in enumerate(self.findings):
            color = colors.get(f.severity.upper(), "#ffffff")
            ref_links = "".join([f'<a href="{ref}" target="_blank">{ref}</a> ' for ref in f.references])
            evidence_escaped = f.evidence.replace("<", "&lt;").replace(">", "&gt;") if f.evidence else "N/A"
            
            compliance_badges = ""
            if getattr(f, 'compliance', None):
                compliance_badges = "".join([f'<span class="badge badge-compliance">{std}</span>' for std in f.compliance])

            row = f"""
            <div class="finding-card border-{f.severity.lower()}">
                <summary class="finding-header">
                    <span class="badge badge-{f.severity.lower()}">{f.severity}</span>
                    {compliance_badges}
                    <span class="finding-id">{f.id}</span>
                    <span class="finding-title">{f.title}</span>
                    <span class="finding-module">{f.module.upper()}</span>
                </summary>
                <div class="finding-details">
                    <p><strong>Description:</strong> {f.description}</p>
                    <div class="code-block">
                        <strong>Evidence:</strong>
                        <pre><code>{evidence_escaped}</code></pre>
                    </div>
                    <p class="remediation"><strong>Remediation:</strong> {f.remediation}</p>
                    <p><strong>References:</strong> {ref_links or "None"}</p>
                </div>
            </div>
            """
            findings_html.append(row)

        findings_joined = "\n".join(findings_html) if findings_html else "<p class='no-vulns'>🎉 Pass: No system vulnerabilities were detected!</p>"

        # Determine risk color
        risk_color = "#22c55e" # Green
        if self.risk_score >= 70:
            risk_color = "#ef4444"
        elif self.risk_score >= 40:
            risk_color = "#f97316"
        elif self.risk_score >= 15:
            risk_color = "#eab308"

        # Determine hardening score and color
        hardening_score = 100 - self.risk_score
        hardening_color = "#22c55e" # Green
        if hardening_score < 30:
            hardening_color = "#ef4444"
        elif hardening_score < 60:
            hardening_color = "#f97316"
        elif hardening_score < 85:
            hardening_color = "#eab308"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NULLHOUND Vulnerability Scan Report</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --container-bg: #1e293b;
            --text-color: #f8fafc;
            --text-dim: #94a3b8;
            --border-color: #334155;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #06b6d4;
            --info: #64748b;
            --pass: #22c55e;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}

        header {{
            background-color: var(--container-bg);
            padding: 30px;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            margin-bottom: 25px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }}

        h1 {{
            margin-top: 0;
            font-size: 2.5rem;
            color: #ffffff;
            display: flex;
            align-items: center;
            letter-spacing: 0.05em;
        }}

        .subtitle {{
            color: var(--text-dim);
            margin-bottom: 20px;
            font-size: 1.1rem;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            border-top: 1px solid var(--border-color);
            padding-top: 20px;
        }}

        .meta-item strong {{
            color: var(--text-dim);
            display: block;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}

        .meta-item span {{
            font-size: 1.05rem;
            font-weight: 500;
        }}

        /* Dashboard widgets */
        .dashboard {{
            display: grid;
            grid-template-columns: 1.5fr 1fr 1fr;
            gap: 25px;
            margin-bottom: 25px;
        }}

        @media (max-width: 768px) {{
            .dashboard {{
                grid-template-columns: 1fr;
                gap: 15px;
            }}
        }}

        .card {{
            background-color: var(--container-bg);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            padding: 25px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            height: 100%;
            align-items: center;
        }}

        @media (max-width: 480px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
                gap: 10px;
            }}
        }}

        .stat-box {{
            text-align: center;
            padding: 15px 5px;
            border-radius: 8px;
            background-color: #0f172a90;
            border: 1px solid var(--border-color);
        }}

        .stat-count {{
            font-size: 2rem;
            font-weight: 700;
            display: block;
        }}

        .stat-label {{
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-dim);
            text-transform: uppercase;
        }}

        .risk-gauge {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}

        .risk-score {{
            font-size: 4rem;
            font-weight: 800;
            line-height: 1;
        }}

        .risk-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-top: 10px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        /* Findings list */
        .findings-section {{
            margin-top: 30px;
        }}

        .findings-title {{
            font-size: 1.8rem;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .finding-card {{
            background-color: var(--container-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            margin-bottom: 15px;
            padding: 20px;
            border-left: 6px solid var(--text-dim);
        }}

        .border-critical {{ border-left-color: var(--critical); }}
        .border-high {{ border-left-color: var(--high); }}
        .border-medium {{ border-left-color: var(--medium); }}
        .border-low {{ border-left-color: var(--low); }}
        .border-info {{ border-left-color: var(--info); }}

        .finding-header {{
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
        }}

        .badge {{
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            color: #ffffff;
        }}

        .badge-critical {{ background-color: var(--critical); }}
        .badge-high {{ background-color: var(--high); }}
        .badge-medium {{ background-color: var(--medium); color: #000; }}
        .badge-low {{ background-color: var(--low); color: #000; }}
        .badge-info {{ background-color: var(--info); }}
        .badge-compliance {{ background-color: #2563eb; color: #ffffff; }}

        .finding-id {{
            font-family: monospace;
            font-weight: bold;
            color: var(--text-dim);
        }}

        .finding-title {{
            font-size: 1.15rem;
            font-weight: 600;
            color: #ffffff;
            flex-grow: 1;
        }}

        .finding-module {{
            font-size: 0.75rem;
            background-color: #0f172a;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
            border: 1px solid var(--border-color);
        }}

        .finding-details {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #334155a0;
        }}

        .code-block {{
            margin: 15px 0;
        }}

        .code-block pre {{
            background-color: #090d16;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            margin-top: 5px;
        }}

        .code-block code {{
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9rem;
            color: #38bdf8;
        }}

        .remediation {{
            background-color: #1e293b;
            border-left: 4px solid var(--pass);
            padding: 10px 15px;
            margin: 15px 0;
            border-radius: 0 6px 6px 0;
        }}

        a {{
            color: #38bdf8;
            text-decoration: none;
            font-size: 0.9rem;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .no-vulns {{
            text-align: center;
            font-size: 1.3rem;
            padding: 50px;
            background-color: var(--container-bg);
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ NULLHOUND SECURITY REPORT</h1>
            <div class="subtitle">Automated Enumeration & Guided Intelligence Scanner</div>
            <div class="meta-grid">
                <div class="meta-item">
                    <strong>Host Name</strong>
                    <span>{self.meta.get('hostname')}</span>
                </div>
                <div class="meta-item">
                    <strong>Kernel</strong>
                    <span>{self.meta.get('kernel')}</span>
                </div>
                <div class="meta-item">
                    <strong>Scan Time</strong>
                    <span>{self.meta.get('timestamp')}</span>
                </div>
                <div class="meta-item">
                    <strong>Scanner Version</strong>
                    <span>{self.meta.get('version')}</span>
                </div>
                <div class="meta-item">
                    <strong>Audit User</strong>
                    <span>{self.meta.get('user')}</span>
                </div>
            </div>
        </header>

        <div class="dashboard">
            <div class="card">
                <div class="stats-grid">
                    <div class="stat-box" style="border-top: 4px solid var(--critical)">
                        <span class="stat-count" style="color: var(--critical)">{counts['CRITICAL']}</span>
                        <span class="stat-label">Critical</span>
                    </div>
                    <div class="stat-box" style="border-top: 4px solid var(--high)">
                        <span class="stat-count" style="color: var(--high)">{counts['HIGH']}</span>
                        <span class="stat-label">High</span>
                    </div>
                    <div class="stat-box" style="border-top: 4px solid var(--medium)">
                        <span class="stat-count" style="color: var(--medium)">{counts['MEDIUM']}</span>
                        <span class="stat-label">Medium</span>
                    </div>
                    <div class="stat-box" style="border-top: 4px solid var(--low)">
                        <span class="stat-count" style="color: var(--low)">{counts['LOW']}</span>
                        <span class="stat-label">Low</span>
                    </div>
                    <div class="stat-box" style="border-top: 4px solid var(--info)">
                        <span class="stat-count" style="color: var(--info)">{counts['INFO']}</span>
                        <span class="stat-label">Info</span>
                    </div>
                </div>
            </div>
            
            <div class="card risk-gauge">
                <span class="risk-score" style="color: {risk_color}">{self.risk_score}</span>
                <span class="risk-title">OVERALL RISK SCORE</span>
            </div>

            <div class="card risk-gauge">
                <span class="risk-score" style="color: {hardening_color}">{hardening_score}</span>
                <span class="risk-title">HARDENING INDEX</span>
            </div>
        </div>

        <div class="findings-section">
            <div class="findings-title">
                <span>Vulnerabilities & Findings ({len(self.findings)})</span>
            </div>
            {findings_joined}
        </div>
        <footer style="margin-top: 30px; padding: 20px; text-align: center; border-top: 1px solid var(--border-color); color: var(--info); font-size: 0.9rem;">
            NULLHOUND Security Auditor &bull; Strictly for Educational Purposes &bull; Made By Hercules
        </footer>
    </div>
</body>
</html>
"""
        with open(file_path, "w") as f:
            f.write(html_content)
        return file_path

    def _get_counts(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.severity.upper()
            if sev in counts:
                counts[sev] += 1
        return counts
