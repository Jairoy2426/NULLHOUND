import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable
from modules.base import BaseModule
from core.finding import Finding

class ModuleRunner:
    def __init__(self, modules: List[BaseModule], threads: int = 4):
        self.modules = modules
        self.threads = threads

    def run_all(
        self,
        profile: str = "standard",
        on_start: Callable[[str], None] = None,
        on_complete: Callable[[str, List[Finding]], None] = None
    ) -> List[Finding]:
        """
        Executes all configured modules in parallel using a ThreadPoolExecutor.
        Catches exceptions per module and wraps them as INFO findings to prevent crashes.
        """
        all_findings = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_module = {}
            for m in self.modules:
                if on_start:
                    on_start(m.name)
                # Submit module run execution
                future = executor.submit(m.run, profile)
                future_to_module[future] = m

            for future in as_completed(future_to_module):
                module = future_to_module[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    if on_complete:
                        on_complete(module.name, findings)
                except Exception as e:
                    # In case of any unhandled module crash, generate an INFO finding as per requirements
                    err_finding = Finding(
                        id=f"AEG-{module.name.upper()}-ERR",
                        title=f"Module '{module.name}' execution failed",
                        severity="INFO",
                        module=module.name,
                        description=f"An unhandled exception occurred during execution: {str(e)}",
                        evidence=f"Exception detail: {str(e)}",
                        remediation="Report this issue or inspect system command logs.",
                        references=[]
                    )
                    all_findings.append(err_finding)
                    if on_complete:
                        on_complete(module.name, [err_finding])

        return all_findings
