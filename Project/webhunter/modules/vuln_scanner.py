# Copyright 2025 nabar
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import logging
from pathlib import Path
from typing import Dict, List
import json
from ..core.utils import ToolRunner
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor

class VulnerabilityScanner:
    def __init__(self, output_dir: Path, max_threads: int = 10):
        self.output_dir = output_dir
        self.results = []
        self.executor = ThreadPoolExecutor(max_workers=max_threads)
        self.logger = logging.getLogger(__name__)

    async def scan_targets(self, targets: List[str]) -> Dict:
        try:
            async with Progress() as progress:
                task = progress.add_task("[cyan]Scanning vulnerabilities...", total=len(targets))
                scan_results = {
                    'xss': await self.scan_xss(targets),
                    'sqli': await self.scan_sqli(targets),
                    'ssrf': await self.scan_ssrf(targets),
                    'rce': await self.scan_rce(targets),
                    'nuclei': await self.run_nuclei(targets),
                    'wapiti': await self.run_wapiti(targets),
                    'nikto': await self.run_nikto(targets),
                    'gitleaks': await self.scan_gitleaks(targets)
                }
                progress.update(task, advance=1)
            
            await self.save_results(scan_results)
            return scan_results
        except Exception as e:
            self.logger.error(f"Vulnerability scanning failed: {e}")
            raise

    async def scan_xss(self, targets: List[str]) -> List[Dict]:
        results = []
        for target in targets:
            # Run dalfox
            command = ["dalfox", "url", target, "--silence"]
            stdout, _ = await ToolRunner.run_command(command)
            if stdout:
                results.append({
                    'target': target,
                    'vulnerability': 'XSS',
                    'details': stdout
                })
        return results

    async def run_nuclei(self, targets: List[str]) -> List[Dict]:
        results = []
        templates = [
            'cves/', 'vulnerabilities/', 'misconfiguration/',
            'exposed-panels/', 'exposures/'
        ]
        
        for template in templates:
            command = [
                "nuclei", "-l", targets,
                "-t", template,
                "-json"
            ]
            stdout, _ = await ToolRunner.run_command(command)
            if stdout:
                results.extend(json.loads(stdout))
        
        return results

