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
import os
from typing import List, Optional
from dataclasses import dataclass
from pathlib import Path
from webhunter.modules.subdomain_enum import SubdomainEnumerator
from rich.progress import Progress, SpinnerColumn, TextColumn
from concurrent.futures import ThreadPoolExecutor
import asyncio
import logging

@dataclass
class ScanTarget:
    domain: Optional[str] = None
    wildcard: Optional[str] = None
    ip: Optional[str] = None
    cidr: Optional[str] = None
    wildcard_list: Optional[List[str]] = None
    subdomain_list: Optional[str] = None

class Scanner:
    def __init__(self, target: ScanTarget, output_dir: str):
        self.target = target
        self.base_output_dir = Path(output_dir)
        self.current_target_dir = None
        self.setup_directories()

    def setup_directories(self):
        # Create target-specific directory
        target_name = self.target.domain or self.target.ip or "scan"
        self.current_target_dir = self.base_output_dir / target_name
        
        # Create step-specific directories
        directories = [
            "step1_subdomains",
            "step2_endpoints",
            "step3_vulnerabilities",
            "step4_nuclei",
            "step5_misc"
        ]
        
        for dir_name in directories:
            os.makedirs(self.current_target_dir / dir_name, exist_ok=True)

    async def start_subdomain_scan(self):
        if self.target.subdomain_list:
            print("[*] Using provided subdomain list, skipping enumeration...")
            return
            
        if self.target.wildcard or self.target.wildcard_list:
            await self._scan_wildcard_domains()
        elif self.target.ip or self.target.cidr:
            await self._scan_ip_based()
        else:
            await self._scan_single_domain()

    async def _scan_wildcard_domains(self):
        # Implement wildcard domain scanning using various tools
        pass

    async def _scan_ip_based(self):
        # Implement IP/CIDR based scanning
        pass

    async def _scan_single_domain(self):
        subdomain_dir = self.current_target_dir / "step1_subdomains"
        enumerator = SubdomainEnumerator(subdomain_dir)
        
        print(f"[*] Starting subdomain enumeration for {self.target.domain}")
        subdomains = await enumerator.enumerate_subdomains(self.target.domain)
        
        print(f"[+] Found {len(subdomains)} alive subdomains")
        return subdomains

    async def resume_scan(self, checkpoint_file: Path):
        if checkpoint_file.exists():
            with open(checkpoint_file) as f:
                checkpoint = json.load(f)
            return checkpoint
        return None

    async def save_checkpoint(self, state: dict):
        with open(self.current_target_dir / "checkpoint.json", 'w') as f:
            json.dump(state, f)

