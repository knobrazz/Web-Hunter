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
from typing import List, Dict
import masscan
from rich.progress import Progress

class PortScanner:
    def __init__(self, output_dir, max_threads=100):
        self.output_dir = Path(output_dir)
        self.max_threads = max_threads
        self.executor = ThreadPoolExecutor(max_workers=max_threads)
        self.mas = masscan.PortScanner()
        
    async def scan_multiple_targets(self, targets: List[str]) -> Dict[str, List[int]]:
        all_results = {}
        async with Progress() as progress:
            task = progress.add_task("[cyan]Scanning ports...", total=len(targets))
            for target in targets:
                results = await self.scan_ports(target)
                all_results.update(results)
                progress.update(task, advance=1)
        return all_results

    # Add Nmap integration for service detection
    async def detect_services(self, host: str, ports: List[int]) -> Dict[int, str]:
        # Implementation for service detection
        pass

    async def scan_ports(self, target: str, ports: str = "1-65535") -> Dict[str, List[int]]:
        try:
            print(f"[*] Starting port scan for {target}")
            
            # Run masscan
            self.mas.scan(target, ports=ports, arguments="--rate 1000")
            
            # Process results
            results = {}
            for host in self.mas.all_hosts:
                results[host] = []
                for port in self.mas[host]['tcp'].keys():
                    results[host].append(int(port))
            
            # Save results
            self._save_results(target, results)
            
            return results
        except Exception as e:
            print(f"[!] Port scanning error: {e}")
            return {}

    def _save_results(self, target: str, results: Dict[str, List[int]]):
        output_file = self.output_dir / f"{target}_ports.txt"
        with open(output_file, 'w') as f:
            for host, ports in results.items():
                f.write(f"{host}:{','.join(map(str, sorted(ports)))}\n")

