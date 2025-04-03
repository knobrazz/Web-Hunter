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

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

class ResultsManager:
    def __init__(self, target_name: str):
        self.base_dir = Path("c:/Users/nabar/OneDrive/Desktop/Project/results")
        self.target_dir = self.base_dir / target_name
        self.setup_directories()

    def setup_directories(self):
        """Create the necessary directories for results"""
        self.target_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for different scan phases
        (self.target_dir / "raw").mkdir(exist_ok=True)
        (self.target_dir / "processed").mkdir(exist_ok=True)

    def save_subdomains(self, subdomains: List[str], is_alive: bool = False):
        """Save subdomain results"""
        filename = "alive_subdomains.txt" if is_alive else "subdomains.txt"
        with open(self.target_dir / filename, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))

    def save_ports(self, ports_data: Dict[str, List[int]]):
        """Save port scanning results"""
        with open(self.target_dir / "ports.txt", 'w') as f:
            for host, ports in ports_data.items():
                f.write(f"{host}:{','.join(map(str, sorted(ports)))}\n")

    def save_endpoints(self, endpoints: List[str], is_critical: bool = False):
        """Save endpoint discovery results"""
        filename = "critical_endpoints.txt" if is_critical else "endpoints.txt"
        with open(self.target_dir / filename, 'w') as f:
            f.write('\n'.join(sorted(endpoints)))

    def save_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """Save vulnerability scan results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_vulnerabilities": len(vulns),
            "vulnerabilities": vulns
        }
        
        with open(self.target_dir / "vulnerabilities.json", 'w') as f:
            json.dump(output, f, indent=4)

    def save_nuclei_results(self, results: List[Dict[str, Any]]):
        """Save Nuclei scan results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_findings": len(results),
            "findings": results
        }
        
        with open(self.target_dir / "nuclei_result.json", 'w') as f:
            json.dump(output, f, indent=4)

    def create_summary(self):
        """Create a summary of all scan results"""
        summary = {
            "target": self.target_dir.name,
            "scan_completed": datetime.now().isoformat(),
            "statistics": {
                "subdomains": self._count_lines("subdomains.txt"),
                "alive_subdomains": self._count_lines("alive_subdomains.txt"),
                "endpoints": self._count_lines("endpoints.txt"),
                "critical_endpoints": self._count_lines("critical_endpoints.txt"),
                "vulnerabilities": self._count_vulns("vulnerabilities.json"),
                "nuclei_findings": self._count_vulns("nuclei_result.json")
            }
        }
        
        with open(self.target_dir / "summary.json", 'w') as f:
            json.dump(summary, f, indent=4)

    def _count_lines(self, filename: str) -> int:
        try:
            with open(self.target_dir / filename) as f:
                return sum(1 for _ in f)
        except FileNotFoundError:
            return 0

    def _count_vulns(self, filename: str) -> int:
        try:
            with open(self.target_dir / filename) as f:
                data = json.load(f)
                return len(data.get("vulnerabilities", [])) or len(data.get("findings", []))
        except FileNotFoundError:
            return 0

