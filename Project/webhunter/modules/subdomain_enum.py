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
import json
from pathlib import Path
from typing import List, Set
import httpx
from rich.progress import Progress
from ..core.utils import ToolRunner
from ..core.utils import RateLimiter

class SubdomainEnumerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.subdomains: Set[str] = set()
        self.alive_subdomains: Set[str] = set()
        self.rate_limiter = RateLimiter(100)  # 100 requests per second

    async def enumerate_subdomains(self, target: str) -> List[str]:
        tasks = [
            self.run_subfinder(target),
            self.run_amass(target),
            self.run_assetfinder(target),
            self.run_findomain(target),
            self.run_massdns(target)
        ]
        
        async with Progress() as progress:
            task_id = progress.add_task("[cyan]Enumerating subdomains...", total=len(tasks))
            results = await asyncio.gather(*tasks)
            progress.update(task_id, advance=1)

        # Merge results and remove duplicates
        for result in results:
            self.subdomains.update(result)

        # Save raw results
        self._save_results("raw_subdomains.txt", self.subdomains)
        
        # Check for alive subdomains
        await self.verify_alive_subdomains()
        
        return list(self.alive_subdomains)

    async def verify_alive_subdomains(self):
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            tasks = []
            for subdomain in self.subdomains:
                await self.rate_limiter.wait()  # Add rate limiting
                tasks.append(self.check_subdomain(client, subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for subdomain, is_alive in zip(self.subdomains, results):
                if is_alive and not isinstance(is_alive, Exception):
                    self.alive_subdomains.add(subdomain)

        self._save_results("alive_subdomains.txt", self.alive_subdomains)

    async def check_subdomain(self, client, subdomain: str) -> bool:
        try:
            for protocol in ['https://', 'http://']:
                try:
                    resp = await client.get(f"{protocol}{subdomain}", follow_redirects=True)
                    if resp.status_code < 400:
                        return True
                except:
                    continue
            return False
        except:
            return False

    def _save_results(self, filename: str, data: Set[str]):
        output_file = self.output_dir / filename
        with open(output_file, 'w') as f:
            for item in sorted(data):
                f.write(f"{item}\n")

    # Tool-specific implementation methods
    async def run_subfinder(self, target: str) -> List[str]:
        if not ToolRunner.ensure_tool_installed("subfinder"):
            return []
        
        output_file = self.output_dir / "subfinder_output.txt"
        command = ["subfinder", "-d", target, "-silent", "-o", str(output_file)]
        
        try:
            await ToolRunner.run_command(command)
            return self._read_file_lines(output_file)
        except Exception as e:
            print(f"[!] Subfinder error: {e}")
            return []

    async def run_amass(self, target: str) -> List[str]:
        if not ToolRunner.ensure_tool_installed("amass"):
            return []
        
        output_file = self.output_dir / "amass_output.txt"
        command = ["amass", "enum", "-passive", "-d", target, "-o", str(output_file)]
        
        try:
            await ToolRunner.run_command(command, timeout=600)  # Longer timeout for Amass
            return self._read_file_lines(output_file)
        except Exception as e:
            print(f"[!] Amass error: {e}")
            return []

    async def run_assetfinder(self, target: str) -> List[str]:
        if not ToolRunner.ensure_tool_installed("assetfinder"):
            return []
        
        output_file = self.output_dir / "assetfinder_output.txt"
        command = ["assetfinder", "--subs-only", target]
        
        try:
            stdout, _ = await ToolRunner.run_command(command)
            with open(output_file, 'w') as f:
                f.write(stdout)
            return stdout.splitlines()
        except Exception as e:
            print(f"[!] Assetfinder error: {e}")
            return []

    async def run_findomain(self, target: str) -> List[str]:
        if not ToolRunner.ensure_tool_installed("findomain"):
            return []
        
        output_file = self.output_dir / "findomain_output.txt"
        command = ["findomain", "-t", target, "-u", str(output_file)]
        
        try:
            await ToolRunner.run_command(command)
            return self._read_file_lines(output_file)
        except Exception as e:
            print(f"[!] Findomain error: {e}")
            return []

    async def run_massdns(self, target: str) -> List[str]:
        if not ToolRunner.ensure_tool_installed("massdns"):
            return []
        
        wordlist = Path("config/wordlists/subdomains.txt")
        if not wordlist.exists():
            print("[!] Subdomain wordlist not found")
            return []
        
        # Generate domain permutations
        permutations_file = self.output_dir / "massdns_domains.txt"
        with open(permutations_file, 'w') as f:
            with open(wordlist) as wl:
                for line in wl:
                    f.write(f"{line.strip()}.{target}\n")
        
        output_file = self.output_dir / "massdns_output.txt"
        resolvers = Path("config/resolvers.txt")
        
        command = [
            "massdns",
            "-r", str(resolvers),
            "-t", "A",
            "-o", "S",
            "-w", str(output_file),
            str(permutations_file)
        ]
        
        try:
            await ToolRunner.run_command(command)
            # Parse MassDNS output and return valid subdomains
            return self._parse_massdns_output(output_file)
        except Exception as e:
            print(f"[!] MassDNS error: {e}")
            return []

    def _read_file_lines(self, file_path: Path) -> List[str]:
        if not file_path.exists():
            return []
        with open(file_path) as f:
            return [line.strip() for line in f if line.strip()]

    def _parse_massdns_output(self, output_file: Path) -> List[str]:
        results = set()
        if not output_file.exists():
            return []
        
        with open(output_file) as f:
            for line in f:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1:
                        domain = parts[0].rstrip('.')
                        results.add(domain)
        return list(results)

