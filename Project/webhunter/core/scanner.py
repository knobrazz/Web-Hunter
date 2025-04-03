import asyncio
import subprocess
from typing import List, Optional, Dict
from pathlib import Path
import json
import nmap
import requests
import warnings
from rich.console import Console
from rich.progress import Progress
from concurrent.futures import ThreadPoolExecutor
from ..modules.vuln_scanner import VulnerabilityScanner
from ..modules.port_scanner import PortScanner
from ..modules.subdomain_enum import SubdomainEnumerator
from ..modules.endpoint_enum import EndpointEnumerator
from ..modules.cloud_scanner import CloudScanner

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class ScanTarget:
    def __init__(self, domain: Optional[str] = None, wildcard: Optional[str] = None,
                 ip: Optional[str] = None, cidr: Optional[str] = None,
                 wildcard_list: Optional[str] = None, subdomain_list: Optional[str] = None):
        self.domain = domain
        self.wildcard = wildcard
        self.ip = ip
        self.cidr = cidr
        self.wildcard_list = wildcard_list
        self.subdomain_list = subdomain_list

class Scanner:
    def __init__(self, target: ScanTarget, output_dir: str):
        self.target = target
        self.output_dir = Path(output_dir)
        self._threads = 10
        self.modules = []
        self.console = Console()
        self.results: Dict = {}
        self.executor = ThreadPoolExecutor(max_workers=self._threads)
        self.wordlist = None
        
        # Initialize scanners
        self.vuln_scanner = VulnerabilityScanner(self.output_dir, self._threads)
        self.port_scanner = PortScanner(self.output_dir, self._threads)
        self.subdomain_enum = SubdomainEnumerator(self.output_dir)
        self.endpoint_enum = EndpointEnumerator(self.output_dir)
        self.cloud_scanner = CloudScanner(self.output_dir)

    def set_wordlist(self, wordlist_path: str) -> None:
        """Set custom wordlist for enumeration"""
        self.wordlist = Path(wordlist_path)
        if not self.wordlist.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    @property
    def threads(self) -> int:
        return self._threads

    def set_threads(self, num_threads: int) -> None:
        """Set the number of threads for scanning"""
        if not isinstance(num_threads, int) or num_threads < 1:
            raise ValueError("Thread count must be a positive integer")
        self._threads = num_threads
        # Update thread pool
        self.executor = ThreadPoolExecutor(max_workers=self._threads)

    async def run_subfinder(self) -> List[str]:
        """Run subfinder for subdomain enumeration"""
        if not self.target.domain:
            self.console.print("[yellow]Warning: No domain specified for subfinder[/yellow]")
            return []
        
        try:
            cmd = f"subfinder -d {self.target.domain} -silent"
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.console.print(f"[red]Subfinder error: {stderr.decode()}[/red]")
                return []
                
            subdomains = [s.strip() for s in stdout.decode().splitlines() if s.strip()]
            return subdomains
        except Exception as e:
            self.console.print(f"[red]Error running subfinder: {e}[/red]")
            return []

    async def run_nmap_scan(self, target: str) -> Dict:
        """Run nmap scan on target"""
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments=f'-sV -sC -p- --min-rate 1000 --max-retries 2 --host-timeout 30m')
            return nm[target]
        except Exception as e:
            self.console.print(f"[red]Error scanning {target}: {e}[/red]")
            return {}

    async def check_http(self, domain: str) -> Dict:
        """Check HTTP/HTTPS services"""
        result = {}
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=10, verify=False)
                result[protocol] = {
                    'status': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'title': response.text.split('<title>')[1].split('</title>')[0] if '<title>' in response.text else 'No title'
                }
            except Exception as e:
                result[protocol] = {'status': 'error', 'error': str(e)}
        return result

    async def start_scan(self, modules: Optional[List[str]] = None) -> None:
        """Start the scanning process with specified modules"""
        if not modules:
            modules = ['all']
        
        if not any([self.target.domain, self.target.ip, self.target.cidr]):
            raise ValueError("No target specified. Please provide domain, IP, or CIDR")

        self.console.print(f"[green]Starting scan with {self.threads} threads[/green]")
        self.console.print(f"[blue]Target: {self.target.domain or self.target.ip or self.target.cidr}[/blue]")
        self.console.print(f"[yellow]Modules: {', '.join(modules)}[/yellow]")
        
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            async with Progress() as progress:
                # Step 1: Subdomain Enumeration
                if self.target.domain:
                    task1 = progress.add_task("[cyan]1. Running subdomain enumeration...", total=100)
                    subdomains = await self.subdomain_enum.enumerate_subdomains(self.target.domain)
                    self.results['subdomains'] = list(subdomains)
                    progress.update(task1, completed=100)

                    # Step 2: Port Scanning
                    if subdomains:
                        task2 = progress.add_task("[magenta]2. Running port scans...", total=len(subdomains))
                        port_results = await self.port_scanner.scan_multiple_targets(list(subdomains))
                        self.results['port_scans'] = port_results
                        progress.update(task2, completed=len(subdomains))

                        # Step 3: Service Enumeration
                        task3 = progress.add_task("[green]3. Enumerating services...", total=len(subdomains))
                        for subdomain in subdomains:
                            service_info = await self.check_http(subdomain)
                            self.results.setdefault('services', {})[subdomain] = service_info
                            progress.update(task3, advance=1)

                        # Step 4: Endpoint Discovery
                        task4 = progress.add_task("[yellow]4. Discovering endpoints...", total=len(subdomains))
                        endpoints = await self.endpoint_enum.enumerate_endpoints(list(subdomains))
                        self.results['endpoints'] = list(endpoints)
                        progress.update(task4, completed=len(subdomains))

                        # Step 5: Vulnerability Scanning
                        task5 = progress.add_task("[red]5. Scanning vulnerabilities...", total=len(subdomains))
                        vuln_results = await self.vuln_scanner.scan_targets(list(subdomains))
                        self.results['vulnerabilities'] = vuln_results
                        progress.update(task5, completed=len(subdomains))

                # Step 6: Cloud Infrastructure Scanning
                if self.target.domain:
                    task6 = progress.add_task("[blue]6. Scanning cloud infrastructure...", total=100)
                    cloud_results = await self.cloud_scanner.scan_cloud_assets(self.target.domain)
                    self.results['cloud_assets'] = cloud_results
                    progress.update(task6, completed=100)

            # Save detailed results
            results_file = self.output_dir / f"{self.target.domain or self.target.ip or 'scan'}_results.json"
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=4)

            # Generate summary report
            await self.generate_summary_report()

            self.console.print(f"[green]Scan completed! Results saved to {results_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error during scan: {e}[/red]")
            raise

    async def generate_summary_report(self):
        """Generate a summary report of findings"""
        summary_file = self.output_dir / f"{self.target.domain or self.target.ip or 'scan'}_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("Web-Hunter Scan Summary\n")
            f.write("=" * 50 + "\n\n")
            
            if 'subdomains' in self.results:
                f.write(f"Subdomains Found: {len(self.results['subdomains'])}\n")
            
            if 'vulnerabilities' in self.results:
                f.write("\nVulnerabilities Summary:\n")
                for vuln_type, findings in self.results['vulnerabilities'].items():
                    f.write(f"{vuln_type}: {len(findings)} findings\n")
            
            if 'cloud_assets' in self.results:
                f.write("\nCloud Assets Found:\n")
                for cloud, assets in self.results['cloud_assets'].items():
                    f.write(f"{cloud}: {len(assets)} resources\n")

