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
                # Subdomain enumeration
                if self.target.domain:
                    task1 = progress.add_task("[cyan]Running subdomain enumeration...", total=100)
                    subdomains = await self.run_subfinder()
                    self.results['subdomains'] = subdomains
                    progress.update(task1, completed=100)

                    if subdomains:
                        # Port scanning
                        task2 = progress.add_task("[magenta]Running port scans...", total=len(subdomains))
                        for subdomain in subdomains:
                            self.results.setdefault('port_scans', {})[subdomain] = await self.run_nmap_scan(subdomain)
                            progress.update(task2, advance=1)

                        # HTTP checks
                        task3 = progress.add_task("[green]Checking HTTP services...", total=len(subdomains))
                        for subdomain in subdomains:
                            self.results.setdefault('http_checks', {})[subdomain] = await self.check_http(subdomain)
                            progress.update(task3, advance=1)

            # Save results
            results_file = self.output_dir / f"{self.target.domain or self.target.ip or 'scan'}_results.json"
            with open(results_file, 'w') as f:
                json.dump(self.results, f, indent=4)

            self.console.print(f"[green]Scan completed! Results saved to {results_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error during scan: {e}[/red]")
            raise

