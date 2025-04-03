import asyncio
import subprocess
from typing import List, Optional, Dict
from pathlib import Path
import json
import nmap
import requests
from rich.console import Console
from rich.progress import Progress

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
        self.threads = 10
        self.modules = []
        self.console = Console()
        self.results: Dict = {}

    async def run_subfinder(self) -> List[str]:
        """Run subfinder for subdomain enumeration"""
        try:
            cmd = f"subfinder -d {self.target.domain} -silent"
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            subdomains = stdout.decode().splitlines()
            return subdomains
        except Exception as e:
            self.console.print(f"[red]Error running subfinder: {e}[/red]")
            return []

    async def run_nmap_scan(self, target: str) -> Dict:
        """Run nmap scan on target"""
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-sV -sC -p-')
            return nm[target]
        except Exception as e:
            self.console.print(f"[red]Error running nmap scan: {e}[/red]")
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
            except:
                result[protocol] = {'status': 'error'}
        return result

    async def start_scan(self, modules: Optional[List[str]] = None) -> None:
        """Start the scanning process with specified modules"""
        if not modules:
            modules = ['all']
        
        self.console.print(f"[green]Starting scan with {self.threads} threads[/green]")
        self.console.print(f"[blue]Target: {self.target.domain or self.target.ip or self.target.cidr}[/blue]")
        self.console.print(f"[yellow]Modules: {', '.join(modules)}[/yellow]")
        
        self.output_dir.mkdir(parents=True, exist_ok=True)

        with Progress() as progress:
            # Subdomain enumeration
            task1 = progress.add_task("[cyan]Running subdomain enumeration...", total=100)
            subdomains = await self.run_subfinder()
            self.results['subdomains'] = subdomains
            progress.update(task1, completed=100)

            # Port scanning
            if subdomains:
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
        results_file = self.output_dir / f"{self.target.domain}_scan_results.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=4)

        self.console.print(f"[green]Scan completed! Results saved to {results_file}[/green]")

