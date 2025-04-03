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

import argparse
import asyncio
import click
import yaml
import sys
from pathlib import Path
from webhunter.core.banner import show_banner
from webhunter.core.scanner import Scanner, ScanTarget

# Remove duplicate imports and fix relative import
import re
from typing import Optional

def validate_domain(ctx, param, value: Optional[str]) -> Optional[str]:
    """Validate domain name format."""
    if value is None:
        return None
        
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, value):
        raise click.BadParameter('Invalid domain format. Example: example.com')
    return value

@click.group()
def cli():
    """Web-Hunter - Advanced Reconnaissance Tool"""
    show_banner()

@cli.command()
@click.option('-d', '--domain', callback=validate_domain)
@click.option('-w', '--wordlist', type=click.Path(exists=True))
@click.option('--threads', type=click.IntRange(1, 100), default=10)
@click.option('-w', '--wildcard', help='Wildcard domain')
@click.option('-ip', '--ip-address', help='IP address')
@click.option('-cidr', help='CIDR range')
@click.option('-wl', '--wildcard-list', help='List of wildcard domains')
@click.option('-list', '--subdomain-list', help='Pre-defined subdomain list')
@click.option('--modules', multiple=True, help='Specific modules to run')
def scan(domain, wordlist, threads, wildcard, ip_address, cidr, wildcard_list, subdomain_list, modules):
    """Start a new scan with specified options"""
    try:
        target = ScanTarget(
            domain=domain,
            wildcard=wildcard,
            ip=ip_address,
            cidr=cidr,
            wildcard_list=wildcard_list,
            subdomain_list=subdomain_list
        )
        
        # Modified Scanner initialization
        scanner = Scanner(target, "results")
        scanner.set_threads(threads)  # Set threads after initialization
        asyncio.run(scanner.start_scan(modules))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('config_file', type=click.Path(exists=True))
def scan_from_config(config_file):
    """Start a scan using a configuration file"""
    with open(config_file) as f:
        config = yaml.safe_load(f)
    
    target = ScanTarget(**config['target'])
    scanner = Scanner(target, config.get('output_dir', 'results'))
    asyncio.run(scanner.start_scan(config.get('modules', ['all'])))

if __name__ == '__main__':
    cli()

