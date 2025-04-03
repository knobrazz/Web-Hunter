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

import re
from typing import Optional, List

def validate_domain(ctx, param, value: Optional[str]) -> Optional[str]:
    """Validate domain name format."""
    if value is None:
        return None
        
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, value):
        raise click.BadParameter('Invalid domain format. Example: example.com')
    return value

def validate_ip(ctx, param, value: Optional[str]) -> Optional[str]:
    """Validate IP address format."""
    if value is None:
        return None
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, value):
        raise click.BadParameter('Invalid IP format. Example: 192.168.1.1')
    return value

def validate_cidr(ctx, param, value: Optional[str]) -> Optional[str]:
    """Validate CIDR format."""
    if value is None:
        return None
    
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(cidr_pattern, value):
        raise click.BadParameter('Invalid CIDR format. Example: 192.168.1.0/24')
    return value

@click.group()
def cli():
    """Web-Hunter - Advanced Reconnaissance Tool"""
    show_banner()

@cli.command()
@click.option('-d', '--domain', callback=validate_domain, help='Target domain (e.g., example.com)')
@click.option('-ip', '--ip-address', callback=validate_ip, help='Target IP address')
@click.option('-cidr', '--cidr-range', callback=validate_cidr, help='Target CIDR range')
@click.option('-w', '--wordlist', type=click.Path(exists=True), help='Custom wordlist for enumeration')
@click.option('-wl', '--wildcard-list', type=click.Path(exists=True), help='List of wildcard domains')
@click.option('-l', '--subdomain-list', type=click.Path(exists=True), help='Pre-defined subdomain list')
@click.option('--threads', type=click.IntRange(1, 100), default=10, help='Number of threads (1-100)')
@click.option('--modules', multiple=True, type=click.Choice(['subdomain', 'port', 'vuln', 'all']), 
              default=['all'], help='Specific modules to run')
@click.option('--output', type=click.Path(), default='results', help='Output directory for results')
def scan(domain, ip_address, cidr_range, wordlist, wildcard_list, subdomain_list, 
         threads, modules, output):
    """Start a new scan with specified options"""
    try:
        if not any([domain, ip_address, cidr_range]):
            raise click.UsageError("Please provide at least one target: domain (-d), IP (-ip), or CIDR (-cidr)")

        target = ScanTarget(
            domain=domain,
            ip=ip_address,
            cidr=cidr_range,
            wildcard_list=wildcard_list,
            subdomain_list=subdomain_list
        )
        
        scanner = Scanner(target, output)
        scanner.set_threads(threads)
        
        if wordlist:
            scanner.set_wordlist(wordlist)
            
        asyncio.run(scanner.start_scan(list(modules)))
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

@cli.command()
@click.argument('config_file', type=click.Path(exists=True))
def scan_from_config(config_file):
    """Start a scan using a configuration file"""
    try:
        with open(config_file) as f:
            config = yaml.safe_load(f)
        
        target = ScanTarget(**config['target'])
        scanner = Scanner(target, config.get('output_dir', 'results'))
        scanner.set_threads(config.get('threads', 10))
        asyncio.run(scanner.start_scan(config.get('modules', ['all'])))
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()

