#!/usr/bin/env python3
"""
Web-Hunter - Advanced Security Reconnaissance Tool
Created by Nabaraj Lamichhane
GitHub: https://github.com/knobrazz

CAUTION: This tool is for ethical purposes only. Use responsibly and only on systems you have permission to test.
"""

import os
import sys
import argparse
import time
import random
import signal
import json
from colorama import Fore, Back, Style, init
from tqdm import tqdm
from modules.banner import display_banner, display_thanks
from modules.utils import (
    create_project_directory,
    parse_cidr,
    validate_domain,
    validate_ip,
    print_colored,
    animate_text,
    load_targets_from_file
)
from modules.subdomain_enum import (
    passive_subdomain_enum,
    active_subdomain_enum,
    validate_subdomains
)
from modules.port_scanner import perform_port_scan
from modules.tech_detection import detect_technologies
from modules.endpoint_finder import (
    extract_endpoints,
    filter_endpoints,
    filter_js_files,
    extract_sensitive_info
)
from modules.vulnerability_scanner import (
    scan_sqli,
    scan_xss,
    scan_rce,
    scan_lfi,
    scan_csrf,
    scan_ssrf,
    scan_idor,
    scan_xxe,
    scan_ssti,
    scan_jwt,
    scan_broken_auth,
    run_nuclei_scan,
    run_vulnerability_scan
)
from modules.bypass_techniques import (
    status_code_bypass,
    waf_bypass
)
from modules.cloud_assets import (
    discover_cloud_assets,
    api_fuzzing
)
from modules.osint import (
    whois_lookup,
    email_finder,
    check_leaks,
    azure_tenant_mapper,
    find_metadata,
    search_api_leaks,
    run_google_dorks,
    run_github_dorks,
    analyze_github_repos,
    check_misconfigurations,
    check_spoofable_domains
)

# Initialize colorama
init(autoreset=True)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print_colored("\n\n[!] Interrupted by user. Exiting gracefully...", Fore.YELLOW)
    display_thanks()
    sys.exit(0)

def find_existing_scans(base_dir):
    """Find existing scan directories"""
    scan_dirs = []
    
    if os.path.exists(base_dir):
        for dir_name in os.listdir(base_dir):
            full_path = os.path.join(base_dir, dir_name)
            if os.path.isdir(full_path) and '_' in dir_name:
                # Check if it seems like a scan directory
                if any([os.path.exists(os.path.join(full_path, subdir)) for subdir in 
                        ['subdomains', 'endpoints', 'ports', 'technologies', 'vulnerabilities']]):
                    scan_dirs.append(full_path)
    
    return scan_dirs

def load_scan_data(scan_dir):
    """Load existing scan data from a directory"""
    scan_data = {
        'domain': None,
        'subdomains': [],
        'endpoints': [],
        'critical_endpoints': [],
        'js_files': [],
        'ports': [],
        'technologies': [],
        'vulnerabilities': {}
    }
    
    # Extract domain from directory name
    dir_name = os.path.basename(scan_dir)
    if '_' in dir_name:
        scan_data['domain'] = dir_name.split('_')[0]
    
    # Load subdomains
    subdomains_file = os.path.join(scan_dir, 'subdomains', 'valid_subdomains.txt')
    if os.path.exists(subdomains_file):
        scan_data['subdomains'] = load_targets_from_file(subdomains_file)
    
    # Load endpoints
    endpoints_file = os.path.join(scan_dir, 'endpoints', 'all_endpoints.txt')
    if os.path.exists(endpoints_file):
        scan_data['endpoints'] = load_targets_from_file(endpoints_file)
    
    critical_endpoints_file = os.path.join(scan_dir, 'endpoints', 'critical_endpoints.txt')
    if os.path.exists(critical_endpoints_file):
        scan_data['critical_endpoints'] = load_targets_from_file(critical_endpoints_file)
    
    js_files_file = os.path.join(scan_dir, 'endpoints', 'js_files.txt')
    if os.path.exists(js_files_file):
        scan_data['js_files'] = load_targets_from_file(js_files_file)
    
    # Load vulnerability data if available
    vuln_dir = os.path.join(scan_dir, 'vulnerabilities')
    if os.path.exists(vuln_dir):
        for vuln_type in ['sqli', 'xss', 'rce', 'lfi', 'csrf', 'ssrf', 'idor', 'xxe', 'ssti', 'jwt', 'broken_auth']:
            vuln_file = os.path.join(vuln_dir, vuln_type, f"vulnerable_urls.txt")
            if os.path.exists(vuln_file):
                scan_data['vulnerabilities'][vuln_type] = load_targets_from_file(vuln_file)
    
    return scan_data

def continue_scan_from_directory(scan_dir):
    """Continue scanning from an existing scan directory"""
    print_colored(f"[+] Continuing scan from directory: {scan_dir}", Fore.CYAN)
    
    # Load existing scan data
    scan_data = load_scan_data(scan_dir)
    
    if not scan_data['domain']:
        print_colored("[!] Could not determine domain from directory name", Fore.RED)
        return
    
    domain = scan_data['domain']
    print_colored(f"[+] Detected domain: {domain}", Fore.GREEN)
    
    # Ask user what to continue with
    print_colored("\nSelect operations to continue:", Fore.CYAN)
    print_colored("[1] Extract more endpoints (requires existing subdomains)", Fore.WHITE)
    print_colored("[2] Extract sensitive information from endpoints", Fore.WHITE)
    print_colored("[3] Continue vulnerability scanning", Fore.WHITE)
    print_colored("[4] Run specialized vulnerability scanners", Fore.WHITE)
    print_colored("[5] All of the above", Fore.WHITE)
    
    choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter your choice (1-5): ")
    
    if choice in ['1', '5']:
        # Extract more endpoints from subdomains
        if scan_data['subdomains']:
            print_colored("\n[+] Extracting more endpoints from subdomains...", Fore.CYAN)
            new_endpoints = extract_endpoints(scan_data['subdomains'], scan_dir)
            combined_endpoints = list(set(scan_data['endpoints'] + new_endpoints))
            print_colored(f"[+] Found {len(combined_endpoints)} total endpoints ({len(new_endpoints)} new)", Fore.GREEN)
            
            # Filter newly discovered endpoints
            critical_endpoints = filter_endpoints(combined_endpoints, scan_dir)
            js_files = filter_js_files(combined_endpoints, scan_dir)
            scan_data['endpoints'] = combined_endpoints
            scan_data['critical_endpoints'] = critical_endpoints
            scan_data['js_files'] = js_files
        else:
            print_colored("[!] No subdomains found in previous scan", Fore.YELLOW)
    
    if choice in ['2', '5']:
        # Extract sensitive information from endpoints
        if scan_data['endpoints']:
            print_colored("\n[+] Extracting sensitive information from endpoints...", Fore.CYAN)
            extract_sensitive_info(scan_data['endpoints'], scan_dir)
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    
    if choice in ['3', '5']:
        # Continue vulnerability scanning
        if scan_data['critical_endpoints']:
            print_colored("\n[+] Continuing vulnerability scanning on critical endpoints...", Fore.CYAN)
            run_vulnerability_scan(scan_data['critical_endpoints'], scan_dir)
        elif scan_data['endpoints']:
            print_colored("\n[+] No critical endpoints found. Scanning all endpoints...", Fore.CYAN)
            # First filter to find critical ones
            critical_endpoints = filter_endpoints(scan_data['endpoints'], scan_dir)
            if critical_endpoints:
                run_vulnerability_scan(critical_endpoints, scan_dir)
            else:
                # If still no critical endpoints, use a sample of regular endpoints
                sample_size = min(50, len(scan_data['endpoints']))
                sample_endpoints = random.sample(scan_data['endpoints'], sample_size)
                print_colored(f"[+] Scanning sample of {sample_size} endpoints", Fore.CYAN)
                run_vulnerability_scan(sample_endpoints, scan_dir)
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    
    if choice in ['4', '5']:
        # Run specialized vulnerability scanners
        if scan_data['endpoints'] or scan_data['critical_endpoints']:
            targets = scan_data['critical_endpoints'] if scan_data['critical_endpoints'] else scan_data['endpoints']
            
            print_colored("\n[+] Select specialized vulnerability scanners to run:", Fore.CYAN)
            print_colored("[1] SQL Injection", Fore.WHITE)
            print_colored("[2] Cross-Site Scripting (XSS)", Fore.WHITE)
            print_colored("[3] Remote Code Execution (RCE)", Fore.WHITE)
            print_colored("[4] Local/Remote File Inclusion (LFI/RFI)", Fore.WHITE)
            print_colored("[5] Cross-Site Request Forgery (CSRF)", Fore.WHITE)
            print_colored("[6] Server-Side Request Forgery (SSRF)", Fore.WHITE)
            print_colored("[7] Insecure Direct Object References (IDOR)", Fore.WHITE)
            print_colored("[8] XML External Entity (XXE)", Fore.WHITE)
            print_colored("[9] Server-Side Template Injection (SSTI)", Fore.WHITE)
            print_colored("[10] JWT Vulnerabilities", Fore.WHITE)
            print_colored("[11] Authentication Vulnerabilities", Fore.WHITE)
            print_colored("[12] Comprehensive Nuclei Scan", Fore.WHITE)
            print_colored("[13] All of the above", Fore.WHITE)
            
            scanner_choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter your choice (1-13, or comma-separated list): ")
            
            # Process the choice
            if scanner_choice == '13':
                scanner_choices = list(range(1, 13))
            else:
                try:
                    # Handle comma-separated list
                    scanner_choices = [int(c.strip()) for c in scanner_choice.split(',') if c.strip().isdigit()]
                except:
                    scanner_choices = []
                    if scanner_choice.isdigit():
                        scanner_choices = [int(scanner_choice)]
            
            # Run selected scanners
            for choice in scanner_choices:
                if choice == 1:
                    print_colored("\n[+] Running SQL Injection scanner...", Fore.CYAN)
                    scan_sqli(targets, scan_dir)
                elif choice == 2:
                    print_colored("\n[+] Running XSS scanner...", Fore.CYAN)
                    scan_xss(targets, scan_dir)
                elif choice == 3:
                    print_colored("\n[+] Running RCE scanner...", Fore.CYAN)
                    scan_rce(targets, scan_dir)
                elif choice == 4:
                    print_colored("\n[+] Running LFI/RFI scanner...", Fore.CYAN)
                    scan_lfi(targets, scan_dir)
                elif choice == 5:
                    print_colored("\n[+] Running CSRF scanner...", Fore.CYAN)
                    scan_csrf(targets, scan_dir)
                elif choice == 6:
                    print_colored("\n[+] Running SSRF scanner...", Fore.CYAN)
                    scan_ssrf(targets, scan_dir)
                elif choice == 7:
                    print_colored("\n[+] Running IDOR scanner...", Fore.CYAN)
                    scan_idor(targets, scan_dir)
                elif choice == 8:
                    print_colored("\n[+] Running XXE scanner...", Fore.CYAN)
                    scan_xxe(targets, scan_dir)
                elif choice == 9:
                    print_colored("\n[+] Running SSTI scanner...", Fore.CYAN)
                    scan_ssti(targets, scan_dir)
                elif choice == 10:
                    print_colored("\n[+] Running JWT vulnerability scanner...", Fore.CYAN)
                    scan_jwt(targets, scan_dir)
                elif choice == 11:
                    print_colored("\n[+] Running authentication vulnerability scanner...", Fore.CYAN)
                    scan_broken_auth(targets, scan_dir)
                elif choice == 12:
                    print_colored("\n[+] Running comprehensive Nuclei scan...", Fore.CYAN)
                    run_nuclei_scan(targets, scan_dir)
        else:
            print_colored("[!] No endpoints found in previous scan", Fore.YELLOW)
    
    print_colored("\n[+] Continued scan completed successfully!", Fore.GREEN)

def run_domain_recon(domain, output_dir):
    """Run reconnaissance on a domain"""
    print_colored(f"\n[*] Starting reconnaissance for domain: {domain}", Fore.BLUE)
    
    # Create project directory
    project_dir = create_project_directory(output_dir, domain)
    
    # Step 1: Subdomain enumeration
    print_colored("\n[*] Step 1: Subdomain Enumeration", Fore.BLUE)
    passive_subdomains = passive_subdomain_enum(domain, project_dir)
    active_subdomains = active_subdomain_enum(domain, project_dir)
    
    # Combine and validate subdomains
    all_subdomains = list(set(passive_subdomains + active_subdomains))
    valid_subdomains = validate_subdomains(all_subdomains, project_dir)
    
    if not valid_subdomains:
        print_colored("[!] No valid subdomains found. Adding base domain for scanning.", Fore.YELLOW)
        valid_subdomains = [domain]
    
    # Step 2: Port scanning
    print_colored("\n[*] Step 2: Port Scanning", Fore.BLUE)
    perform_port_scan(valid_subdomains, project_dir)
    
    # Step 3: Technology detection
    print_colored("\n[*] Step 3: Technology Detection", Fore.BLUE)
    tech_results = detect_technologies(valid_subdomains, project_dir)
    
    # Step 4: Endpoint discovery
    print_colored("\n[*] Step 4: Endpoint Discovery", Fore.BLUE)
    all_endpoints = extract_endpoints(valid_subdomains, project_dir)
    
    # Filter critical endpoints and JS files
    critical_endpoints = filter_endpoints(all_endpoints, project_dir)
    js_files = filter_js_files(all_endpoints, project_dir)
    
    # Extract sensitive information
    extract_sensitive_info(all_endpoints, project_dir)
    
    # Step 5: Vulnerability scanning
    print_colored("\n[*] Step 5: Vulnerability Scanning", Fore.BLUE)
    run_vulnerability_scan(critical_endpoints, project_dir)
    
    # Step 6: OSINT
    print_colored("\n[*] Step 6: OSINT Information Gathering", Fore.BLUE)
    whois_data = whois_lookup(domain, project_dir)
    emails = email_finder(domain, project_dir)
    leaks = check_leaks(domain, project_dir)
    
    # Additional specialized scans based on user input
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    
    return {
        'project_dir': project_dir,
        'domain': domain,
        'subdomains': valid_subdomains,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files
    }

def run_ip_recon(ip, output_dir):
    """Run reconnaissance on an IP"""
    print_colored(f"\n[*] Starting reconnaissance for IP: {ip}", Fore.BLUE)
    
    # Create project directory
    project_dir = create_project_directory(output_dir, ip)
    
    # Step 1: Port scanning
    print_colored("\n[*] Step 1: Port Scanning", Fore.BLUE)
    perform_port_scan([ip], project_dir)
    
    # Step 2: Technology detection
    print_colored("\n[*] Step 2: Technology Detection", Fore.BLUE)
    tech_results = detect_technologies([f"http://{ip}", f"https://{ip}"], project_dir)
    
    # Step 3: Endpoint discovery
    print_colored("\n[*] Step 3: Endpoint Discovery", Fore.BLUE)
    all_endpoints = extract_endpoints([f"http://{ip}", f"https://{ip}"], project_dir)
    
    # Filter critical endpoints and JS files
    critical_endpoints = filter_endpoints(all_endpoints, project_dir)
    js_files = filter_js_files(all_endpoints, project_dir)
    
    # Step 4: Vulnerability scanning
    print_colored("\n[*] Step 4: Vulnerability Scanning", Fore.BLUE)
    if critical_endpoints:
        run_vulnerability_scan(critical_endpoints, project_dir)
    else:
        print_colored("[!] No critical endpoints found for vulnerability scanning", Fore.YELLOW)
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    
    return {
        'project_dir': project_dir,
        'ip': ip,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files
    }

def run_cidr_recon(cidr, output_dir):
    """Run reconnaissance on a CIDR range"""
    print_colored(f"\n[*] Starting reconnaissance for CIDR range: {cidr}", Fore.BLUE)
    
    # Parse CIDR to get list of IPs
    ips = parse_cidr(cidr)
    
    if not ips:
        print_colored("[!] No valid IPs found in the CIDR range", Fore.RED)
        return None
    
    # Create project directory
    project_dir = create_project_directory(output_dir, cidr.replace('/', '_'))
    
    # Step 1: Port scanning (sample for efficiency)
    print_colored("\n[*] Step 1: Port Scanning", Fore.BLUE)
    max_ips_to_scan = min(100, len(ips))  # Limit for large ranges
    ip_sample = ips[:max_ips_to_scan] if len(ips) > max_ips_to_scan else ips
    
    print_colored(f"[*] Scanning {len(ip_sample)} out of {len(ips)} IPs for ports", Fore.YELLOW)
    perform_port_scan(ip_sample, project_dir)
    
    # For the rest of the scans, we'll work with HTTP/HTTPS URLs
    http_targets = []
    for ip in ip_sample:
        http_targets.append(f"http://{ip}")
        http_targets.append(f"https://{ip}")
    
    # Step 2: Technology detection
    print_colored("\n[*] Step 2: Technology Detection", Fore.BLUE)
    tech_results = detect_technologies(http_targets, project_dir)
    
    # Step 3: Endpoint discovery
    print_colored("\n[*] Step 3: Endpoint Discovery", Fore.BLUE)
    all_endpoints = extract_endpoints(http_targets, project_dir)
    
    # Filter critical endpoints and JS files
    critical_endpoints = filter_endpoints(all_endpoints, project_dir)
    js_files = filter_js_files(all_endpoints, project_dir)
    
    # Step 4: Vulnerability scanning
    print_colored("\n[*] Step 4: Vulnerability Scanning", Fore.BLUE)
    if critical_endpoints:
        run_vulnerability_scan(critical_endpoints, project_dir)
    else:
        print_colored("[!] No critical endpoints found for vulnerability scanning", Fore.YELLOW)
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    
    return {
        'project_dir': project_dir,
        'cidr': cidr,
        'ips': ips,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files
    }

def run_wildcard_recon(wildcard, output_dir):
    """Run reconnaissance on a wildcard domain"""
    # Extract the base domain from the wildcard
    base_domain = wildcard.replace('*.', '')
    
    print_colored(f"\n[*] Starting reconnaissance for wildcard domain: {wildcard}", Fore.BLUE)
    
    # Create project directory
    project_dir = create_project_directory(output_dir, f"wildcard_{base_domain}")
    
    # Step 1: Subdomain enumeration (more aggressive for wildcards)
    print_colored("\n[*] Step 1: Subdomain Enumeration (Extended)", Fore.BLUE)
    passive_subdomains = passive_subdomain_enum(base_domain, project_dir)
    # Pass the wordlist_size parameter which is now handled in active_subdomain_enum
    active_subdomains = active_subdomain_enum(base_domain, project_dir, wordlist_size='large')
    
    # Combine and validate subdomains
    all_subdomains = list(set(passive_subdomains + active_subdomains))
    valid_subdomains = validate_subdomains(all_subdomains, project_dir)
    
    if not valid_subdomains:
        print_colored("[!] No valid subdomains found. Adding base domain for scanning.", Fore.YELLOW)
        valid_subdomains = [base_domain]
    
    # Continue with standard recon process
    # Step 2: Port scanning
    print_colored("\n[*] Step 2: Port Scanning", Fore.BLUE)
    perform_port_scan(valid_subdomains, project_dir)
    
    # Step 3: Technology detection
    print_colored("\n[*] Step 3: Technology Detection", Fore.BLUE)
    tech_results = detect_technologies(valid_subdomains, project_dir)
    
    # Step 4: Endpoint discovery
    print_colored("\n[*] Step 4: Endpoint Discovery", Fore.BLUE)
    all_endpoints = extract_endpoints(valid_subdomains, project_dir)
    
    # Filter critical endpoints and JS files
    critical_endpoints = filter_endpoints(all_endpoints, project_dir)
    js_files = filter_js_files(all_endpoints, project_dir)
    
    # Extract sensitive information
    extract_sensitive_info(all_endpoints, project_dir)
    
    # Step 5: Vulnerability scanning
    print_colored("\n[*] Step 5: Vulnerability Scanning", Fore.BLUE)
    run_vulnerability_scan(critical_endpoints, project_dir)
    
    # Step 6: OSINT
    print_colored("\n[*] Step 6: OSINT Information Gathering", Fore.BLUE)
    whois_data = whois_lookup(base_domain, project_dir)
    emails = email_finder(base_domain, project_dir)
    leaks = check_leaks(base_domain, project_dir)
    
    print_colored("\n[+] Reconnaissance completed successfully!", Fore.GREEN)
    
    return {
        'project_dir': project_dir,
        'wildcard': wildcard,
        'base_domain': base_domain,
        'subdomains': valid_subdomains,
        'endpoints': all_endpoints,
        'critical_endpoints': critical_endpoints,
        'js_files': js_files
    }

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Web-Hunter - Advanced Security Reconnaissance Tool")
    parser.add_argument("--domain", help="Target domain to scan")
    parser.add_argument("--cidr", help="Target CIDR range to scan")
    parser.add_argument("--ip", help="Target IP address to scan")
    parser.add_argument("--wildcard", help="Wildcard domain to scan")
    parser.add_argument("--wildcard-list", help="File containing wildcard domains")
    parser.add_argument("--output", help="Output directory", default="results")
    parser.add_argument("--continue-from", help="Continue from existing scan directory")
    parser.add_argument("--load-endpoints", help="Load endpoints from file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--subdomain-enum", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--port-scan", action="store_true", help="Run port scanning")
    parser.add_argument("--tech-detect", action="store_true", help="Run technology detection")
    parser.add_argument("--endpoints", action="store_true", help="Run endpoint discovery")
    parser.add_argument("--vuln-scan", action="store_true", help="Run vulnerability scanning")
    parser.add_argument("--bypass", action="store_true", help="Run bypass techniques")
    parser.add_argument("--cloud-assets", action="store_true", help="Run cloud asset discovery")
    parser.add_argument("--osint", action="store_true", help="Run OSINT modules")
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    
    return parser.parse_args()

def interactive_menu():
    """Display interactive menu for the tool with enhanced visuals"""
    options = {
        "1": "Domain Reconnaissance",
        "2": "IP/CIDR Reconnaissance",
        "3": "Wildcard Domain Reconnaissance",
        "4": "Continue from Existing Scan",
        "5": "Load Endpoints and Scan",
        "6": "Exit"
    }
    
    while True:
        print_colored("\n" + "╔" + "═" * 50 + "╗", Fore.MAGENTA)
        print_colored("║        Web-Hunter - Interactive Menu          ║", Fore.CYAN + Style.BRIGHT)
        print_colored("╚" + "═" * 50 + "╝", Fore.MAGENTA)
        
        for key, value in options.items():
            print_colored(f" [{Fore.CYAN}{key}{Fore.WHITE}] {value}", Fore.WHITE)
        
        choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter your choice (1-6): ")
        
        if choice == "1":
            domain = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter target domain: ")
            if validate_domain(domain):
                print_colored(f"\n[+] Setting up reconnaissance for {domain}", Fore.GREEN)
                run_domain_recon(domain, "results")
                break
            else:
                print_colored("[!] Invalid domain format. Please try again.", Fore.RED)
        
        elif choice == "2":
            ip_or_cidr = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter target IP or CIDR: ")
            if "/" in ip_or_cidr and parse_cidr(ip_or_cidr):
                print_colored(f"\n[+] Setting up reconnaissance for CIDR {ip_or_cidr}", Fore.GREEN)
                run_cidr_recon(ip_or_cidr, "results")
                break
            elif validate_ip(ip_or_cidr):
                print_colored(f"\n[+] Setting up reconnaissance for IP {ip_or_cidr}", Fore.GREEN)
                run_ip_recon(ip_or_cidr, "results")
                break
            else:
                print_colored("[!] Invalid IP or CIDR format. Please try again.", Fore.RED)
        
        elif choice == "3":
            wildcard = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter wildcard domain (e.g., *.example.com): ")
            if "*." in wildcard and validate_domain(wildcard.replace("*.", "")):
                print_colored(f"\n[+] Setting up reconnaissance for {wildcard}", Fore.GREEN)
                run_wildcard_recon(wildcard, "results")
                break
            else:
                print_colored("[!] Invalid wildcard format. Please try again.", Fore.RED)
        
        elif choice == "4":
            # Find existing scan directories
            existing_scans = find_existing_scans("results")
            
            if not existing_scans:
                print_colored("[!] No existing scan directories found in 'results' folder", Fore.YELLOW)
                continue
            
            print_colored("\nFound existing scan directories:", Fore.CYAN)
            for i, scan_dir in enumerate(existing_scans):
                print_colored(f"[{i+1}] {scan_dir}", Fore.WHITE)
            
            scan_choice = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter the number of the scan to continue from (or 'c' to cancel): ")
            
            if scan_choice.lower() == 'c':
                continue
            
            try:
                scan_index = int(scan_choice) - 1
                if 0 <= scan_index < len(existing_scans):
                    selected_dir = existing_scans[scan_index]
                    continue_scan_from_directory(selected_dir)
                    break
                else:
                    print_colored("[!] Invalid selection. Please try again.", Fore.RED)
            except ValueError:
                print_colored("[!] Invalid input. Please enter a number or 'c' to cancel.", Fore.RED)
        
        elif choice == "5":
            endpoints_file = input(f"\n{Fore.YELLOW}❯{Style.RESET_ALL} Enter path to endpoints file: ")
            if os.path.exists(endpoints_file):
                print_colored(f"\n[+] Setting up scan with endpoints from {endpoints_file}", Fore.GREEN)
                
                # Create project directory
                project_dir = create_project_directory("results", "endpoint_scan")
                
                # Load endpoints
                endpoints = load_targets_from_file(endpoints_file)
                
                # Save endpoints to project directory
                endpoints_dir = os.path.join(project_dir, "endpoints")
                if not os.path.exists(endpoints_dir):
                    os.makedirs(endpoints_dir)
                
                all_endpoints_file = os.path.join(endpoints_dir, "all_endpoints.txt")
                with open(all_endpoints_file, 'w') as f:
                    f.write('\n'.join(endpoints))
                
                # Filter endpoints
                critical_endpoints = filter_endpoints(endpoints, project_dir)
                
                # Run vulnerability scanning
                if critical_endpoints:
                    print_colored("\n[+] Running vulnerability scans on critical endpoints...", Fore.CYAN)
                    run_vulnerability_scan(critical_endpoints, project_dir)
                else:
                    print_colored("\n[!] No critical endpoints found. Scanning a sample of all endpoints...", Fore.YELLOW)
                    sample_size = min(50, len(endpoints))
                    sample_endpoints = random.sample(endpoints, sample_size)
                    run_vulnerability_scan(sample_endpoints, project_dir)
                
                break
            else:
                print_colored("[!] File not found. Please try again.", Fore.RED)
        
        elif choice == "6":
            print_colored("\n[*] Exiting Web-Hunter...", Fore.CYAN)
            display_thanks()
            sys.exit(0)
        
        else:
            print_colored("[!] Invalid choice. Please try again.", Fore.RED)

def main():
    """Main function to run the reconnaissance tool"""
    signal.signal(signal.SIGINT, signal_handler)
    
    # Display banner
    display_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Check if any arguments were provided
    has_target = any([args.domain, args.ip, args.cidr, args.wildcard, args.wildcard_list,
                     args.continue_from, args.load_endpoints])
    
    if has_target:
        # Process provided arguments
        output_dir = args.output
        
        if args.domain:
            if validate_domain(args.domain):
                run_domain_recon(args.domain, output_dir)
            else:
                print_colored("[!] Invalid domain format", Fore.RED)
                sys.exit(1)
        
        elif args.ip:
            if validate_ip(args.ip):
                run_ip_recon(args.ip, output_dir)
            else:
                print_colored("[!] Invalid IP format", Fore.RED)
                sys.exit(1)
        
        elif args.cidr:
            if parse_cidr(args.cidr):
                run_cidr_recon(args.cidr, output_dir)
            else:
                print_colored("[!] Invalid CIDR format", Fore.RED)
                sys.exit(1)
        
        elif args.wildcard:
            if "*." in args.wildcard and validate_domain(args.wildcard.replace("*.", "")):
                run_wildcard_recon(args.wildcard, output_dir)
            else:
                print_colored("[!] Invalid wildcard format", Fore.RED)
                sys.exit(1)
        
        elif args.wildcard_list:
            if os.path.exists(args.wildcard_list):
                wildcards = load_targets_from_file(args.wildcard_list)
                for wildcard in wildcards:
                    if "*." in wildcard and validate_domain(wildcard.replace("*.", "")):
                        run_wildcard_recon(wildcard, output_dir)
                    else:
                        print_colored(f"[!] Skipping invalid wildcard: {wildcard}", Fore.YELLOW)
            else:
                print_colored("[!] Wildcard list file not found", Fore.RED)
                sys.exit(1)
        
        elif args.continue_from:
            if os.path.exists(args.continue_from) and os.path.isdir(args.continue_from):
                continue_scan_from_directory(args.continue_from)
            else:
                print_colored("[!] Specified scan directory not found", Fore.RED)
                sys.exit(1)
        
        elif args.load_endpoints:
            if os.path.exists(args.load_endpoints):
                # Create project directory
                project_dir = create_project_directory(output_dir, "endpoint_scan")
                
                # Load endpoints
                endpoints = load_targets_from_file(args.load_endpoints)
                
                # Save endpoints to project directory
                endpoints_dir = os.path.join(project_dir, "endpoints")
                if not os.path.exists(endpoints_dir):
                    os.makedirs(endpoints_dir)
                
                all_endpoints_file = os.path.join(endpoints_dir, "all_endpoints.txt")
                with open(all_endpoints_file, 'w') as f:
                    f.write('\n'.join(endpoints))
                
                # Filter endpoints
                critical_endpoints = filter_endpoints(endpoints, project_dir)
                
                # Run vulnerability scanning
                if critical_endpoints:
                    print_colored("\n[+] Running vulnerability scans on critical endpoints...", Fore.CYAN)
                    run_vulnerability_scan(critical_endpoints, project_dir)
                else:
                    print_colored("\n[!] No critical endpoints found. Scanning a sample of all endpoints...", Fore.YELLOW)
                    sample_size = min(50, len(endpoints))
                    sample_endpoints = random.sample(endpoints, sample_size)
                    run_vulnerability_scan(sample_endpoints, project_dir)
            else:
                print_colored("[!] Endpoints file not found", Fore.RED)
                sys.exit(1)
    else:
        # No command line arguments provided, show interactive menu
        interactive_menu()

if __name__ == "__main__":
    main()
