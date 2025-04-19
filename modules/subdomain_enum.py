
#!/usr/bin/env python3
"""
Subdomain enumeration module for Web-Hunter
"""

import os
import subprocess
import concurrent.futures
import random
import dns.resolver
from colorama import Fore
from .utils import print_colored, show_progress, save_to_file, check_command, get_command_output

def passive_subdomain_enum(domain, output_dir):
    """Perform passive subdomain enumeration"""
    print_colored("[*] Starting passive subdomain enumeration...", Fore.BLUE)
    
    subdomains = []
    subdomains_dir = os.path.join(output_dir, "subdomains")
    
    # Create output files
    crtsh_file = os.path.join(subdomains_dir, "crtsh.txt")
    virustotal_file = os.path.join(subdomains_dir, "virustotal.txt")
    subfinder_file = os.path.join(subdomains_dir, "subfinder.txt")
    assetfinder_file = os.path.join(subdomains_dir, "assetfinder.txt")
    
    # Check for tools
    tools = {
        "subfinder": check_command("subfinder"),
        "assetfinder": check_command("assetfinder"),
        "curl": check_command("curl")
    }
    
    if not any(tools.values()):
        print_colored("[!] No subdomain enumeration tools found. Please install at least one of: subfinder, assetfinder, curl", Fore.RED)
        return []
    
    # Functions for each source
    def get_crtsh():
        """Get subdomains from crt.sh"""
        if tools["curl"]:
            try:
                cmd = f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' | jq -r '.[].name_value' | sort -u"
                output = get_command_output(cmd)
                if output:
                    result = [line for line in output.split('\n') if line.strip() and line.endswith(f".{domain}")]
                    save_to_file(result, crtsh_file)
                    return result
            except Exception:
                # Silently continue on error
                pass
        return []
    
    def get_virustotal():
        """Get subdomains from VirusTotal (requires API key in env vars)"""
        vt_api_key = os.environ.get("VT_API_KEY")
        if tools["curl"] and vt_api_key:
            try:
                cmd = f"curl -s -H 'x-apikey: {vt_api_key}' https://www.virustotal.com/api/v3/domains/{domain}/subdomains | jq -r '.data[].id'"
                output = get_command_output(cmd)
                if output:
                    result = [line for line in output.split('\n') if line.strip()]
                    save_to_file(result, virustotal_file)
                    return result
            except Exception:
                # Silently continue on error
                pass
        return []
    
    def get_subfinder():
        """Get subdomains from subfinder"""
        if tools["subfinder"]:
            try:
                cmd = f"subfinder -d {domain} -silent"
                output = get_command_output(cmd)
                if output:
                    result = [line for line in output.split('\n') if line.strip()]
                    save_to_file(result, subfinder_file)
                    return result
            except Exception:
                # Silently continue on error
                pass
        return []
    
    def get_assetfinder():
        """Get subdomains from assetfinder"""
        if tools["assetfinder"]:
            try:
                cmd = f"assetfinder --subs-only {domain}"
                output = get_command_output(cmd)
                if output:
                    result = [line for line in output.split('\n') if line.strip() and line.endswith(f".{domain}")]
                    save_to_file(result, assetfinder_file)
                    return result
            except Exception:
                # Silently continue on error
                pass
        return []
    
    # Run all sources in parallel
    sources = [get_crtsh, get_virustotal, get_subfinder, get_assetfinder]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
        results = list(executor.map(lambda f: f(), sources))
    
    # Combine results
    for result in results:
        subdomains.extend(result)
    
    # Remove duplicates
    subdomains = list(set(subdomains))
    
    # Save combined results
    all_passive_file = os.path.join(subdomains_dir, "all_passive.txt")
    save_to_file(subdomains, all_passive_file)
    
    print_colored(f"[+] Found {len(subdomains)} unique subdomains from passive sources", Fore.GREEN)
    return subdomains

def active_subdomain_enum(domain, output_dir, wordlist_size=None):
    """Perform active subdomain enumeration
    
    Args:
        domain: Target domain
        output_dir: Directory to save output
        wordlist_size: Size of wordlist to use (None, 'small', 'medium', 'large')
    """
    print_colored("[*] Starting active subdomain enumeration...", Fore.BLUE)
    
    subdomains = []
    subdomains_dir = os.path.join(output_dir, "subdomains")
    
    # Create output files
    bruteforce_file = os.path.join(subdomains_dir, "bruteforce.txt")
    dns_file = os.path.join(subdomains_dir, "dns.txt")
    
    # Create a wordlist of common subdomains based on size
    wordlist_path = os.path.join(subdomains_dir, "wordlist.txt")
    
    # Default subdomains (common ones)
    common_subdomains = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", 
                        "vpn", "app", "api", "dev", "test", "portal", "admin", "mobile", "m", "shop", "ftp", 
                        "ssh", "webdisk", "pop", "cpanel", "whm", "support", "status", "staging", "news",
                        "demo", "docs", "wiki", "help", "login", "auth", "cdn", "beta", "stage", "internal",
                        "media", "files", "forum", "store", "git", "host", "web", "cloud", "proxy", "crm",
                        "monitor", "control", "intranet", "backup", "exchange", "public", "private", "vpn2"]
    
    # Add more subdomains if larger wordlist is requested
    if wordlist_size == 'medium':
        common_subdomains.extend([
            "analytics", "dashboard", "services", "static", "assets", "img", "images", "upload", "downloads",
            "database", "sql", "mysql", "oracle", "payment", "billing", "pay", "checkout", "cart", "shop",
            "store", "market", "sales", "marketing", "affiliate", "partner", "reseller", "customer", "client",
            "user", "account", "profile", "member", "staff", "employee", "hr", "finance", "accounting", "legal",
            "compliance", "security", "it", "tech", "support", "helpdesk", "tickets", "chat", "webinar", "meet"
        ])
    elif wordlist_size == 'large':
        # Medium wordlist + even more subdomains
        common_subdomains.extend([
            "analytics", "dashboard", "services", "static", "assets", "img", "images", "upload", "downloads",
            "database", "sql", "mysql", "oracle", "payment", "billing", "pay", "checkout", "cart", "shop",
            "store", "market", "sales", "marketing", "affiliate", "partner", "reseller", "customer", "client",
            "user", "account", "profile", "member", "staff", "employee", "hr", "finance", "accounting", "legal",
            "compliance", "security", "it", "tech", "support", "helpdesk", "tickets", "chat", "webinar", "meet",
            "legacy", "old", "new", "dev1", "dev2", "qa", "stage1", "stage2", "uat", "prod", "production",
            "development", "testing", "jenkins", "ci", "cd", "build", "jira", "confluence", "wiki1", "wiki2",
            "gitlab", "github", "bitbucket", "svn", "cvs", "repos", "repository", "digital", "mobile1", "mobile2",
            "ios", "android", "app1", "app2", "api1", "api2", "graphql", "rest", "soap", "grpc", "data", "ml",
            "ai", "auth1", "auth2", "login1", "login2", "sso", "jwt", "oauth", "signup", "register", "signin",
            "crm1", "crm2", "erp", "inventory", "orders", "products", "catalog", "cms", "wordpress", "drupal",
            "joomla", "magento", "shopify", "wix", "squarespace", "woocommerce", "prestashop", "opencart",
            "europe", "asia", "us", "usa", "uk", "canada", "australia", "germany", "france", "spain", "italy",
            "japan", "china", "india", "brazil", "mexico", "russia", "africa", "sandbox", "preview", "preprod"
        ])
    
    # Remove duplicates
    common_subdomains = list(set(common_subdomains))
    save_to_file(common_subdomains, wordlist_path)
    
    print_colored(f"[*] Using built-in DNS resolver for subdomain discovery with {len(common_subdomains)} common subdomains...", Fore.BLUE)
    
    # Set up DNS resolver
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']  # Public DNS servers
    
    # Function to check if a subdomain resolves
    def check_subdomain(subdomain):
        full_domain = f"{subdomain}.{domain}"
        try:
            resolver.resolve(full_domain, 'A')
            return full_domain
        except Exception:
            try:
                resolver.resolve(full_domain, 'CNAME')
                return full_domain
            except Exception:
                return None
    
    # Bruteforce subdomains
    valid_subdomains = []
    progress = show_progress(len(common_subdomains), "Bruteforcing subdomains")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_subdomain, common_subdomains))
        
        for result in results:
            progress.update(1)
            if result:
                valid_subdomains.append(result)
    
    progress.close()
    
    # Save bruteforced subdomains
    save_to_file(valid_subdomains, bruteforce_file)
    
    # Also try DNS enumeration techniques
    print_colored("[*] Attempting DNS zone transfer...", Fore.BLUE)
    
    try:
        # Try to get NS records
        ns_records = []
        try:
            answers = resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_records.append(str(rdata))
        except Exception:
            pass
        
        # Try zone transfer from each NS
        more_subdomains = []
        for ns in ns_records:
            if check_command("dig"):
                try:
                    cmd = f"dig @{ns} {domain} AXFR"
                    output = get_command_output(cmd)
                    if output and "Transfer failed" not in output:
                        # Extract domains from successful zone transfer
                        for line in output.split('\n'):
                            if domain in line and "IN" in line:
                                parts = line.split()
                                if len(parts) >= 1:
                                    candidate = parts[0].strip()
                                    if candidate.endswith('.'):
                                        candidate = candidate[:-1]
                                    if domain in candidate and candidate != domain:
                                        more_subdomains.append(candidate)
                except Exception:
                    # Silently continue on error
                    pass
        
        valid_subdomains.extend(more_subdomains)
    except Exception:
        # Silently continue on error
        pass
    
    # Save DNS results
    save_to_file(more_subdomains, dns_file)
    
    # Remove duplicates
    valid_subdomains = list(set(valid_subdomains))
    
    # Save all active results
    all_active_file = os.path.join(subdomains_dir, "all_active.txt")
    save_to_file(valid_subdomains, all_active_file)
    
    print_colored(f"[+] Found {len(valid_subdomains)} unique subdomains from active enumeration", Fore.GREEN)
    return valid_subdomains

def validate_subdomains(subdomains, output_dir):
    """Validate subdomains using httpx"""
    print_colored("[*] Validating subdomains...", Fore.BLUE)
    
    subdomains_dir = os.path.join(output_dir, "subdomains")
    
    # Create temporary file with all subdomains
    temp_file = os.path.join(subdomains_dir, "all_subdomains.txt")
    save_to_file(subdomains, temp_file)
    
    valid_subdomains = []
    
    # Check for httpx
    if check_command("httpx"):
        try:
            cmd = f"cat {temp_file} | httpx -silent -fc 404"
            output = get_command_output(cmd)
            if output:
                valid_subdomains = [line.strip() for line in output.split('\n') if line.strip()]
        except Exception:
            # Fall back to basic HTTP requests if httpx fails
            print_colored("[!] httpx failed, attempting to validate using basic HTTP requests", Fore.YELLOW)
            valid_subdomains = basic_validation(subdomains)
    else:
        print_colored("[!] httpx not found, attempting to validate using basic HTTP requests", Fore.YELLOW)
        valid_subdomains = basic_validation(subdomains)
    
    # Save valid subdomains
    valid_file = os.path.join(subdomains_dir, "valid_subdomains.txt")
    save_to_file(valid_subdomains, valid_file)
    
    print_colored(f"[+] Validated {len(valid_subdomains)} live subdomains out of {len(subdomains)}", Fore.GREEN)
    return valid_subdomains

def basic_validation(subdomains):
    """Validate subdomains using basic HTTP requests"""
    valid_subdomains = []
    
    import requests
    from concurrent.futures import ThreadPoolExecutor
    from urllib3.exceptions import InsecureRequestWarning
    
    # Suppress only the single InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    def check_subdomain(subdomain):
        try:
            protocols = ["https://", "http://"]
            for protocol in protocols:
                url = f"{protocol}{subdomain}"
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code != 404:
                    return url
            return None
        except Exception:
            return None
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_subdomain, subdomains))
    
    valid_subdomains = [result for result in results if result]
    return valid_subdomains

