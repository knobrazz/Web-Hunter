import os
import sys
import json
import subprocess
from pathlib import Path
import requests

class WebHunterUpdater:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.config_dir = self.base_dir / "config"
        self.tools_dir = self.base_dir / "tools"

    def update_python_packages(self):
        print("Updating Python packages...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", 
                       str(self.base_dir / "requirements.txt"), "--upgrade"])

    def update_nuclei_templates(self):
        print("Updating Nuclei templates...")
        templates_dir = self.config_dir / "nuclei-templates"
        subprocess.run(["nuclei", "-update-templates"])
        
        # Update custom templates
        custom_templates = templates_dir / "custom"
        if custom_templates.exists():
            print("Backing up custom templates...")
            backup_dir = templates_dir / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_dir.mkdir(parents=True, exist_ok=True)
            for template in custom_templates.glob("*.yaml"):
                shutil.copy2(template, backup_dir)

    def update_wordlists(self):
        print("Updating wordlists...")
        wordlists = {
            "subdomains.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            "endpoints.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        }
        
        for filename, url in wordlists.items():
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    with open(self.config_dir / "wordlists" / filename, "wb") as f:
                        f.write(response.content)
            except Exception as e:
                print(f"Error updating {filename}: {e}")

    def update_tools(self):
        print("Updating external tools...")
        tools = [
            "subfinder",
            "nuclei",
            "httpx",
            "amass"
        ]
        
        for tool in tools:
            subprocess.run(["go", "install", "-v", f"github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest"])

    def run_update(self):
        print("Starting Web-Hunter update process...")
        self.update_python_packages()
        self.update_nuclei_templates()
        self.update_wordlists()
        self.update_tools()
        print("Update completed successfully!")

if __name__ == "__main__":
    updater = WebHunterUpdater()
    updater.run_update()

