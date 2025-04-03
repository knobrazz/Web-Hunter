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

import subprocess
import sys
import os
from pathlib import Path

def install_requirements():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def install_tools():
    # Install Go if not installed
    try:
        subprocess.run(["go", "version"], check=True)
    except:
        print("Please install Go from: https://golang.org/dl/")
        sys.exit(1)

    # Install subfinder
    subprocess.run(["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"])

    # Install nmap
    print("Please install Nmap from: https://nmap.org/download.html")

def main():
    print("Installing Web-Hunter dependencies...")
    install_requirements()
    install_tools()
    print("Installation completed!")

if __name__ == "__main__":
    main()

