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
import venv
from pathlib import Path

def create_venv():
    """Create and activate virtual environment"""
    venv_path = Path("venv")
    if not venv_path.exists():
        print("Creating virtual environment...")
        venv.create(venv_path, with_pip=True)
    
    # Get the path to the virtual environment's Python executable
    if os.name == 'nt':  # Windows
        python_path = venv_path / "Scripts" / "python.exe"
        pip_path = venv_path / "Scripts" / "pip.exe"
    else:  # Linux/Unix
        python_path = venv_path / "bin" / "python"
        pip_path = venv_path / "bin" / "pip"
    
    return python_path, pip_path

def install_requirements(python_path, pip_path):
    try:
        # Install build dependencies first
        subprocess.check_call([str(pip_path), "install", "--upgrade", "pip", "setuptools", "wheel"])
        
        # Install Cython and PyYAML separately first
        subprocess.check_call([str(pip_path), "install", "cython"])
        subprocess.check_call([str(pip_path), "install", "--no-build-isolation", "pyyaml"])
        
        # Then install remaining project requirements
        with open("requirements.txt") as f:
            reqs = [line.strip() for line in f if "pyyaml" not in line.lower()]
        
        for req in reqs:
            if req and not req.startswith("#"):
                try:
                    subprocess.check_call([str(pip_path), "install", req])
                except subprocess.CalledProcessError:
                    print(f"Failed to install {req}, continuing...")
                    continue
                    
    except subprocess.CalledProcessError as e:
        print(f"Error installing requirements: {e}")
        print("\nTrying to install system dependencies...")
        try:
            # For Ubuntu/Debian systems
            subprocess.check_call(["sudo", "apt-get", "update"])
            subprocess.check_call(["sudo", "apt-get", "install", "-y", 
                                 "python3-dev", "build-essential", "libyaml-dev"])
            # Try installing requirements again
            subprocess.check_call([str(pip_path), "install", "-r", "requirements.txt"])
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            sys.exit(1)

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

def install_dependencies(python_path, pip_path):
    try:
        # Create __init__.py files to make webhunter a proper package
        Path("webhunter/__init__.py").touch()
        Path("webhunter/core/__init__.py").touch()
        Path("webhunter/modules/__init__.py").touch()
        
        # Ensure pyproject.toml exists and is valid
        if not Path("pyproject.toml").exists():
            print("Creating pyproject.toml...")
            with open("pyproject.toml", "w") as f:
                f.write('''[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "webhunter"
version = "1.0.0"
description = "Advanced Web Reconnaissance Tool"
requires-python = ">=3.8"
license = {text = "Apache-2.0"}
''')
        
        # Install the package in development mode
        subprocess.run([str(pip_path), "install", "-e", "."], check=True)
        
        # Add the project directory to PYTHONPATH
        project_dir = Path.cwd()
        os.environ["PYTHONPATH"] = str(project_dir)
            
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        sys.exit(1)

def create_directories():
    dirs = [
        "results",
        "config/wordlists",
        "config/nuclei-templates"
    ]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)

if __name__ == "__main__":
    create_directories()
    python_path, pip_path = create_venv()
    install_requirements(python_path, pip_path)
    install_tools()
    install_dependencies(python_path, pip_path)
    print("\nInstallation completed successfully!")
    print("\nTo activate the virtual environment:")
    if os.name == 'nt':
        print("    venv\\Scripts\\activate")
    else:
        print("    source venv/bin/activate")

