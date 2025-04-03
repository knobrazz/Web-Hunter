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

def install_dependencies():
    try:
        # Create __init__.py files to make webhunter a proper package
        Path("webhunter/__init__.py").touch()
        Path("webhunter/core/__init__.py").touch()
        Path("webhunter/modules/__init__.py").touch()
        
        # Install the package in development mode
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], check=True)
        
        # Add the project directory to PYTHONPATH
        project_dir = Path.cwd()
        if "PYTHONPATH" in os.environ:
            os.environ["PYTHONPATH"] = f"{project_dir};{os.environ['PYTHONPATH']}"
        else:
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
    install_requirements()
    install_tools()
    install_dependencies()
    print("Installation completed successfully!")
