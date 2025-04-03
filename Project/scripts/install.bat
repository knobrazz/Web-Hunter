@echo off
echo Installing Web-Hunter dependencies...

:: Check Python installation
python --version 2>NUL
if errorlevel 1 (
    echo Python is not installed! Please install Python 3.8 or later.
    exit /b 1
)

:: Install Python dependencies
echo Installing Python packages...
pip install -r ..\requirements.txt

:: Create necessary directories
echo Creating directories...
mkdir ..\results 2>NUL
mkdir ..\config\wordlists 2>NUL
mkdir ..\config\nuclei-templates 2>NUL

:: Install external tools
echo Installing external tools...
:: Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

:: Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo Installation completed!

