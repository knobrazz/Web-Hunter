FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    golang \
    git \
    wget \
    nmap \
    nikto \
    wapiti \
    masscan \
    dalfox \
    subjack \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Go tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/amass/v3/...@latest
RUN go install -v github.com/hahwul/dalfox/v2@latest

# Create necessary directories
RUN mkdir -p results config/wordlists config/nuclei-templates

# Set environment variables
ENV PATH="/root/go/bin:${PATH}"

ENTRYPOINT ["python", "webhunter/cli.py"]

