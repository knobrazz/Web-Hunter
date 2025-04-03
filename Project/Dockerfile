FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    golang \
    git \
    wget \
    nmap \
    build-essential \
    perl \
    libnet-ssleay-perl \
    openssl \
    libwww-perl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

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
RUN go install -v github.com/haccer/subjack@latest

# Install additional tools via go
RUN GO111MODULE=on go install -v github.com/projectdiscovery/masscan@latest

# Create necessary directories
RUN mkdir -p results config/wordlists config/nuclei-templates

# Set environment variables
ENV PATH="/root/go/bin:${PATH}"
ENV GOPATH=/root/go
ENV GOBIN=/root/go/bin

ENTRYPOINT ["python", "webhunter/cli.py"]

