FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    git \
    nmap \
    build-essential \
    perl \
    libnet-ssleay-perl \
    openssl \
    libwww-perl \
    python3-dev \
    libffi-dev \
    libssl-dev \
    cargo \
    unzip \
    masscan \
    subjack \
    && rm -rf /var/lib/apt/lists/*

# Install subfinder binary
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip && \
    unzip subfinder_2.6.3_linux_amd64.zip -d /usr/local/bin/ && \
    rm subfinder_2.6.3_linux_amd64.zip && \
    chmod +x /usr/local/bin/subfinder

# Install nuclei binary
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.6/nuclei_3.1.6_linux_amd64.zip && \
    unzip nuclei_3.1.6_linux_amd64.zip -d /usr/local/bin/ && \
    rm nuclei_3.1.6_linux_amd64.zip && \
    chmod +x /usr/local/bin/nuclei

# Install httpx binary
RUN wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.8/httpx_1.3.8_linux_amd64.zip && \
    unzip -o httpx_1.3.8_linux_amd64.zip -d /usr/local/bin/ && \
    rm httpx_1.3.8_linux_amd64.zip && \
    chmod +x /usr/local/bin/httpx

# Set working directory
WORKDIR /app

# Install Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Install Gitleaks with updated version
RUN wget https://github.com/zricethezav/gitleaks/releases/download/v8.24.2/gitleaks_8.24.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.24.2_linux_x64.tar.gz -C /usr/local/bin/ && \
    rm gitleaks_8.24.2_linux_x64.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Copy project files
COPY . .

# Install Python dependencies and the webhunter package
RUN pip install --upgrade pip && \
    pip install wheel setuptools && \
    pip install --no-cache-dir -r requirements.txt && \
    python setup.py develop

# Create necessary directories
RUN mkdir -p results config/wordlists config/nuclei-templates

ENTRYPOINT ["python", "webhunter/cli.py"]

