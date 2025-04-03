FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    golang \
    nmap \
    python3-dev \
    build-essential \
    libyaml-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up Go environment
ENV GOPATH /root/go
ENV PATH $GOPATH/bin:$PATH

# Install Go tools
RUN mkdir -p $GOPATH && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Create virtual environment and install dependencies
RUN python -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip setuptools wheel && \
    pip install -e .

# Set Python environment
ENV PYTHONPATH /app

# Entry point
ENTRYPOINT ["venv/bin/python", "-m", "webhunter.cli"]

