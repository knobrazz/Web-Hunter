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

# Install Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Create virtual environment and install dependencies
RUN python -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip setuptools wheel && \
    pip install -e .

# Set environment variables
ENV PATH="/root/go/bin:${PATH}"
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Entry point
ENTRYPOINT ["venv/bin/python", "-m", "webhunter.cli"]

