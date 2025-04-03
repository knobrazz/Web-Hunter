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

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Security
from typing import List, Optional, Dict
from .models import ScanRequest, ScanResult, ScanStatus
from ..core.scanner import Scanner, ScanTarget
from ..core.utils import generate_scan_id
import asyncio
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
import json
from pathlib import Path

app = FastAPI(
    title="Web-Hunter API",
    description="Security reconnaissance and vulnerability scanning API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = "your-secure-api-key"  # In production, use environment variables
api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    return api_key

@app.post("/scan", response_model=ScanResult)
async def start_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    try:
        scan_id = generate_scan_id()
        target = ScanTarget(
            domain=scan_request.domain,
            wildcard=scan_request.wildcard,
            ip=scan_request.ip,
            cidr=scan_request.cidr
        )
        
        scanner = Scanner(target, f"results/{scan_id}")
        background_tasks.add_task(scanner.start_scan, scan_request.modules)
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": "Scan started successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/results/{scan_id}", response_model=Dict)
async def get_results(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    try:
        results_dir = Path(f"results/{scan_id}")
        if not results_dir.exists():
            raise HTTPException(status_code=404, detail="Scan not found")

        summary_file = results_dir / "summary.json"
        if not summary_file.exists():
            return {
                "scan_id": scan_id,
                "status": "in_progress",
                "message": "Scan is still running"
            }

        with open(summary_file) as f:
            results = json.load(f)
            return {
                "scan_id": scan_id,
                "status": "completed",
                "results": results
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status/{scan_id}", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    try:
        results_dir = Path(f"results/{scan_id}")
        if not results_dir.exists():
            raise HTTPException(status_code=404, detail="Scan not found")

        status_file = results_dir / "status.json"
        if not status_file.exists():
            return {"status": "initializing"}

        with open(status_file) as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

