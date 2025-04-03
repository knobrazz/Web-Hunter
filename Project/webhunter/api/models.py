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

from pydantic import BaseModel, HttpUrl, validator
from typing import List, Optional, Dict
from enum import Enum
import re
from datetime import datetime  # Add this import

class ScanModules(str, Enum):
    SUBDOMAIN = "subdomain"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    CLOUD = "cloud"
    TAKEOVER = "takeover"
    JS = "js"

class ScanRequest(BaseModel):
    domain: Optional[str]
    wildcard: Optional[str]
    ip: Optional[str]
    cidr: Optional[str]
    modules: Optional[List[ScanModules]]
    
    @validator('domain')
    def validate_domain(cls, v):
        if v and not re.match(r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$', v):
            raise ValueError('Invalid domain format')
        return v

class ScanResult(BaseModel):
    scan_id: str
    status: str
    message: str
    timestamp: datetime
    results: Optional[Dict]

class ScanStatus(BaseModel):
    status: str
    progress: Optional[float]
    current_module: Optional[str]
    errors: Optional[List[str]]
    start_time: Optional[datetime]
    estimated_completion: Optional[datetime]

