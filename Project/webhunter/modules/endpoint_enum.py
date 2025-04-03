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

import asyncio
from pathlib import Path
from typing import List, Set
from ..core.utils import ToolRunner, RateLimiter
import re

class EndpointEnumerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.rate_limiter = RateLimiter(10)
        self.excluded_extensions = r'\.(jpg|jpeg|png|gif|css|js|woff|woff2|ttf|eot|svg|pdf)$'

    async def enumerate_endpoints(self, targets: List[str]) -> Set[str]:
        all_endpoints = set()
        
        for target in targets:
            endpoints = await asyncio.gather(
                self.run_waybackurls(target),
                self.run_katana(target),
                self.run_hakrawler(target),
                self.run_paramspider(target),
                self.run_dirsearch(target)
            )
            
            for endpoint_set in endpoints:
                all_endpoints.update(endpoint_set)

        filtered_endpoints = self.filter_endpoints(all_endpoints)
        self.save_results(filtered_endpoints)
        return filtered_endpoints

    def filter_endpoints(self, endpoints: Set[str]) -> Set[str]:
        filtered = {
            endpoint for endpoint in endpoints
            if not re.search(self.excluded_extensions, endpoint, re.I)
        }
        return filtered

    async def run_waybackurls(self, target: str) -> Set[str]:
        command = ["waybackurls", target]
        stdout, _ = await ToolRunner.run_command(command)
        return set(stdout.splitlines())

    # Similar implementations for other tools...

