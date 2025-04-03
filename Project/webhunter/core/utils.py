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
import subprocess
import time
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime
import shutil  # Add at the top with other imports

class ToolRunner:
    @staticmethod
    def check_tool_exists(tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    @staticmethod
    async def run_command(command, timeout=300, check_return=True):
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            if check_return and process.returncode != 0:
                raise RuntimeError(f"Command failed: {stderr.decode()}")
                
            return stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"Command timed out after {timeout} seconds")

    @staticmethod
    def ensure_tool_installed(tool_name: str) -> bool:
        if not ToolRunner.check_tool_exists(tool_name):
            print(f"[!] {tool_name} not found. Please install it first.")
            return False
        return True


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.rate = requests_per_second
        self.last_request = 0

    async def wait(self):
        now = time.time()
        wait_time = max(0, 1/self.rate - (now - self.last_request))
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        self.last_request = time.time()

class Logger:
    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.setup_logging()

    def setup_logging(self):
        log_file = self.log_dir / f"webhunter_{datetime.now():%Y%m%d}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )

