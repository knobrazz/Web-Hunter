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
from typing import Dict, List
import json
from ..core.utils import ToolRunner
import re
import httpx
from datetime import datetime
from ..core.utils import RateLimiter
import tenacity

class TakeoverChecker:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.fingerprints = self.load_fingerprints()
        self.results_file = self.output_dir / "takeover_results.json"
        self.rate_limiter = RateLimiter(10)  # 10 requests per second
        self.logger = logging.getLogger(__name__)

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=4, max=10)
    )
    async def run_can_i_take_over_x(self, subdomains: List[str]) -> List[Dict]:
        results = []
        for subdomain in subdomains:
            await self.rate_limiter.wait()
            for service, fingerprint in self.fingerprints.items():
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.get(f"https://{subdomain}")
                        if fingerprint in resp.text:
                            results.append({
                                'subdomain': subdomain,
                                'tool': 'custom_checker',
                                'service': service,
                                'vulnerable': True,
                                'fingerprint': fingerprint
                            })
                except Exception as e:
                    self.logger.error(f"Error checking {subdomain}: {e}")
                    continue
        return results

    def load_fingerprints(self) -> Dict:
        fingerprints_file = Path("config/takeover-fingerprints.json")
        if fingerprints_file.exists():
            with open(fingerprints_file) as f:
                return json.load(f)
        return {}

    async def check_takeover(self, subdomains: List[str]) -> List[Dict]:
        results = []
        
        # Run parallel checks using different tools
        tool_results = await asyncio.gather(
            self.run_subjack(subdomains),
            self.run_nuclei_takeover(subdomains),
            self.run_can_i_take_over_x(subdomains),
            self.check_cloud_services(subdomains),
            return_exceptions=True
        )
        
        for result in tool_results:
            if isinstance(result, list):
                results.extend(result)
        
        self.save_results(results)
        return results

    async def run_subjack(self, subdomains: List[str]) -> List[Dict]:
        results = []
        for subdomain in subdomains:
            try:
                command = ["subjack", "-d", subdomain, "-ssl", "-v", "-timeout", "30"]
                stdout, _ = await ToolRunner.run_command(command)
                
                if stdout:
                    results.append({
                        'subdomain': subdomain,
                        'tool': 'subjack',
                        'vulnerable': True,
                        'details': stdout
                    })
            except Exception as e:
                print(f"Error running subjack on {subdomain}: {e}")
        return results

    async def run_nuclei_takeover(self, subdomains: List[str]) -> List[Dict]:
        try:
            subdomains_file = self.output_dir / "temp_subdomains.txt"
            with open(subdomains_file, 'w') as f:
                f.write('\n'.join(subdomains))

            command = [
                "nuclei",
                "-l", str(subdomains_file),
                "-t", "takeovers/",
                "-severity", "critical,high",
                "-json"
            ]
            stdout, _ = await ToolRunner.run_command(command)
            subdomains_file.unlink()  # Clean up temporary file
            
            if stdout:
                results = json.loads(stdout)
                return [{'tool': 'nuclei', **result} for result in results]
        except Exception as e:
            print(f"Error running nuclei: {e}")
        return []

    async def check_cloud_services(self, subdomains: List[str]) -> List[Dict]:
        results = []
        cloud_services = {
            'aws': r'\.amazonaws\.com$',
            'azure': r'\.azurewebsites\.net$',
            'gcp': r'\.googleapis\.com$',
            'heroku': r'\.herokuapp\.com$'
        }
        
        for subdomain in subdomains:
            for service, pattern in cloud_services.items():
                if re.search(pattern, subdomain):
                    results.append({
                        'subdomain': subdomain,
                        'tool': 'cloud_checker',
                        'service': service,
                        'vulnerable': True
                    })
        return results

    def save_results(self, results: List[Dict]):
        with open(self.results_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'results': results,
                'total_vulnerabilities': len(results)
            }, f, indent=4)

