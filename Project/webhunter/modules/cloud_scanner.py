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
from ..core.utils import ToolRunner

class CloudScanner:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    async def scan_cloud_assets(self, domain: str) -> Dict:
        results = {
            'aws': await self.scan_aws(domain),
            'gcp': await self.scan_gcp(domain),
            'azure': await self.scan_azure(domain)
        }
        
        self.save_results(results)
        return results

    async def scan_aws(self, domain: str) -> Dict:
        try:
            s3_buckets = await self.find_s3_buckets(domain)
            cloudfront = await self.scan_cloudfront(domain)
            return {
                's3_buckets': s3_buckets,
                'cloudfront': cloudfront
            }
        except Exception as e:
            logging.error(f"AWS scan failed: {e}")
            return {'error': str(e)}

    async def scan_gcp(self, domain: str) -> Dict:
        storage_buckets = await self.find_gcp_buckets(domain)
        return {
            'storage_buckets': storage_buckets
        }

    async def scan_azure(self, domain: str) -> Dict:
        blob_storage = await self.find_azure_blobs(domain)
        return {
            'blob_storage': blob_storage
        }

