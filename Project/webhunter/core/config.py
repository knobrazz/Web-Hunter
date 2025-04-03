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


import yaml
import shutil
from pathlib import Path
from typing import Dict, Any, List

class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config = self.load_config()
        self.validate_config()

    def validate_config(self):
        required_sections = ['scanner', 'modules', 'output']
        optional_sections = ['api', 'webhooks', 'reporting']
        
        # Check required sections
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required config section: {section}")
        
        # Validate scanner settings
        scanner_settings = self.config.get('scanner', {})
        if not isinstance(scanner_settings.get('threads', 0), int):
            raise ValueError("Scanner threads must be an integer")

    def load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return self.create_default_config()
        
        with open(self.config_path) as f:
            return yaml.safe_load(f)

    def create_default_config(self) -> Dict[str, Any]:
        default_config = {
            'scan_settings': {
                'threads': 10,
                'timeout': 30,
                'rate_limit': 100,
                'user_agent': 'Web-Hunter/1.0'
            },
            'tools': {
                'subdomain_enum': ['subfinder', 'amass', 'assetfinder'],
                'port_scan': ['masscan', 'nmap'],
                'vuln_scan': ['nuclei', 'naabu']
            },
            'output': {
                'format': ['json', 'txt'],
                'webhook_url': None
            }
        }
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f)
        
        return default_config

class ConfigValidator:
    @staticmethod
    def validate_tools() -> List[str]:
        required_tools = ['subfinder', 'amass', 'nuclei']
        missing_tools = []
        for tool in required_tools:
            if not shutil.which(tool):
                missing_tools.append(tool)
        return missing_tools

    @staticmethod
    def validate_config(config: Dict[str, Any]) -> List[str]:
        errors = []
        required_keys = ['scan_settings', 'tools', 'output']
        
        for key in required_keys:
            if key not in config:
                errors.append(f"Missing required config section: {key}")
        
        return errors

