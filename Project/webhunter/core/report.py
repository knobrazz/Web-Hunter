import json
import csv
import yaml
from pathlib import Path
from typing import Dict, Any, List
import requests
from datetime import datetime

class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.results: Dict[str, Any] = {}

    def add_result(self, section: str, data: Any):
        self.results[section] = data

    def generate_report(self, formats: List[str] = ['json']):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for fmt in formats:
            if fmt == 'json':
                self._save_json(timestamp)
            elif fmt == 'csv':
                self._save_csv(timestamp)
            elif fmt == 'yaml':
                self._save_yaml(timestamp)

    def _save_json(self, timestamp: str):
        output_file = self.output_dir / f"report_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)

    def _save_csv(self, timestamp: str):
        output_file = self.output_dir / f"report_{timestamp}.csv"
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            for section, data in self.results.items():
                writer.writerow([section])
                if isinstance(data, list):
                    for item in data:
                        writer.writerow([item])
                elif isinstance(data, dict):
                    for key, value in data.items():
                        writer.writerow([key, value])

    def _save_yaml(self, timestamp: str):
        output_file = self.output_dir / f"report_{timestamp}.yaml"
        with open(output_file, 'w') as f:
            yaml.dump(self.results, f)

    async def send_webhook(self, webhook_url: str):
        if not webhook_url:
            return
            
        try:
            requests.post(webhook_url, json=self.results)
        except Exception as e:
            logging.error(f"Failed to send webhook: {e}")

