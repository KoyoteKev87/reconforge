import json
import os
from datetime import datetime
from ..models import ScanResult

class ResultWriter:
    def __init__(self, base_dir="data/runs"):
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
        self.run_dir = os.path.join(base_dir, self.timestamp)
        os.makedirs(self.run_dir, exist_ok=True)
        
    def save(self, scan_result: ScanResult):
        file_path = os.path.join(self.run_dir, "results.json")
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(scan_result.json(indent=2))
            return file_path
        except Exception as e:
            print(f"Error saving results: {e}")
            return None

    def get_run_dir(self):
        return self.run_dir
