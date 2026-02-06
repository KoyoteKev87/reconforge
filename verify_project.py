import sys
import os

# Ensure src is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.models import RunConfig, TargetType
from src.engine import ReconEngine
from src.config import PROFILES

def test_engine():
    print("Testing ReconForge Engine...")
    
    # Test Config
    cfg = RunConfig(
        target_input="scanme.nmap.org",
        target_type=TargetType.DOMAIN,
        profile_name="Fast",
        enabled_modules=["dns", "ports"], # fast test
        concurrency=10,
        connect_timeout=0.5
    )
    
    engine = ReconEngine()
    try:
        result = engine.run(cfg)
        print("✅ Scan finished successfully.")
        print(f"Target: {result.summary.target}")
        print(f"Duration: {result.summary.duration_total}s")
        print(f"Open Ports: {result.summary.open_ports_total}")
        print("Model Validation Passed.")
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        raise e

if __name__ == "__main__":
    test_engine()
