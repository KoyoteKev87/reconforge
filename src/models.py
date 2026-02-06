from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"

class RunConfig(BaseModel):
    target_input: str
    target_type: TargetType
    profile_name: str
    enabled_modules: List[str]
    concurrency: int = 25
    connect_timeout: float = 0.5
    cidr_limit: int = 64

class ModuleResult(BaseModel):
    module: str
    duration: float
    status: str = "success" # success, error, skipped
    error: Optional[str] = None
    data: Any = None

class ScanSummary(BaseModel):
    target: str
    type: str
    start_time: str
    end_time: str
    duration_total: float
    hosts_discovered: int = 0
    open_ports_total: int = 0
    subdomains_found: int = 0
    cidr_notes: Optional[Dict[str, Any]] = None # e.g. { "cap_applied": True, "skipped": 60 }
    risk_tags: List[str] = []
    module_timings: Dict[str, float] = {}
    ip_class: str = "public" # public, private, loopback
    ports_service_profile: str = "n/a" # e.g. "top_100", "top_1000", "custom"
    open_ports_list: List[int] = []
    risk_details: Dict[str, str] = {}

class ScanResult(BaseModel):
    config: RunConfig
    summary: ScanSummary
    results: Dict[str, Any] = Field(default_factory=dict) # Keyed by normalized target (IP or Domain)
    logs: List[str] = []
