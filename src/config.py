import socket

# --- CONSTANTS ---

# Default Timeouts
DEFAULT_CONNECT_TIMEOUT = 0.5  # Seconds
MAX_CONNECT_TIMEOUT = 2.0
DEFAULT_READ_TIMEOUT = 3.0    # For HTTP/Whois

# Concurrency
DEFAULT_CONCURRENCY = 25
MAX_CONCURRENCY = 50

# Limits
MAX_CIDR_HOSTS = 64
MAX_RUNTIME_SOFT_LIMIT = 110 # Stop starting tasks if 110s elapsed (limit is 120s)

# --- PORT LISTS (Reference: Nmap top ports) ---
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 137, 138, 139, 143, 443, 445, 
    587, 631, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443
    # ... truncated for brevity, I will add a reasonable set of common ports
] + [
    # Adding more common ones to reach ~100 important ones
    7, 9, 13, 17, 19, 26, 37, 42, 49, 53, 70, 79, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 389, 443, 444, 445, 456, 464, 465, 481, 497, 500, 513, 514, 515, 524, 541, 543, 544, 548, 554, 563, 587, 593, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 800, 808
]
# Ensure uniqueness and sort
TOP_100_PORTS = sorted(list(set(TOP_100_PORTS)))[:100]

# Expanded list for "Full" profile
# "Top 1000" is usually frequency based. For this project, we define it as
# The Privileged Ports (1-1024) + Common High Ports.
# This ensures we hit ~1000 targets and cover all standard customized services.
_SYSTEM_PORTS = list(range(1, 1025))
_EXTRA_COMMON = [
    # DBs
    1433, 1521, 3306, 5432, 5984, 6379, 27017,
    # Web Alt
    8000, 8008, 8080, 8443, 8888, 9000, 9090, 9443, 10000,
    # Windows/RPC/Remote
    3389, 5900, 5985, 5986,
    # Misc
    1883, 5000, 5060, 5353, 5601, 8081, 9200
]
TOP_1000_PORTS = sorted(list(set(TOP_100_PORTS + _SYSTEM_PORTS + _EXTRA_COMMON)))

# Profiles
PROFILES = {
    "Fast": {
        "description": "Passive Only + Top 100 Ports",
        "modules": ["dns", "whois", "subdomains", "ports"],
        "port_list": TOP_100_PORTS,
        "concurrency": 25,
        "timeout": DEFAULT_CONNECT_TIMEOUT,
        "web_probe": False
    },
    "Full": {
        "description": "Passive + Extended Ports + Web Probe",
        "modules": ["dns", "whois", "subdomains", "ports", "web"],
        "port_list": TOP_1000_PORTS,
        "concurrency": 25,
        "timeout": DEFAULT_CONNECT_TIMEOUT,
        "web_probe": True
    },
    "Custom": {
        "description": "User defined settings",
        "modules": [], # Populated by UI
        "port_list": [],
        "concurrency": DEFAULT_CONCURRENCY,
        "timeout": DEFAULT_CONNECT_TIMEOUT,
        "web_probe": False
    }
}
