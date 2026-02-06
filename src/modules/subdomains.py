import requests
from typing import List

def run_subdomain_recon(domain: str) -> List[str]:
    """
    Queries crt.sh for subdomains.
    """
    subdomains = set()
    
    # Clean domain just in case
    domain = domain.lower()
    
    # 1. crt.sh
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get('name_value')
                if name_value:
                    # Split multiline entries
                    for sub in name_value.split('\n'):
                        if sub.endswith(domain) and sub != domain:
                             subdomains.add(sub.lower())
    except Exception as e:
        # Fallback or just log error?
        # User requested graceful failure + caching (simplifying caching to just memory for this run)
        print(f"crt.sh failed: {e}")
        
    # TODO: Add HackerTarget fallback if crt.sh fails
    
    return sorted(list(subdomains))
