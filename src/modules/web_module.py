import requests
from typing import Dict, Any

def run_web_probe(target: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Probes HTTP/HTTPS endpoints for headers, status, and redirects.
    """
    results = {}
    protocols = ["http", "https"]
    
    # If target is already a URL, parse it
    # If it's a domain/IP, try both http and https
    
    targets_to_probe = []
    if target.startswith("http"):
        targets_to_probe.append(target)
    else:
        targets_to_probe.append(f"http://{target}")
        targets_to_probe.append(f"https://{target}")
        
    for url in targets_to_probe:
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            results[url] = {
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", "Unknown"),
                "title": "TODO: extract title", # simplified for speed
                "redirects": [r.url for r in resp.history]
            }
        except requests.exceptions.RequestException as e:
            results[url] = {"error": str(e)}
            
    return results
