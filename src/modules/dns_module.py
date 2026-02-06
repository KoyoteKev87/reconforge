import dns.resolver
from typing import Dict, Any, List

def run_dns_recon(target: str) -> Dict[str, Any]:
    """
    Resolves common DNS records for a given domain.
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    results = {}
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            results[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results[rtype] = []
        except Exception as e:
            results[rtype] = [f"Error: {str(e)}"]

    return results
