import whois
from ipwhois import IPWhois
from ..models import TargetType
from typing import Dict, Any

def run_whois_recon(target: str, target_type: TargetType) -> Dict[str, Any]:
    """
    Performs WHOIS for domains or RDAP for IPs.
    """
    results = {}
    
    if target_type == TargetType.DOMAIN:
        try:
            # python-whois
            w = whois.whois(target)
            # Serialize dates and lists
            results = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "emails": w.emails,
                "org": w.org
            }
        except Exception as e:
            results = {"error": str(e)}
            
    elif target_type in [TargetType.IP, TargetType.CIDR]:
        # For CIDR, we just use the network address or the first IP provided
        # Actually target passed here is likely an IP.
        try:
            obj = IPWhois(target.split('/')[0])
            rdap = obj.lookup_rdap()
            results = {
                "asn": rdap.get("asn"),
                "asn_description": rdap.get("asn_description"),
                "network": rdap.get("network"),
                "objects": rdap.get("objects")
            }
        except Exception as e:
            results = {"error": str(e)}
            
    return results
