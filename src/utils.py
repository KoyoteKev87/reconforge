import logging
import ipaddress
import tldextract
from urllib.parse import urlparse
from .models import TargetType
from .config import MAX_CIDR_HOSTS

def setup_logger(name: str = "reconforge") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

def validate_target(input_str: str) -> tuple[str, TargetType]:
    """
    Returns (normalized_target, TargetType)
    """
    input_str = input_str.strip()
    
    # 1. Check CIDR
    if "/" in input_str:
        try:
            ipaddress.ip_network(input_str, strict=False)
            return input_str, TargetType.CIDR
        except ValueError:
            pass
    
    # 2. Check IP
    try:
        ipaddress.ip_address(input_str)
        return input_str, TargetType.IP
    except ValueError:
        pass
    
    # 3. Check URL (must have scheme)
    if input_str.startswith("http://") or input_str.startswith("https://"):
        return input_str, TargetType.URL
    
    # 4. Assume Domain
    # Use tldextract to check validity broadly, or just return as domain
    # We strip 'www.' if just a domain? Maybe not, keep input true.
    # But usually for domain scan we want base domain + subdomains.
    # For now, return as is.
    return input_str, TargetType.DOMAIN

def expand_cidr(cidr_str: str, limit: int = MAX_CIDR_HOSTS) -> tuple[list[str], int]:
    """
    Returns (list_of_ips, count_skipped)
    """
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        all_hosts = list(net.hosts())
        # If /32 or single host
        if not all_hosts: 
            return [str(net.network_address)], 0
        
        if len(all_hosts) > limit:
            return [str(ip) for ip in all_hosts[:limit]], len(all_hosts) - limit
        return [str(ip) for ip in all_hosts], 0
    except Exception:
         return [], 0
