import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

def check_port(ip: str, port: int, timeout: float) -> int:
    """
    Returns port if open, 0 if closed/timeout.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return 0

def run_port_scan(target_ip: str, ports: List[int], concurrency: int = 20, timeout: float = 0.5) -> Dict[str, Any]:
    """
    Scans a list of ports on a target IP.
    """
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_port = {executor.submit(check_port, target_ip, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result != 0:
                    open_ports.append(result)
            except Exception:
                pass
                
    return {
        "open_ports": sorted(open_ports),
        "scanned_count": len(ports)
    }
