import time
import logging
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, List

from .models import RunConfig, ScanResult, ModuleResult, ScanSummary, TargetType
from .utils import validate_target, expand_cidr, setup_logger
from .config import MAX_RUNTIME_SOFT_LIMIT, PROFILES

# Modules
from .modules.dns_module import run_dns_recon
from .modules.whois_module import run_whois_recon
from .modules.subdomains import run_subdomain_recon
from .modules.ports_module import run_port_scan
from .modules.web_module import run_web_probe

logger = setup_logger()

class ReconEngine:
    def __init__(self):
        pass

    def run(self, config: RunConfig) -> ScanResult:
        start_time = datetime.now()
        logger.info(f"Starting scan for {config.target_input} with profile {config.profile_name}")
        
        # 1. Validation & Expansion
        normalized_target, target_type = validate_target(config.target_input)
        targets_to_scan = [normalized_target]
        cidr_notes = None
        
        if target_type == TargetType.CIDR:
            expanded, skipped_count = expand_cidr(normalized_target, config.cidr_limit)
            targets_to_scan = expanded
            cidr_notes = {"cap_applied": True, "limit": config.cidr_limit, "skipped": skipped_count}
            logger.info(f"CIDR expansion: scanning {len(targets_to_scan)} hosts, skipped {skipped_count}")

        # Initialize Results
        scan_results_data = {}
        target_summaries = {
             "open_ports": 0,
             "subdomains": 0
        }
        
        # 2. Loop through targets (Single or List)
        # For CIDR, we might want to parallelize HOSTS? 
        # But we must respect concurrency limits. 
        # The prompt implies "Single target per run" usually, but CIDR is supported.
        # For CIDR, we should probably run simpler checks (ping/port) rather than full DNS/Whois per IP?
        # The PRD says for CIDR: "Input 192.0.2.0/28 -> host reachability ... + controlled port scanning".
        
        # We will iterate sequentially over targets to ensure control, or use a small pool.
        # Given the "2 minute goal", sequential for 64 hosts might be too slow if we do full scans.
        # But usually CIDR scan implies Port Scan mainly.
        
        for target in targets_to_scan:
            # Check Runtime Guard
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > MAX_RUNTIME_SOFT_LIMIT:
                logger.warning(f"Soft runtime limit reached ({elapsed}s). Stopping new tasks.")
                break
                
            # Per-target results
            target_res = {}
            
            # Decide what to run based on Config + Profile
            # The config.enabled_modules list governs this.
            
            # --- PASSIVE MODULES (Parallel) ---
            passive_futures = {}
            # Track start times for passive block
            # Since they run in parallel, wall clock is shared. 
            # We'll just time the individual execution inside the future? 
            # No, `run_dns_recon` returns dict. 
            # We need to wrap it to get time.
            
            def timed_execution(func, *args):
                s = time.time()
                res = func(*args)
                d = time.time() - s
                return res, d

            module_times = {} # store duration for this target

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                if "dns" in config.enabled_modules and target_type in [TargetType.DOMAIN]:
                    passive_futures["dns"] = executor.submit(timed_execution, run_dns_recon, target)
                
                if "whois" in config.enabled_modules:
                    passive_futures["whois"] = executor.submit(timed_execution, run_whois_recon, target, target_type)
                    
                if "subdomains" in config.enabled_modules and target_type == TargetType.DOMAIN:
                    passive_futures["subdomains"] = executor.submit(timed_execution, run_subdomain_recon, target)

                # Collect Passive Results
                for mod, future in passive_futures.items():
                    try:
                        data, dur = future.result()
                        target_res[mod] = data
                        module_times[mod] = dur
                        if mod == "subdomains":
                            target_summaries["subdomains"] += len(data)
                    except Exception as e:
                        target_res[mod] = {"error": str(e)}

            # --- ACTIVE MODULES (Sequential to control noise) ---
            # Ports
            if "ports" in config.enabled_modules:
                s_ports = time.time()
                # Resolve profile ports
                ports_to_scan = []
                profile_def = PROFILES.get(config.profile_name, PROFILES["Custom"])
                if config.profile_name == "Custom":
                    # For custom, maybe default to Top 100 if not specified? 
                    # Or Config should have generic lists? 
                    # Use Top 100 as safe default for custom active scan
                    ports_to_scan = PROFILES["Fast"]["port_list"]
                else:
                    ports_to_scan = profile_def["port_list"]
                
                # Check target is valid IP or Domain (resolve domain first?)
                # Port scanner takes IP usually.
                scan_ip = target
                if target_type == TargetType.DOMAIN:
                    # Quick resolve for port scan
                    try:
                        scan_ip = list(target_res.get("dns", {}).get("A", []))[0]
                    except:
                        scan_ip = target # Try scanning hostname directly (socket supports it)

                if scan_ip:
                    port_data = run_port_scan(
                        scan_ip, 
                        ports_to_scan, 
                        concurrency=config.concurrency, 
                        timeout=config.connect_timeout
                    )
                    
                    # ENRICHMENT: Add Security Details
                    from .knowledge import PORT_KNOWLEDGE, DEFAULT_UNKNOWN_PORT
                    enriched_details = []
                    for p in port_data.get("open_ports", []):
                        info = PORT_KNOWLEDGE.get(p, DEFAULT_UNKNOWN_PORT).copy()
                        info["port"] = p # Add port number to the record
                        enriched_details.append(info)
                    
                    port_data["details"] = enriched_details
                    target_res["ports"] = port_data
                    target_summaries["open_ports"] += len(port_data.get("open_ports", []))
                module_times["ports"] = time.time() - s_ports

            # Web
            if "web" in config.enabled_modules:
                s_web = time.time()
                # Use configured timeout
                web_data = run_web_probe(target, timeout=config.connect_timeout)
                target_res["web"] = web_data
                module_times["web"] = time.time() - s_web
            
            # Store timings in result for aggregation later (or just aggregate now)
            target_res["_timings"] = module_times
            scan_results_data[target] = target_res

        # 3. Finalize Summary
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Determine IP Class (check first target if it looks like IP)
        # Simplified check for summary
        ip_class = "public"
        primary_target = targets_to_scan[0] if targets_to_scan else config.target_input
        # Naive check, better to use ipaddress module but pure string check is fast/safe for now
        if primary_target.startswith("127."): 
            ip_class = "loopback"
        elif primary_target.startswith("192.168.") or primary_target.startswith("10.") or (primary_target.startswith("172.") and 16 <= int(primary_target.split(".")[1]) <= 31):
            ip_class = "private"
        
        # Aggregate Timings
        module_timings = {}
        risk_tags = set()
        
        # Analyze results for risks relative to IP class
        # (e.g. public RDP is higher risk than private RDP, but tag simpler for now)
        
        for t, res in scan_results_data.items():
            # ... (risk tag logic same as before) ...
            if "ports" in res:
                open_ports = res["ports"].get("open_ports", [])
                if 22 in open_ports: risk_tags.add("ssh_exposed")
                if 80 in open_ports: risk_tags.add("web_exposed")
                if 443 in open_ports: risk_tags.add("web_exposed")
                if 3389 in open_ports: risk_tags.add("rdp_exposed")
                if 21 in open_ports: risk_tags.add("ftp_exposed")
                if 23 in open_ports: risk_tags.add("telnet_exposed")
                if 135 in open_ports: risk_tags.add("rpc_exposed")
                if 445 in open_ports: risk_tags.add("smb_exposed")
                
                # Check for any non-standard/uncommon ports (Simple heuristic)
                common_allows = {20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 5900, 8000, 8080, 8443}
                if any(p not in common_allows for p in open_ports):
                    risk_tags.add("nonstandard_ports_open")
            
            # Check Web
            if "web" in res:
                web = res["web"]
                if web.get("server"): risk_tags.add("server_version_disclosure")

            t_times = res.get("_timings", {})
            for m, d in t_times.items():
                module_timings[m] = module_timings.get(m, 0) + d

        # Determine Port Profile Name for Report
        if "ports" in config.enabled_modules:
            # Re-resolve to get accurate count for labeling
            # Note: The actual scan loop logic mirrors this
            if config.profile_name == "Custom":
                 p_list = PROFILES["Fast"]["port_list"] # Fallback used in loop
            else:
                 p_list = PROFILES.get(config.profile_name, PROFILES["Fast"])["port_list"]
            
            count = len(p_list)
            if config.profile_name == "Fast": port_prof = f"top_{count}"
            elif config.profile_name == "Full": port_prof = f"extended_{count}"
            else: port_prof = f"custom_{count}"

        # Populate User-Friendly Risk Details
        from .knowledge import RISK_TAG_DESCRIPTIONS
        risk_map = {}
        for tag in risk_tags:
            risk_map[tag] = RISK_TAG_DESCRIPTIONS.get(tag, "No description available.")

        # Consolidate Open Ports List given we might have scanned multiple targets
        # For single target, it's just one list.
        all_open_ports = []
        for res in scan_results_data.values():
            if "ports" in res:
                all_open_ports.extend(res["ports"].get("open_ports", []))
        all_open_ports = sorted(list(set(all_open_ports)))

        summary = ScanSummary(
            target=config.target_input,
            type=config.target_type.value,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_total=duration,
            hosts_discovered=len(targets_to_scan),
            open_ports_total=target_summaries["open_ports"],
            subdomains_found=target_summaries["subdomains"],
            cidr_notes=cidr_notes,
            risk_tags=list(risk_tags),
            module_timings=module_timings,
            ip_class=ip_class,
            ports_service_profile=port_prof,
            open_ports_list=all_open_ports,
            risk_details=risk_map
        )
        
        return ScanResult(
            config=config,
            summary=summary,
            results=scan_results_data,
            logs=[] # Logs handled separately or via UI capture
        )
