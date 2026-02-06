
# Security Knowledge Base for common ports

PORT_KNOWLEDGE = {
    20: {
        "service": "FTP-Data",
        "risk": "Medium",
        "description": "File Transfer Protocol (Data Channel). Transmits files in cleartext.",
        "attacks": "Sniffing, Man-in-the-Middle (MitM), Data exfiltration."
    },
    21: {
        "service": "FTP",
        "risk": "High",
        "description": "File Transfer Protocol (Control). Used for authentication and commands.",
        "attacks": "Brute Force, Anonymous Login, Cleartext credentials sniffing, FTP bounce."
    },
    22: {
        "service": "SSH",
        "risk": "Medium/High",
        "description": "Secure Shell. Standard for secure remote administration.",
        "attacks": "Brute Force (Hydra/Medusa), Credential Stuffing, Weak SSH Keys, SSH User Enumeration."
    },
    23: {
        "service": "Telnet",
        "risk": "Critical",
        "description": "Unencrypted remote administration protocol. Obsolete and insecure.",
        "attacks": "Sniffing credentials (cleartext), MitM, Brute Force."
    },
    25: {
        "service": "SMTP",
        "risk": "Medium",
        "description": "Simple Mail Transfer Protocol. Used for sending emails.",
        "attacks": "Open Relay abuse, SPAM, User Enumeration (VRFY/EXPN), Phishing campaigns."
    },
    53: {
        "service": "DNS",
        "risk": "Low/Medium",
        "description": "Domain Name System. Translates domain names to IPs.",
        "attacks": "DNS Amplification DDoS, Zone Transfer (AXFR), Cache Poisoning."
    },
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "description": "Hypertext Transfer Protocol. Unencrypted web traffic.",
        "attacks": "SQL Injection, XSS, Cleartext sniffing, Directory Traversal, Web Shells."
    },
    110: {
        "service": "POP3",
        "risk": "Medium",
        "description": "Post Office Protocol v3. Retrieves emails.",
        "attacks": "Brute Force, Cleartext authentication sniffing."
    },
    111: {
        "service": "RPCbind",
        "risk": "Medium",
        "description": "Maps RPC services to ports (UNIX).",
        "attacks": "Reconnaissance (rpcinfo), DDoS reflection."
    },
    135: {
        "service": "MSRPC",
        "risk": "High",
        "description": "Microsoft RPC Endpoint Mapper. essential for Windows networking.",
        "attacks": "Reconnaissance, RPC DCOM exploits, Lateral Movement."
    },
    137: {
        "service": "NetBIOS-NS",
        "risk": "Medium",
        "description": "NetBIOS Name Service. Resolves NetBIOS names.",
        "attacks": "Reconnaissance, NetBIOS name spoofing (LLMNR/NBT-NS poisoning)."
    },
    139: {
        "service": "NetBIOS-SSN",
        "risk": "High",
        "description": "NetBIOS Session Service. Used for file sharing.",
        "attacks": "SMB Enumeration, Null Session, Brute Force."
    },
    143: {
        "service": "IMAP",
        "risk": "Medium",
        "description": "Internet Message Access Protocol. Retrieves emails.",
        "attacks": "Brute Force, Cleartext sniffing (if not IMAPS)."
    },
    389: {
        "service": "LDAP",
        "risk": "High",
        "description": "Lightweight Directory Access Protocol. Directory services.",
        "attacks": "Anonymous binding, User Enumeration, LDAP Injection, Pass-the-hash."
    },
    443: {
        "service": "HTTPS",
        "risk": "Low",
        "description": "Secure HTTP. Encrypted web traffic.",
        "attacks": "Heartbleed, POODLE (if old SSL/TLS), Web App exploitations (SQLi/XSS)."
    },
    445: {
        "service": "SMB",
        "risk": "Critical",
        "description": "Server Message Block. Windows file sharing and remote execution.",
        "attacks": "EternalBlue (WannaCry), PsExec Lateral Movement, Null Session, Brute Force."
    },
    587: {
        "service": "SMTP (Submission)",
        "risk": "Medium",
        "description": "Secure email submission.",
        "attacks": "Brute Force, Open Relay (rare)."
    },
    1433: {
        "service": "MSSQL",
        "risk": "High",
        "description": "Microsoft SQL Server.",
        "attacks": "SA Brute Force, SQL Injection, xp_cmdshell RCE."
    },
    1521: {
        "service": "Oracle DB",
        "risk": "High",
        "description": "Oracle Database listener.",
        "attacks": "TNS Poisoning, SID Enumeration, Default credentials."
    },
    3306: {
        "service": "MySQL",
        "risk": "High",
        "description": "MySQL Database.",
        "attacks": "Brute Force, SQL Injection, Authentication Bypass (rare legacy)."
    },
    3389: {
        "service": "RDP",
        "risk": "High",
        "description": "Remote Desktop Protocol. Windows GUI remote access.",
        "attacks": "BlueKeep, Brute Force, Credential Stuffing, MitM (if no NLA)."
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "High",
        "description": "PostgreSQL Database.",
        "attacks": "Brute Force, Remote Code Execution (if misconfigured)."
    },
    5900: {
        "service": "VNC",
        "risk": "High",
        "description": "Virtual Network Computing. Remote desktop.",
        "attacks": "Brute Force, No Authentication exploit."
    },
    6379: {
        "service": "Redis",
        "risk": "High",
        "description": "Redis Key-Value Store.",
        "attacks": "Unauthenticated Access, RCE via crude write."
    },
    8080: {
        "service": "HTTPweb-alt",
        "risk": "Medium",
        "description": "Alternative HTTP port (often Tomcat/Proxy).",
        "attacks": "Tomcat Manager Brute Force, Web vulnerabilities."
    },
    8443: {
        "service": "HTTPS-alt",
        "risk": "Low/Medium",
        "description": "Alternative HTTPS port.",
        "attacks": "Web vulnerabilities."
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "High",
        "description": "Elasticsearch REST API.",
        "attacks": "Unauth Data Access, RCE (Log4Shell legacy)."
    },
    27017: {
        "service": "MongoDB",
        "risk": "High",
        "description": "MongoDB NoSQL Database.",
        "attacks": "Unauthenticated Access, Data Dumping."
    }
}

DEFAULT_UNKNOWN_PORT = {
    "service": "Unknown",
    "risk": "Unknown",
    "description": "Non-standard or unmapped port.",
    "attacks": "Service enumeration required (nmap -sV)."
}

RISK_TAG_DESCRIPTIONS = {
    "ssh_exposed": "SSH service (port 22) is exposed to the internet. If relying on password auth, it is highly susceptible to brute-force attacks.",
    "web_exposed": "Web services (HTTP/HTTPS) are accessible. This increases the attack surface for web application vulnerabilities (SQLi, XSS, etc.).",
    "rdp_exposed": "Remote Desktop Protocol (port 3389) is exposed. Highly targeted by ransomware groups and brute-force campaigns.",
    "ftp_exposed": "FTP service (port 21) is exposed. FTP often transmits credentials in cleartext and is considered insecure.",
    "telnet_exposed": "Telnet service (port 23) is exposed. Telnet is entirely unencrypted and obsolete; credentials and data can be easily sniffed.",
    "smb_exposed": "SMB (port 445) is exposed. This is a CRITICAL risk typically blocked by ISPs. It allows file sharing and potential remote exploitation (e.g., EternalBlue).",
    "rpc_exposed": "RPC Endpoint Mapper (port 135) is exposed. Often used for reconnaissance and lateral movement in Windows environments.",
    "server_version_disclosure": "The web server is revealing its version header. Attackers can use this to identify known vulnerabilities (CVEs) for that specific version.",
    "nonstandard_ports_open": "One or more non-standard ports are open. These may be obscure services, backdoors, or misconfigured applications requiring manual investigation."
}
