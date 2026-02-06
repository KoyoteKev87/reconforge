ReconForge is a modular reconnaissance tool designed for authorized security assessments and educational penetration testing environments.

## Features

- Passive reconnaissance (DNS, WHOIS, Subdomain enumeration)
- Controlled active reconnaissance (port scanning, web probing)
- Modular scanning architecture
- Low-footprint threaded scanning engine
- Structured JSON output
- Gradio-based UI interface

## Architecture

ReconForge uses a modular execution engine:

Target Input → Scanner Engine → Recon Modules → Aggregation → JSON Output

Modules include:
- DNS Enumeration
- WHOIS / RDAP Lookup
- Subdomain Discovery
- Port Scanning
- Web Service Probing

Legal Notice

This tool is intended for authorized security testing only.
Unauthorized scanning of systems without permission is illegal.

Author

Kevin Mujica
California State University, San Bernardino
Information Systems & Technology – Cybersecurity

## Installation

```bash
pip install -r requirements.txt
python main.py
