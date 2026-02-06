## ReconForge 

ReconForge is a Python-based reconnaissance tool designed for authorized security testing and educational environments. It performs passive intelligence gathering and controlled active probing to help identify exposed services, open ports, and potential security risks on a target system.

The tool was built as a learning-focused reconnaissance platform with an emphasis on safety, modular design, and clear reporting output.

### Features

- Target input support (IP, Domain, CIDR)
- Multiple scan profiles:
  - Fast (passive + top ports)
  - Full (extended reconnaissance)
  - Custom module selection
- DNS and WHOIS lookup
- Subdomain discovery
- Port scanning with risk tagging
- Basic web service probing
- JSON result output for automation
- Modular architecture for future expansion

### Safety

ReconForge is intended **only for authorized security testing**. Users must have explicit permission before scanning any target.

### Requirements

- Python 3.9 (recommended)
- Windows/Linux compatible
- Dependencies managed via `requirements.txt`

Author

Kevin Mujica
Information Systems & Technology – Cybersecurity
California State University, San Bernardino

### Quick Start

```powershell
git clone https://github.com/KoyoteKev87/reconforge.git
cd reconforge
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python main.py
