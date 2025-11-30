# VulnWebScanner

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-in--development-orange.svg)

## 🎯 Overview

Advanced Web Vulnerability Scanner built on modern bug bounty methodologies and OWASP Top 10 2021 framework. Designed for professional penetration testing and security research.

## ✨ Key Features

- **Async Architecture**: 10x faster concurrent scanning
- **Bug Bounty Methodology**: Comprehensive reconnaissance pipeline
- **OWASP Top 10 2021**: Full coverage of critical web vulnerabilities
- **Smart Detection**: ML-based false positive reduction
- **Professional Reports**: HTML, JSON, PDF exports with CVSS scoring
- **Nuclei Integration**: 8000+ community vulnerability templates
- **CI/CD Ready**: Automation-friendly JSON output

## 🏗️ Architecture

### Phase 1: Reconnaissance Engine
- **Passive Recon**: Subdomain enumeration, asset discovery, tech detection
- **Active Recon**: Port scanning, web crawling, directory bruteforcing, WAF detection

### Phase 2: OWASP Top 10 2021 Scanning
- A01: Broken Access Control (IDOR, path traversal, privilege escalation)
- A02: Cryptographic Failures (weak SSL/TLS, insecure cookies)
- A03: Injection (SQL, NoSQL, Command, LDAP, XPath)
- A04: Insecure Design (business logic flaws, 2FA bypass)
- A05: Security Misconfiguration (default creds, debug mode, headers)
- A06: Vulnerable Components (outdated libraries, CVE lookup)
- A07: Authentication Failures (brute force, session management, JWT)
- A08: Data Integrity Failures (insecure deserialization)
- A09: Logging & Monitoring Failures (log injection)
- A10: Server-Side Request Forgery (SSRF, cloud metadata)

### Phase 3: Reporting & Intelligence
- Interactive HTML dashboards
- JSON/XML exports for automation
- PDF executive summaries
- CVSS scoring with remediation guidance

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/TheJamesSHx/VulnWebScanner.git
cd VulnWebScanner

# Install dependencies
pip install -r requirements.txt

# Install external tools (Linux/Debian)
sudo apt-get install nmap
./scripts/install_tools.sh
```

### Basic Usage

```bash
# Full scan with all modules
python cli.py scan --target https://example.com --all

# Reconnaissance only
python cli.py recon --target example.com --passive --active

# OWASP Top 10 scan
python cli.py scan --target https://example.com --owasp

# Custom module selection
python cli.py scan --target https://example.com --modules sql-injection,xss,ssrf

# Generate report
python cli.py report --scan-id 12345 --format html,pdf,json
```

## 📁 Project Structure

```
VulnWebScanner/
├── core/                    # Core scanning engine
├── recon/                   # Reconnaissance modules
│   ├── passive/            # Passive recon
│   └── active/             # Active recon
├── modules/                 # Vulnerability detection
│   └── owasp/              # OWASP Top 10 modules
├── reporting/               # Report generation
├── utils/                   # Utilities and helpers
│   ├── payloads/           # Attack payloads
│   └── wordlists/          # Fuzzing wordlists
├── config/                  # Configuration files
├── tests/                   # Unit tests
├── scripts/                 # Setup scripts
├── cli.py                   # Command-line interface
└── api.py                   # REST API (optional)
```

## 🛠️ Technology Stack

- **Core**: Python 3.11+, asyncio, aiohttp
- **Database**: SQLAlchemy, Redis
- **Web**: BeautifulSoup4, lxml, Playwright
- **Security**: requests, python-nmap, pyjwt
- **Integration**: subfinder, httpx, nuclei, katana, wafw00f

## 📋 Development Roadmap

- [x] Project structure initialization
- [ ] Phase 1: Core engine & async framework (Week 1)
- [ ] Phase 2: Reconnaissance modules (Week 2)
- [ ] Phase 3: OWASP A01-A05 scanners (Week 3)
- [ ] Phase 4: OWASP A06-A10 scanners (Week 4)
- [ ] Phase 5: Reporting engine (Week 5)
- [ ] Phase 6: Testing & optimization (Week 6)

## 🎓 Educational Purpose

This project is developed as part of a PFE (Projet de Fin d'Études) at DataProtect for educational and professional training purposes.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED TESTING ONLY**

This tool is designed for:
- Authorized penetration testing
- Bug bounty programs
- Security research with explicit permission
- Educational purposes in controlled environments

Unauthorized scanning of systems you don't own or have permission to test is **illegal**. Users are responsible for complying with all applicable laws.

## 📚 References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [Bug Bounty Recon Methodology](https://www.hivefive.community/p/the-best-bug-bounty-recon-methodology)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 👤 Author

**TheJamesSHx**
- GitHub: [@TheJamesSHx](https://github.com/TheJamesSHx)
- Project: Penetration Testing Internship at DataProtect

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

---

**⚡ Built for speed, designed for accuracy, created for professionals.**