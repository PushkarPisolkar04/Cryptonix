# 🛡️ Cryptonix - Automated Penetration Testing Platform

A comprehensive automated penetration testing framework with 10 stages covering OSINT, discovery, vulnerability assessment, exploitation, and reporting.

---

## 🚀 Quick Start

### Installation

```powershell
# 1. Run setup script
.\setup.ps1

# 2. Install Nmap (required - run as Administrator)
choco install nmap -y
# Or download from: https://nmap.org/download.html

# 3. Restart PowerShell and verify
.\check_dependencies.ps1
```

### Run Your First Scan

```powershell
# Safe OSINT scan (recommended first)
.\run.ps1 --target example.com --stages osint --dry-run

# Full assessment (dry-run mode)
.\run.ps1 --target example.com --dry-run

# Get help
.\run.ps1 --help
```

---

## 📋 What It Does

Cryptonix automates penetration testing through 10 stages:

1. **OSINT** - Gather intelligence (WHOIS, subdomains, emails, certificates)
2. **Discovery** - Scan networks and identify services
3. **Vulnerability Assessment** - Find security weaknesses
4. **Threat Modeling** - Analyze attack paths and risks
5. **Exploit Mapping** - Match vulnerabilities to exploits
6. **Exploitation** - Safely verify vulnerabilities
7. **Post-Exploitation** - Assess post-compromise capabilities
8. **Lateral Movement** - Test internal network pivoting
9. **Impact Analysis** - Calculate business impact
10. **Reporting** - Generate comprehensive reports (HTML, PDF, JSON, Markdown)

**Safety Features:**
- Dry-run mode (simulate without executing)
- Automatic rollback
- Rate limiting
- Emergency stop (Ctrl+C)

---

## 💻 Usage

### Basic Commands

```powershell
# OSINT only (safest, no active scanning)
.\run.ps1 --target example.com --stages osint --dry-run

# Specific stages
.\run.ps1 --target example.com --stages discovery,vulnerability --dry-run

# Full assessment
.\run.ps1 --target example.com --dry-run

# Stealth mode (slower, harder to detect)
.\run.ps1 --target example.com --stealth --dry-run

# Verbose output
.\run.ps1 --target example.com --verbose --dry-run
```

### Available Stages

Use `--stages` to run specific stages:

- `osint` - OSINT & Intelligence Gathering
- `discovery` - Network Discovery
- `vulnerability` - Vulnerability Assessment
- `threat_modeling` - Threat Modeling
- `exploit_mapping` - Exploit Mapping
- `exploitation` - Exploitation
- `post_exploitation` - Post-Exploitation
- `lateral_movement` - Lateral Movement
- `impact` - Impact Analysis
- `reporting` - Report Generation

---

## ⚙️ Configuration

### API Keys (Optional)

Edit `config/config.yaml` to add API keys for enhanced OSINT:

```yaml
apis:
  shodan_api_key: "your_key_here"
  censys_api_id: "your_id_here"
  virustotal_api_key: "your_key_here"
```

### Target Scope

Edit `config/scope.yaml` to define your target scope:

```yaml
target: "192.168.1.0/24"
excluded_hosts:
  - "192.168.1.1"  # Router
stealth_mode: true
```

---

## 📊 Reports

Reports are generated in `reports/` directory:

- **HTML** - Interactive web report
- **PDF** - Executive summary
- **JSON** - Machine-readable data
- **Markdown** - Documentation format

Each report includes:
- Discovered hosts and services
- Vulnerabilities with CVSS scores
- Attack paths
- Remediation recommendations
- Compliance violations
- Financial impact estimate

---

## 🛠️ Troubleshooting

### "Nmap not found"

```powershell
# Install Nmap (as Administrator)
choco install nmap -y
# Or download from: https://nmap.org/download.html

# Restart PowerShell
```

### "Python not found"

Install Python 3.11+ from [python.org](https://www.python.org/downloads/)

### "Module not found"

```powershell
pip install -r requirements.txt --force-reinstall
```

### Scan returns 0 vulnerabilities

**Common causes:**
- Nmap not installed (run `.\check_dependencies.ps1`)
- Target behind WAF/CDN (limited attack surface)
- Firewall blocking scans
- Target is actually secure

**Try:**
```powershell
# Verify Nmap
nmap --version

# Check dependencies
.\check_dependencies.ps1

# Try OSINT only (doesn't need Nmap)
.\run.ps1 --target example.com --stages osint --dry-run
```

---

## 📦 Requirements

- **Windows 10/11**
- **Python 3.11+**
- **Nmap** (required for network scanning)
- **Metasploit** (optional, only for exploitation stage)

All Python dependencies are installed automatically by `setup.ps1`.

---

## ⚠️ Legal & Safety

**IMPORTANT:** Always get written authorization before scanning any target!

- Unauthorized scanning is illegal
- Use `--dry-run` mode for testing
- This tool is for authorized security testing only
- Follow responsible disclosure practices

---

## 🎯 Quick Reference

```powershell
# Check installation
.\check_dependencies.ps1

# Safe OSINT scan
.\run.ps1 --target example.com --stages osint --dry-run

# Full assessment (dry-run)
.\run.ps1 --target example.com --dry-run --verbose

# Help
.\run.ps1 --help
```

---

## 📚 Documentation

- **README.md** - This file (installation & usage)
- **DOCUMENTATION.md** - Detailed feature documentation
- **STATUS.txt** - Implementation status

---

**Version:** 2.0  
**Status:** Production Ready  

**Remember:** Always get authorization before testing! 🔒
