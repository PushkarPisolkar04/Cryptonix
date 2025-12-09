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

**Option 1: Interactive Menu (Easiest - Double-Click)**

Simply double-click `run.bat` and choose from:

1. **OSINT scan only** - Fastest (15-30 sec), gathers public info only
2. **Fast scan** - Quick scan (2-5 min), 10 subdomains, top 1000 ports
3. **Full scan** - Deep scan (30+ min), 50 subdomains, all 65535 ports
4. **REAL exploitation** - ⚠️ Actual exploitation (requires authorization!)
5. Check dependencies
6. Show help
7. Custom command

Each option shows estimated time and progress updates!

**Option 2: PowerShell (For Advanced Users)**
```powershell
# Dry-run mode (safe simulation)
.\run.ps1 --target example.com --dry-run

# Real mode (actual exploitation - needs authorization!)
.\run.ps1 --target example.com
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
- **Dry-run mode** - Simulate attacks without executing them
- **Automatic rollback** - Undo changes on failure
- **Rate limiting** - Avoid overwhelming targets
- **Emergency stop** - Press Ctrl+C to abort immediately
- **Authorization check** - Confirms before real exploitation

---

## 🔍 Dry-Run vs Full Mode

### What is Dry-Run Mode?

**Dry-run mode** = Safe simulation mode

| Feature | Dry-Run Mode (`--dry-run`) | Full Mode (No flag) |
|---------|---------------------------|---------------------|
| Scans for vulnerabilities | ✅ Yes | ✅ Yes |
| Shows what exploits would be used | ✅ Yes | ✅ Yes |
| Actually exploits vulnerabilities | ❌ No | ✅ Yes |
| Makes changes to target | ❌ No | ✅ Yes |
| Can cause damage | ❌ No | ⚠️ Yes |
| Requires authorization | ⚠️ Recommended | ✅ Required |
| Safe for testing | ✅ Yes | ❌ No |

### When to Use Each Mode

**Use Dry-Run Mode (`--dry-run`) when:**
- ✅ Testing the tool for the first time
- ✅ Learning how it works
- ✅ Generating vulnerability reports without exploitation
- ✅ Demonstrating capabilities to clients
- ✅ You want to be safe

**Use Full Mode (no `--dry-run`) when:**
- ✅ You have **written authorization**
- ✅ Testing your **own systems**
- ✅ You understand the **risks**
- ✅ You have **backups** ready
- ✅ You're in a **controlled environment**

### Example

```powershell
# DRY-RUN (Safe - Recommended)
.\run.ps1 --target example.com --dry-run
# Output: "Found SQL injection. Would attempt exploit XYZ"

# FULL MODE (Dangerous - Needs Authorization)
.\run.ps1 --target example.com
# Output: Actually attempts SQL injection and accesses database
```

---

## 💻 Usage

### Basic Commands

```powershell
# OSINT only (fastest, safest - 15 seconds)
.\run.ps1 --target example.com --stages osint --dry-run

# Discovery scan (scans top 10 subdomains, top 1000 ports - ~2-5 minutes)
.\run.ps1 --target example.com --stages discovery --dry-run

# Full assessment (dry-run - safe, ~5-10 minutes)
.\run.ps1 --target example.com --dry-run

# Full assessment (REAL - requires authorization!)
.\run.ps1 --target example.com

# Aggressive mode (scans 50 subdomains, all ports - SLOW, ~30+ minutes)
.\run.ps1 --target example.com --aggressive --dry-run

# Stealth mode (slower, harder to detect)
.\run.ps1 --target example.com --stealth --dry-run

# Verbose output
.\run.ps1 --target example.com --verbose --dry-run
```

### Scan Speed Guide

| Mode | Subdomains | Ports | Time per Target | Total Time | Command |
|------|-----------|-------|----------------|------------|---------|
| **OSINT only** | N/A | N/A | N/A | 15-30 sec | `--stages osint` |
| **Fast (Normal)** | 10 | Top 1000 | ~30 sec | 2-5 min | Default |
| **Full (Aggressive)** | 50 | All 65535 | ~2 min | 30+ min | `--aggressive` |
| **Stealth** | 10 | Top 1000 | ~1 min | 10-20 min | `--stealth` |

**Progress Tracking:**
- Shows estimated total time at start
- Updates progress after each target
- Displays elapsed time and remaining time
- Shows time taken per target

**Example Output:**
```
⏱️  Estimated scan time: 5 minutes 0 seconds
📊 Progress: 1/10 targets | Elapsed: 28s | Remaining: ~252s | This target: 28s
📊 Progress: 2/10 targets | Elapsed: 55s | Remaining: ~220s | This target: 27s
✅ Scan complete! Total time: 4m 32s
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

### IMPORTANT WARNINGS

🚨 **Always get written authorization before scanning any target!**

**Legal Requirements:**
- Unauthorized scanning is **illegal** in most jurisdictions
- Penalties can include fines and imprisonment
- Even "harmless" scanning can be prosecuted
- Get written permission from the target owner

**Best Practices:**
- ✅ **Always start with `--dry-run` mode**
- ✅ Test on your own systems first
- ✅ Have written authorization before full mode
- ✅ Keep backups before testing
- ✅ Follow responsible disclosure practices
- ✅ Document everything you do
- ❌ Never scan without permission
- ❌ Never use full mode without authorization

**This tool is for:**
- Authorized security testing
- Educational purposes (on your own systems)
- Professional penetration testing (with contracts)
- Security research (with permission)

**This tool is NOT for:**
- Unauthorized hacking
- Illegal activities
- Testing systems you don't own
- Causing damage or disruption

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
