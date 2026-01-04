# 🛡️ Cryptonix - Automated Security Scanner

A professional, automated penetration testing tool designed to be simple and effective.

## 🚀 Quick Start

### 1. Installation

```bash
# Install requirements
pip install -r requirements.txt
```

*(Note: On Windows, you don't need to install Nmap manually. The tool will use a built-in fallback scanner.)*

### 2. Run a Scan

**Basic Scan (Safe Mode):**
```bash
python main.py --target example.com --dry-run
```

**Full Scan (Authorized Only):**
```bash
python main.py --target example.com
```

**OSINT Only (Fast):**
```bash
python main.py --target example.com --stages osint --dry-run
```

---

## 📋 Features

- **Automated Discovery**: Finds open ports and services automatically.
- **Vulnerability Scanning**: Detects SQL Injection, XSS, and more.
- **OSINT**: Gathers public intelligence (Emails, DNS, Subdomains).
- **Reporting**: Generates HTML and JSON reports in `reports/`.

---

## ⚠️ Legal Warning

**Authorized Use Only**: Do not use this tool on systems you do not own or have written permission to test.