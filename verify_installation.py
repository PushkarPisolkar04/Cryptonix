#!/usr/bin/env python3
"""
Verification script to check AutoPenTest installation
"""

import sys
import importlib

print("="*60)
print("AutoPenTest Installation Verification")
print("="*60)

# Check Python version
print(f"\n[OK] Python version: {sys.version}")

# Required modules
required_modules = [
    'asyncio', 'pathlib', 'typing', 'dataclasses', 'enum',
    'json', 'yaml', 'subprocess', 'socket', 'ssl'
]

optional_modules = [
    'loguru', 'click', 'aiohttp', 'requests', 'nmap',
    'jinja2', 'reportlab', 'markdown'
]

print("\n" + "="*60)
print("Checking Required Modules (Built-in):")
print("="*60)

for module in required_modules:
    try:
        importlib.import_module(module)
        print(f"[OK] {module}")
    except ImportError:
        print(f"[MISSING] {module}")

print("\n" + "="*60)
print("Checking Optional Modules (Need pip install):")
print("="*60)

missing = []
for module in optional_modules:
    try:
        importlib.import_module(module)
        print(f"[OK] {module}")
    except ImportError:
        print(f"[MISSING] {module} - install with: pip install {module}")
        missing.append(module)

print("\n" + "="*60)
print("Summary:")
print("="*60)

if missing:
    print(f"\n[WARNING] {len(missing)} optional modules missing")
    print(f"Install with: pip install -r requirements.txt")
else:
    print("\n[OK] All modules available!")

print("\n" + "="*60)
print("Project Structure Check:")
print("="*60)

import os
from pathlib import Path

dirs_to_check = [
    'core', 'stages', 'modules', 'utils', 'config'
]

for dir_name in dirs_to_check:
    if Path(dir_name).exists():
        py_files = list(Path(dir_name).rglob('*.py'))
        print(f"[OK] {dir_name}/ - {len(py_files)} Python files")
    else:
        print(f"[MISSING] {dir_name}/")

print("\n" + "="*60)
print("Module Count:")
print("="*60)

module_dirs = {
    'OSINT': 'modules/osint',
    'Discovery': 'modules/discovery',
    'Vulnerability Scanning': 'modules/vuln_scan',
    'Exploit Mapping': 'modules/exploit_map',
    'Exploitation': 'modules/exploitation',
    'Threat Modeling': 'modules/threat_model',
    'Post-Exploitation': 'modules/post_exploit',
    'Lateral Movement': 'modules/lateral',
    'Impact Demonstration': 'modules/impact',
    'Reporting': 'modules/reporting'
}

total_modules = 0
for category, path in module_dirs.items():
    if Path(path).exists():
        modules = [f for f in Path(path).glob('*.py') if f.name != '__init__.py']
        count = len(modules)
        total_modules += count
        print(f"[OK] {category}: {count} modules")
    else:
        print(f"[MISSING] {category}")

print(f"\n[OK] Total: {total_modules} modules")

print("\n" + "="*60)
print("Status: Installation " + ("COMPLETE" if total_modules >= 50 else "INCOMPLETE"))
print("="*60)
