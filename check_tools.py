#!/usr/bin/env python3
"""
Cross-platform tool checker
Works on Windows, Linux, and Kali Linux
"""

import sys
from utils.tool_detector import ToolDetector
from loguru import logger


def main():
    """Check all dependencies and tools"""
    
    print("="*60)
    print("🔍 Cryptonix Tool Checker")
    print("="*60)
    print()
    
    detector = ToolDetector()
    
    # Check Python version
    print("📦 Python Version Check")
    print("-"*60)
    detector.check_python_version()
    print()
    
    # Check tools
    print("🛠️  Security Tools Check")
    print("-"*60)
    tools = detector.detect_all_tools()
    print()
    
    # Show installation instructions for missing tools
    missing_tools = [tool for tool, path in tools.items() if not path]
    
    if missing_tools:
        print("📝 Installation Instructions for Missing Tools")
        print("-"*60)
        for tool in missing_tools:
            print(f"\n{tool.upper()}:")
            print(detector.get_install_instructions(tool))
        print()
    
    # Summary
    print("="*60)
    found = sum(1 for v in tools.values() if v)
    total = len(tools)
    
    if found == total:
        print(f"✅ All tools found! ({found}/{total})")
        print("You can use all vulnerability scanners.")
    elif found >= 2:
        print(f"⚠️  Some tools found ({found}/{total})")
        print("Built-in scanner + some external tools will work.")
    else:
        print(f"⚠️  Few tools found ({found}/{total})")
        print("Only built-in Python scanner will work.")
        print("Install more tools for better results.")
    
    print("="*60)
    print()
    
    # Show what will work
    print("🎯 What Will Work:")
    print("-"*60)
    print("✅ Built-in Python Scanner (always works)")
    print("   - SQL injection detection")
    print("   - XSS detection")
    print("   - Directory traversal")
    print("   - Security headers check")
    print("   - Sensitive file exposure")
    print()
    
    if tools.get('nmap'):
        print("✅ Nmap - Network discovery and port scanning")
    else:
        print("❌ Nmap - Install for network discovery")
    
    if tools.get('sqlmap'):
        print("✅ SQLMap - Advanced SQL injection testing")
    else:
        print("❌ SQLMap - Install for advanced SQL injection")
    
    if tools.get('nikto'):
        print("✅ Nikto - Web server vulnerability scanning")
    else:
        print("❌ Nikto - Install for web server scanning")
    
    if tools.get('msfconsole'):
        print("✅ Metasploit - Exploitation framework")
    else:
        print("❌ Metasploit - Install for exploitation stage")
    
    print()
    print("="*60)
    
    return 0 if found >= 1 else 1


if __name__ == '__main__':
    sys.exit(main())
