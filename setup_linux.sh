#!/bin/bash
# Cryptonix Setup Script for Linux/Kali
# Installs dependencies and checks tools

set -e

echo "=========================================="
echo "🛡️  Cryptonix Setup for Linux/Kali"
echo "=========================================="
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "Detected OS: $PRETTY_NAME"
else
    OS="unknown"
    echo "Unknown Linux distribution"
fi

echo ""

# Check if running as root for tool installation
if [ "$EUID" -ne 0 ] && [ "$1" != "--no-tools" ]; then
    echo "⚠️  Not running as root. Will skip system tool installation."
    echo "   Run with sudo to install system tools (nmap, sqlmap, nikto)"
    echo "   Or run: ./setup_linux.sh --no-tools (Python packages only)"
    echo ""
    INSTALL_TOOLS=false
else
    INSTALL_TOOLS=true
fi

# 1. Check Python
echo "📦 Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✅ Python $PYTHON_VERSION found"
else
    echo "❌ Python 3 not found!"
    echo "Install with: sudo apt install python3 python3-pip"
    exit 1
fi

echo ""

# 2. Install Python dependencies
echo "📦 Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install -r requirements.txt
    echo "✅ Python packages installed"
else
    echo "❌ pip3 not found!"
    echo "Install with: sudo apt install python3-pip"
    exit 1
fi

echo ""

# 3. Install security tools (if root)
if [ "$INSTALL_TOOLS" = true ]; then
    echo "🛠️  Installing security tools..."
    
    if [ "$OS" = "kali" ] || [ "$OS" = "debian" ] || [ "$OS" = "ubuntu" ]; then
        echo "Using apt package manager..."
        
        # Update package list
        apt update
        
        # Install tools
        echo "Installing nmap..."
        apt install -y nmap
        
        echo "Installing sqlmap..."
        apt install -y sqlmap
        
        echo "Installing nikto..."
        apt install -y nikto
        
        echo "Installing additional tools..."
        apt install -y curl wget git
        
        echo "✅ Security tools installed"
    else
        echo "⚠️  Unknown package manager. Please install manually:"
        echo "   - nmap"
        echo "   - sqlmap"
        echo "   - nikto"
    fi
else
    echo "⚠️  Skipping system tool installation (not root)"
    echo "   Tools like nmap, sqlmap, nikto need to be installed manually"
fi

echo ""

# 4. Make scripts executable
echo "🔧 Setting up scripts..."
chmod +x run.sh
chmod +x check_tools.py
echo "✅ Scripts are executable"

echo ""

# 5. Check all tools
echo "🔍 Checking installed tools..."
python3 check_tools.py

echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "Quick Start:"
echo "  ./run.sh --target testphp.vulnweb.com --stages discovery,vulnerability --dry-run"
echo ""
echo "Check tools:"
echo "  python3 check_tools.py"
echo ""
echo "Full scan:"
echo "  ./run.sh --target example.com --dry-run"
echo ""
