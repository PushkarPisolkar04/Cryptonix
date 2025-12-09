#!/bin/bash
# AutoPenTest Setup Script

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              AutoPenTest Setup Script                         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "⚠️  Please do not run as root"
    exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

echo "🔍 Detected OS: $OS"
echo ""

# Install system dependencies
echo "📦 Installing system dependencies..."
if [ "$OS" == "linux" ]; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv nmap git wget curl
elif [ "$OS" == "macos" ]; then
    brew install python3 nmap git wget curl
fi

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "📚 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
echo "📁 Creating directories..."
mkdir -p config reports logs

# Copy configuration templates
echo "⚙️  Setting up configuration..."
if [ ! -f config/config.yaml ]; then
    cp config/config.example.yaml config/config.yaml
    echo "✅ Created config/config.yaml (please edit with your settings)"
fi

if [ ! -f config/scope.yaml ]; then
    cp config/scope.example.yaml config/scope.yaml
    echo "✅ Created config/scope.yaml"
fi

# Optional: Install external tools
echo ""
echo "🔧 Optional External Tools:"
echo "   1. Metasploit Framework"
echo "   2. OWASP ZAP"
echo "   3. Nessus"
echo "   4. SQLMap"
echo "   5. Nikto"
echo ""
read -p "Install external tools? (y/N): " install_tools

if [[ $install_tools =~ ^[Yy]$ ]]; then
    echo "📥 Installing external tools..."
    
    # SQLMap
    if [ ! -d "tools/sqlmap" ]; then
        echo "Installing SQLMap..."
        mkdir -p tools
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools/sqlmap
    fi
    
    # Nikto
    if [ ! -d "tools/nikto" ]; then
        echo "Installing Nikto..."
        git clone https://github.com/sullo/nikto tools/nikto
    fi
    
    echo "✅ External tools installed in ./tools/"
    echo "⚠️  Metasploit and OWASP ZAP require manual installation"
fi

# Test installation
echo ""
echo "🧪 Testing installation..."
python -c "import nmap, requests, aiohttp; print('✅ Core dependencies OK')"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Next steps:"
echo "   1. Edit config/config.yaml with your API keys and tool paths"
echo "   2. Edit config/scope.yaml with your target scope"
echo "   3. Activate virtual environment: source venv/bin/activate"
echo "   4. Run: python main.py --help"
echo ""
echo "📖 Documentation: docs/ARCHITECTURE.md"
echo "🔧 Implementation guide: IMPLEMENTATION_GUIDE.md"
echo ""
