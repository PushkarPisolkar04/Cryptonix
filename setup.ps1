# AutoPenTest Setup Script for Windows
# Run with: powershell -ExecutionPolicy Bypass -File setup.ps1

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              AutoPenTest Setup Script (Windows)               ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "🔍 Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found. Please install Python 3.11+ from python.org" -ForegroundColor Red
    exit 1
}

# Create virtual environment
Write-Host "🐍 Creating Python virtual environment..." -ForegroundColor Yellow
python -m venv venv

# Activate virtual environment
Write-Host "🔌 Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Upgrade pip
Write-Host "📦 Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install dependencies
Write-Host "📚 Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt

# Check for Nmap
Write-Host ""
Write-Host "🔍 Checking for Nmap..." -ForegroundColor Yellow
try {
    $nmapVersion = nmap --version 2>&1 | Select-String "Nmap version"
    Write-Host "✅ Found: $nmapVersion" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Nmap not found!" -ForegroundColor Red
    Write-Host "   Nmap is REQUIRED for network scanning." -ForegroundColor Yellow
    Write-Host "   Install options:" -ForegroundColor Yellow
    Write-Host "   1. Download from: https://nmap.org/download.html" -ForegroundColor Cyan
    Write-Host "   2. Or run as Admin: choco install nmap -y" -ForegroundColor Cyan
    Write-Host ""
    $installNmap = Read-Host "Do you want to install Nmap via Chocolatey now? (y/n)"
    if ($installNmap -eq "y" -or $installNmap -eq "Y") {
        Write-Host "Installing Nmap via Chocolatey..." -ForegroundColor Yellow
        choco install nmap -y
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Nmap installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "❌ Failed to install Nmap. Please install manually." -ForegroundColor Red
        }
    }
}

# Check for Metasploit (optional)
Write-Host ""
Write-Host "🔍 Checking for Metasploit Framework (optional)..." -ForegroundColor Yellow
try {
    $msfVersion = msfconsole --version 2>&1
    Write-Host "✅ Found Metasploit" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Metasploit not found (optional - only needed for exploitation stage)" -ForegroundColor Yellow
    Write-Host "   Download from: https://www.metasploit.com/" -ForegroundColor Cyan
}

# Create directories
Write-Host "📁 Creating directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path config, reports, logs | Out-Null

# Copy configuration templates
Write-Host "⚙️  Setting up configuration..." -ForegroundColor Yellow
if (-not (Test-Path "config\config.yaml")) {
    Copy-Item "config\config.example.yaml" "config\config.yaml"
    Write-Host "✅ Created config\config.yaml (please edit with your settings)" -ForegroundColor Green
}

if (-not (Test-Path "config\scope.yaml")) {
    Copy-Item "config\config.example.yaml" "config\scope.yaml"
    Write-Host "✅ Created config\scope.yaml" -ForegroundColor Green
}

# Test installation
Write-Host ""
Write-Host "🧪 Testing installation..." -ForegroundColor Yellow
try {
    python -c "import requests, aiohttp; print('✅ Core dependencies OK')"
} catch {
    Write-Host "⚠️  Some dependencies may not be installed correctly" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    Setup Complete!                            ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "📝 Next steps:" -ForegroundColor Yellow
Write-Host "   1. Restart PowerShell (to refresh PATH if Nmap was just installed)"
Write-Host "   2. Edit config\config.yaml with your API keys and tool paths"
Write-Host "   3. Edit config\scope.yaml with your target scope"
Write-Host "   4. Run verification: python verify_installation.py"
Write-Host "   5. Run your first scan: .\run.ps1 --target example.com --dry-run"
Write-Host ""
Write-Host "📖 Documentation: docs\ARCHITECTURE.md" -ForegroundColor Cyan
Write-Host "🔧 Implementation guide: IMPLEMENTATION_GUIDE.md" -ForegroundColor Cyan
Write-Host ""
