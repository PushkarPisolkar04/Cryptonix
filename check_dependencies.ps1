# Dependency Checker for Cryptonix
# Run this to verify all required tools are installed

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "           Cryptonix Dependency Checker                     " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$allGood = $true

# Check Python
Write-Host "Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = py -3.11 --version 2>&1
    if ($pythonVersion -match "3\.11") {
        Write-Host "   OK Python 3.11 found: $pythonVersion" -ForegroundColor Green
    } else {
        Write-Host "   WARNING Python 3.11 not found. Found: $pythonVersion" -ForegroundColor Yellow
        Write-Host "      Install from: https://www.python.org/downloads/" -ForegroundColor Cyan
        $allGood = $false
    }
} catch {
    Write-Host "   ERROR Python not found!" -ForegroundColor Red
    Write-Host "      Install from: https://www.python.org/downloads/" -ForegroundColor Cyan
    $allGood = $false
}

# Check pip packages
Write-Host ""
Write-Host "Checking Python packages..." -ForegroundColor Yellow
$requiredPackages = @(
    "requests",
    "aiohttp",
    "python-nmap",
    "pymetasploit3",
    "shodan",
    "dnspython",
    "beautifulsoup4",
    "loguru",
    "click"
)

foreach ($package in $requiredPackages) {
    try {
        $installed = py -3.11 -m pip show $package 2>&1
        if ($installed -match "Name:") {
            Write-Host "   OK $package" -ForegroundColor Green
        } else {
            Write-Host "   MISSING $package" -ForegroundColor Red
            $allGood = $false
        }
    } catch {
        Write-Host "   MISSING $package" -ForegroundColor Red
        $allGood = $false
    }
}

# Check Nmap
Write-Host ""
Write-Host "Checking Nmap..." -ForegroundColor Yellow
try {
    $nmapVersion = nmap --version 2>&1 | Select-String "Nmap version"
    Write-Host "   OK Nmap found: $nmapVersion" -ForegroundColor Green
} catch {
    Write-Host "   ERROR Nmap not found!" -ForegroundColor Red
    Write-Host "      REQUIRED for network scanning" -ForegroundColor Yellow
    Write-Host "      Install from: https://nmap.org/download.html" -ForegroundColor Cyan
    Write-Host "      Or run as Admin: choco install nmap -y" -ForegroundColor Cyan
    $allGood = $false
}

# Check Metasploit (optional)
Write-Host ""
Write-Host "Checking Metasploit Framework (optional)..." -ForegroundColor Yellow
try {
    $msfVersion = msfconsole --version 2>&1
    Write-Host "   OK Metasploit found" -ForegroundColor Green
} catch {
    Write-Host "   WARNING Metasploit not found (optional)" -ForegroundColor Yellow
    Write-Host "      Only needed for exploitation stage" -ForegroundColor Gray
    Write-Host "      Install from: https://www.metasploit.com/" -ForegroundColor Cyan
}

# Check config files
Write-Host ""
Write-Host "Checking configuration files..." -ForegroundColor Yellow
if (Test-Path "config\config.yaml") {
    Write-Host "   OK config\config.yaml exists" -ForegroundColor Green
} else {
    Write-Host "   MISSING config\config.yaml" -ForegroundColor Red
    Write-Host "      Copy from: config\config.example.yaml" -ForegroundColor Cyan
    $allGood = $false
}

if (Test-Path "config\scope.yaml") {
    Write-Host "   OK config\scope.yaml exists" -ForegroundColor Green
} else {
    Write-Host "   WARNING config\scope.yaml missing (optional)" -ForegroundColor Yellow
    Write-Host "      Copy from: config\scope.example.yaml" -ForegroundColor Cyan
}

# Summary
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($allGood) {
    Write-Host "SUCCESS: All required dependencies are installed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Ready to run:" -ForegroundColor Yellow
    Write-Host "   .\run.ps1 --target example.com --dry-run" -ForegroundColor Cyan
} else {
    Write-Host "ERROR: Some dependencies are missing!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To install missing dependencies:" -ForegroundColor Yellow
    Write-Host "   1. Run: .\setup.ps1" -ForegroundColor Cyan
    Write-Host "   2. Install Nmap: choco install nmap -y (as Admin)" -ForegroundColor Cyan
    Write-Host "   3. Run this checker again: .\check_dependencies.ps1" -ForegroundColor Cyan
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
