# Cryptonix Runner Script for Windows
# Ensures correct Python version is used

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $Arguments
)

Write-Host "🛡️  Starting Cryptonix..." -ForegroundColor Cyan

# Try to find Python
$pythonCmd = $null

# Try py launcher with 3.11
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3.11"
    Write-Host "Using Python 3.11 via py launcher" -ForegroundColor Green
}
# Try python3
elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
    Write-Host "Using python3" -ForegroundColor Green
}
# Try python
elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
    Write-Host "Using python" -ForegroundColor Green
}
else {
    Write-Host "❌ Python not found! Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Convert arguments array to string properly for Python
$argString = $Arguments -join ' '
$cmd = "$pythonCmd main.py $argString"

Invoke-Expression $cmd
