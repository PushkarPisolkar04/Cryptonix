# AutoPenTest Runner Script
# Ensures correct Python version (3.11) is used

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    $Arguments
)

Write-Host "Starting AutoPenTest with Python 3.11..." -ForegroundColor Cyan
py -3.11 main.py $Arguments
