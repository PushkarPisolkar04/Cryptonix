#!/bin/bash
# AutoPenTest Runner Script for Linux/Kali
# Ensures correct Python version is used

# Check if Python 3 is available
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "Using Python $PYTHON_VERSION"

# Run the main script with all arguments
$PYTHON_CMD main.py "$@"
