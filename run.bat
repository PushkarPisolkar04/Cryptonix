@echo off
REM Interactive AutoPenTest Runner
REM Double-click this file to run interactively

echo ============================================================
echo            Cryptonix - Automated Penetration Testing
echo ============================================================
echo.

:menu
echo What would you like to do?
echo.
echo 1. OSINT scan only (fastest - 15-30 seconds, dry-run)
echo 2. Fast scan (10 subdomains, top 1000 ports - 2-5 min, dry-run)
echo 3. Full scan (50 subdomains, all ports - 30+ min, dry-run)
echo 4. REAL exploitation (requires authorization!)
echo 5. Check dependencies
echo 6. Show help
echo 7. Custom command
echo 8. Exit
echo.

set /p choice="Enter your choice (1-8): "

if "%choice%"=="1" goto osint
if "%choice%"=="2" goto fast_scan
if "%choice%"=="3" goto full_scan
if "%choice%"=="4" goto full_real
if "%choice%"=="5" goto check
if "%choice%"=="6" goto help
if "%choice%"=="7" goto custom
if "%choice%"=="8" goto end

echo Invalid choice. Please try again.
echo.
goto menu

:osint
set /p target="Enter target (e.g., example.com): "
echo.
echo Running OSINT scan on %target% (dry-run mode)...
echo.
py -3.11 main.py --target %target% --stages osint --dry-run --verbose
echo.
echo Scan complete! Check the reports folder.
pause
goto menu

:fast_scan
set /p target="Enter target (e.g., example.com): "
echo.
echo ============================================================
echo FAST SCAN MODE (Dry-Run)
echo ============================================================
echo - Scans 10 subdomains
echo - Scans top 1000 ports
echo - Estimated time: 2-5 minutes
echo - Safe simulation, no exploitation
echo ============================================================
echo.
echo Starting fast scan on %target%...
echo.
py -3.11 main.py --target %target% --dry-run --verbose
echo.
echo Scan complete! Check the reports folder.
pause
goto menu

:full_scan
set /p target="Enter target (e.g., example.com): "
echo.
echo ============================================================
echo FULL SCAN MODE (Dry-Run - SLOW!)
echo ============================================================
echo - Scans 50 subdomains
echo - Scans ALL 65535 ports
echo - Estimated time: 30+ minutes
echo - Safe simulation, no exploitation
echo ============================================================
echo.
set /p confirm="This will take 30+ minutes. Continue? (yes/no): "
if /i not "%confirm%"=="yes" (
    echo Cancelled. Try fast scan instead.
    pause
    goto menu
)
echo.
echo Starting full scan on %target% (this will take a while)...
echo.
py -3.11 main.py --target %target% --aggressive --dry-run --verbose
echo.
echo Scan complete! Check the reports folder.
pause
goto menu

:full_real
echo.
echo ============================================================
echo WARNING: REAL EXPLOITATION MODE
echo ============================================================
echo.
echo This will ACTUALLY attempt to exploit vulnerabilities!
echo.
echo REQUIREMENTS:
echo - Written authorization from target owner
echo - Legal permission to test
echo - Understanding of risks
echo.
set /p confirm="Do you have authorization? (yes/no): "

if /i not "%confirm%"=="yes" (
    echo.
    echo Cancelled. Use dry-run mode instead.
    pause
    goto menu
)

set /p target="Enter target (e.g., example.com): "
echo.
echo ============================================================
echo RUNNING REAL EXPLOITATION on %target%
echo ============================================================
echo.
py -3.11 main.py --target %target% --verbose
echo.
echo Assessment complete! Check the reports folder.
pause
goto menu

:check
echo.
echo Checking dependencies...
echo.
powershell -ExecutionPolicy Bypass -File check_dependencies.ps1
pause
goto menu

:help
echo.
py -3.11 main.py --help
echo.
pause
goto menu

:custom
echo.
echo Enter your custom command (without 'py -3.11 main.py')
echo Example: --target example.com --stages discovery --dry-run
echo.
set /p custom_cmd="Command: "
echo.
py -3.11 main.py %custom_cmd%
echo.
pause
goto menu

:end
echo.
echo Goodbye!
timeout /t 2 >nul
exit
