@echo off
REM
REM elect-rix AUDIT-KIT — USB Launcher (Windows)
REM
REM Priority:
REM   1. audit-kit.py (polished wizard/express launcher) via Python
REM   2. Bundled Windows .exe (bin\windows\scanner.exe) — no Python needed
REM   3. Portable Python embed (bin\windows-embed\python) — no install needed
REM   4. scanner.py via system Python (fallback)
REM
REM Usage:
REM   run.bat              Wizard mode (interactive)
REM   run.bat --express    Express mode (auto-detect)
REM   run.bat --help       Show options
REM

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

echo ============================================================
echo elect-rix AUDIT-KIT
echo Shadow AI Discovery Scanner
echo ============================================================
echo Platform: Windows
echo USB:      %SCRIPT_DIR%
echo.

REM --- 0. Pre-scan validation ---

REM Check critical files exist
for %%f in (scanner.py ai_domains.json report_template.html) do (
    if not exist "%SCRIPT_DIR%\%%f" (
        echo ERROR: Missing critical file: %%f
        echo The USB may be corrupted. Re-copy from source.
        pause
        exit /b 1
    )
)

REM Check free space — try PowerShell first (works without admin), skip on failure
set FREE_CHECK=0
where powershell >nul 2>&1
if !errorlevel! equ 0 (
    for /f "usebackq delims=" %%s in (`powershell -NoProfile -Command "(Get-PSDrive '%SCRIPT_DIR:~0,1%').Free / 1MB -as [int]" 2^>nul`) do (
        set /a FREE_MB=%%s 2>nul
        set FREE_CHECK=1
    )
)
if !FREE_CHECK! equ 1 (
    if !FREE_MB! LSS 10 (
        echo WARNING: Less than 10MB free ^(!FREE_MB! MB^). Reports may fail to save.
        echo Run cleanup-reports.sh to free space ^(needs WSL or manual delete^).
        echo.
    )
)

REM --- 1. Find runtime ---

set PYTHON=
set SCANNER=
set SCANNER_ARGS=

REM Path 1: audit-kit.py via Python (preferred)
if exist "%SCRIPT_DIR%\audit-kit.py" (
    REM Try portable Python embed first (no install needed)
    if exist "%SCRIPT_DIR%\bin\windows-embed\python\python.exe" (
        set PYTHON="%SCRIPT_DIR%\bin\windows-embed\python\python.exe"
        echo Using: audit-kit.py ^(portable Python^)
        !PYTHON! "%SCRIPT_DIR%\audit-kit.py" %*
        goto :done
    )
    REM Try system Python. NOTE: "where python3" is not a reliable check —
    REM Windows 10/11 ships a python3.exe / python.exe "App Execution Alias"
    REM stub in PATH even when Python is NOT installed; it exists on disk
    REM (so `where` finds it) but just opens the Microsoft Store instead of
    REM running anything. Actually invoking --version is the only reliable
    REM test: the stub fails fast (non-zero exit) when stdout is redirected,
    REM a real interpreter prints its version and exits 0.
    python3 --version >nul 2>&1
    if !errorlevel! equ 0 (
        echo Using: audit-kit.py ^(system Python3^)
        python3 "%SCRIPT_DIR%\audit-kit.py" %*
        goto :done
    )
    python --version >nul 2>&1
    if !errorlevel! equ 0 (
        echo Using: audit-kit.py ^(system Python^)
        python "%SCRIPT_DIR%\audit-kit.py" %*
        goto :done
    )
)

REM Path 2: Bundled Windows .exe (no Python needed)
if exist "%SCRIPT_DIR%\bin\windows\scanner.exe" (
    set SCANNER="%SCRIPT_DIR%\bin\windows\scanner.exe"
    echo Using: bundled Windows executable
    goto :interactive
)

REM Path 3: Portable Python embed (no install needed)
if exist "%SCRIPT_DIR%\bin\windows-embed\python\python.exe" (
    set PYTHON="%SCRIPT_DIR%\bin\windows-embed\python\python.exe"
    set SCANNER=!PYTHON! "%SCRIPT_DIR%\scanner.py"
    echo Using: portable Python ^(no install needed^)
    goto :interactive
)

REM Path 4: System Python (see note above Path 1 — must invoke --version,
REM not "where", to rule out the Microsoft Store app-execution-alias stub)
python3 --version >nul 2>&1
if !errorlevel! equ 0 (
    set SCANNER=python3 "%SCRIPT_DIR%\scanner.py"
    echo Using: system Python3
    goto :interactive
)
python --version >nul 2>&1
if !errorlevel! equ 0 (
    set SCANNER=python "%SCRIPT_DIR%\scanner.py"
    echo Using: system Python
    goto :interactive
)

echo.
echo ERROR: No Python found and no bundled executable available.
echo Options:
echo   1. Install Python 3 from python.org
echo   2. Restore bin\windows-embed\python\ on the USB
echo   3. Build scanner.exe with PyInstaller
echo.
pause
exit /b 1

REM --- 2. Interactive mode (scanner.py fallback) ---

:interactive

echo.
echo Enter client name (for the report):
set /p CLIENT_NAME=

if "!CLIENT_NAME!"=="" (
    echo Client name is required.
    pause
    exit /b 1
)

echo.
echo Enter auditor name (default: elect-rix Auditor):
set /p AUDITOR_NAME=
if "!AUDITOR_NAME!"=="" set AUDITOR_NAME=elect-rix Auditor

echo.
echo Scan mode:
echo   1. Auto-detect everything (recommended) — browsers + software
echo   2. Auto-detect + staff interviews — full SA-1
echo   3. Browser history only
echo   4. Software inventory only
echo   5. DNS log file
echo.
echo Choice (default 1):
set /p SCAN_MODE=
if "!SCAN_MODE!"=="" set SCAN_MODE=1

REM --- 3. Run the scan ---

REM Locale-independent timestamp (works on any Windows locale)
for /f "usebackq tokens=1,2 delims= " %%a in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd_HHmmss'" 2^>nul`) do set TS=%%a
if "!TS!"=="" (
    REM PowerShell fallback failed — use WMIC (works on all locales)
    for /f "usebackq tokens=2 delims==" %%a in (`wmic os get localdatetime /value 2^>nul ^| find "="`) do set DT=%%a
    if "!DT!"=="" (
        REM Last resort — use raw %date% %time% (may break on non-US locales)
        set TS=%date:~-4,4%-%date:~-10,2%-%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
        set TS=!TS: =0!
    ) else (
        set TS=!DT:~0,4!-!DT:~4,2!-!DT:~6,2!_!DT:~8,2!!DT:~10,2!!DT:~12,2!
    )
)
set REPORTS_DIR=%SCRIPT_DIR%\reports\!TS!
mkdir "!REPORTS_DIR!" 2>nul

if "!SCAN_MODE!"=="1" (
    echo.
    echo Running auto-detect scan...
    !SCANNER! --auto --client "!CLIENT_NAME!" --auditor "!AUDITOR_NAME!" --output-dir "!REPORTS_DIR!"
) else if "!SCAN_MODE!"=="2" (
    echo.
    echo Running auto-detect + interview...
    !SCANNER! --auto --interview --client "!CLIENT_NAME!" --auditor "!AUDITOR_NAME!" --output-dir "!REPORTS_DIR!"
) else if "!SCAN_MODE!"=="3" (
    echo.
    echo Running browser history scan...
    set AUDITKIT_SKIP_SOFTWARE=1
    !SCANNER! --auto --client "!CLIENT_NAME!" --auditor "!AUDITOR_NAME!" --output-dir "!REPORTS_DIR!"
) else if "!SCAN_MODE!"=="4" (
    echo.
    echo Running software inventory scan...
    set AUDITKIT_SKIP_BROWSER=1
    !SCANNER! --auto --client "!CLIENT_NAME!" --auditor "!AUDITOR_NAME!" --output-dir "!REPORTS_DIR!"
) else if "!SCAN_MODE!"=="5" (
    echo.
    echo Enter path to DNS log file:
    set /p DNS_LOG=
    !SCANNER! --dns-log "!DNS_LOG!" --client "!CLIENT_NAME!" --auditor "!AUDITOR_NAME!" --output-dir "!REPORTS_DIR!"
) else (
    echo Invalid choice. Running auto-detect.
    !SCANNER! --auto --client "!CLIENT_NAME!" --auditor "!AUDITOR_NAME!" --output-dir "!REPORTS_DIR!"
)

REM --- 4. Open report ---

echo.
echo ============================================================
echo Scan complete!
echo Reports saved to: !REPORTS_DIR!
echo ============================================================

if exist "!REPORTS_DIR!\report.html" (
    echo.
    echo Opening report...
    start "" "!REPORTS_DIR!\report.html"
)

echo.
echo Files generated:
dir "!REPORTS_DIR!\" /b 2>nul
echo.
echo Copy the reports\ folder to take with you.

:done
if !errorlevel! neq 0 pause
