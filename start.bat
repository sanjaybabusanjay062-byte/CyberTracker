@echo off
setlocal enabledelayedexpansion
title CYBERTRACE AI - Forensic SOC Platform Launcher

:: Change to the directory where this script is located
cd /d "%~dp0"

echo ==============================================================================
echo           CYBERTRACE AI - DIGITAL FORENSICS & INCIDENT RESPONSE
echo ==============================================================================
echo.

:: 1. Prioritize explicit Python 3.11 path, then fallback to PATH search
set "PYTHON_EXE="

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
) else (
    for /d %%P in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
        if exist "%%P\python.exe" set "PYTHON_EXE=%%P\python.exe"
    )
    if not defined PYTHON_EXE (
        for /d %%P in ("C:\Program Files\Python*") do (
            if exist "%%P\python.exe" set "PYTHON_EXE=%%P\python.exe"
        )
    )
    if not defined PYTHON_EXE (
        python --version >nul 2>&1
        if !errorlevel! equ 0 set "PYTHON_EXE=python"
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not detected on your system.
    echo Please install Python 3.11 from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [*] Using Python: %PYTHON_EXE%
"%PYTHON_EXE%" --version
echo.

:: 2. Setup or verify database
if not exist "cybertrace.db" (
    echo [1/3] Initializing forensic database with investigation cases...
    "%PYTHON_EXE%" init_db.py
) else (
    echo [1/3] Forensic database verified (cybertrace.db).
)

:: 3. Setup Environment File if missing
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [*] Initialized .env configuration file.
    )
)

echo [2/3] Checking dependencies...
"%PYTHON_EXE%" -m pip install -r requirements.txt --quiet

echo.
echo ==============================================================================
echo   SERVER STARTING AT: http://localhost:5000
echo ==============================================================================
echo   Demo Login Accounts:
echo     - Admin:        admin@cybertrace.ai       /  CyberTrace2024!
echo     - Investigator: investigator@cybertrace.ai /  Invest2024!
echo     - Analyst:      analyst@cybertrace.ai      /  Analyst2024!
echo ==============================================================================
echo.
echo [3/3] Opening your browser in 2 seconds...

:: Launch browser in background
start /b cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5000"

:: Start Flask server
"%PYTHON_EXE%" run.py

echo.
echo Server stopped.
pause
