@echo off
setlocal enabledelayedexpansion
title CYBERTRACE AI - Forensic SOC Platform Launcher

:: Change to the directory where this script is located
cd /d "%~dp0"

echo ==============================================================================
echo           CYBERTRACE AI - DIGITAL FORENSICS & INCIDENT RESPONSE
echo ==============================================================================
echo.

:: 1. Detect Python executable (checks python, py, and common install locations)
set "PYTHON_EXE="

python --version >nul 2>&1
if !errorlevel! equ 0 (
    set "PYTHON_EXE=python"
) else (
    py --version >nul 2>&1
    if !errorlevel! equ 0 (
        set "PYTHON_EXE=py"
    ) else (
        for /d %%P in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
            if exist "%%P\python.exe" set "PYTHON_EXE=%%P\python.exe"
        )
        if not defined PYTHON_EXE (
            for /d %%P in ("C:\Program Files\Python*") do (
                if exist "%%P\python.exe" set "PYTHON_EXE=%%P\python.exe"
            )
        )
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not detected on your system.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Using Python: %PYTHON_EXE%
%PYTHON_EXE% --version
echo.

:: 2. Setup Virtual Environment
if not exist "venv\Scripts\activate.bat" (
    echo [1/4] Creating virtual environment (venv)...
    "%PYTHON_EXE%" -m venv venv
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

:: 3. Install Requirements
echo [3/4] Checking and installing dependencies...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if !errorlevel! neq 0 (
    echo [WARNING] Some dependencies had installation issues, retrying...
    pip install -r requirements.txt
)

:: 4. Setup Environment File
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [*] Initialized .env configuration file.
    )
)

:: 5. Initialize Database with forensic sample data if missing
if not exist "cybertrace.db" (
    echo [4/4] Initializing database with pre-configured forensic investigation cases...
    python init_db.py
) else (
    echo [4/4] Database cybertrace.db verified.
)

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
echo [*] Opening default web browser in 3 seconds...

:: Launch browser in background after 3 seconds
start /b cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:5000"

:: Start Flask server
python run.py

echo.
echo Server stopped.
pause
