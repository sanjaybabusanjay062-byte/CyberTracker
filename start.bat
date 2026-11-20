@echo off
:: CYBERTRACE AI — Quick Start Script for Windows
:: Run this from the cybertrace-ai directory

echo.
echo ====================================================
echo   CYBERTRACE AI - Digital Forensics Platform
echo ====================================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install Python 3.10+ from python.org
    pause
    exit /b 1
)

:: Create venv if it doesn't exist
if not exist "venv\" (
    echo [1/4] Creating virtual environment...
    python -m venv venv
)

:: Activate venv
echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

:: Install dependencies
echo [3/4] Installing dependencies...
pip install -r requirements.txt --quiet

:: Create .env if not exists
if not exist ".env" (
    copy .env.example .env >nul
    echo [INFO] Created .env from .env.example
)

:: Initialize database
if not exist "cybertrace.db" (
    echo [4/4] Initializing database with sample data...
    python init_db.py
) else (
    echo [4/4] Database already exists. Skipping initialization.
    echo       To reset: delete cybertrace.db and run again.
)

echo.
echo ====================================================
echo   Starting CYBERTRACE AI server...
echo   Open: http://localhost:5000
echo   Press Ctrl+C to stop
echo ====================================================
echo.

python run.py

pause
