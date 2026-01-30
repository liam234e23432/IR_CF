@echo off
title VIP3R & NIMA - AUTO SETUP
echo ====================================================
echo    INSTALLING REQUIRMENTS FOR VIP3R & NIMA SCANNER
echo ====================================================
echo.
echo [*] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed! Please install Python first.
    pause
    exit
)
echo [*] Installing Colorama library...
pip install colorama
echo.
echo [!] ALL DONE! YOU CAN NOW RUN THE SCANNER.
echo.
pause