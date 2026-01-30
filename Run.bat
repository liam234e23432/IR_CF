@echo off
title VIP3R & NIMA SCANNER
python "%~dp0VIP3R_SCAN.py"
if %errorlevel% neq 0 (
    echo.
    echo [!] THE SCRIPT CRASHED OR STOPPED.
    pause
)
pause