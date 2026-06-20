@echo off
setlocal
title Blockchain PCAP
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py blockchain_pcap.py
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        python blockchain_pcap.py
    ) else (
        echo Python tidak ditemukan. Instal Python dan centang Add Python to PATH.
    )
)

echo.
pause
