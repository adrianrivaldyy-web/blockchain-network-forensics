@echo off
setlocal
title Membagi Master Capture menjadi 5 PCAP

set "ROOT=%~dp0.."
set "EVIDENCE=%ROOT%\evidence"
set "EDITCAP=C:\Program Files\Wireshark\editcap.exe"

echo ================================================================
echo PEMBAGIAN FILE PCAP OTOMATIS
echo ================================================================
echo.

if not exist "%EDITCAP%" (
    echo editcap tidak ditemukan pada lokasi default:
    echo %EDITCAP%
    echo.
    set /p EDITCAP=Masukkan lokasi lengkap editcap.exe: 
)

if not exist "%EDITCAP%" (
    echo ERROR: editcap.exe tetap tidak ditemukan.
    pause
    exit /b 1
)

set /p NIM=Masukkan NIM tanpa spasi: 
if "%NIM%"=="" (
    echo ERROR: NIM tidak boleh kosong.
    pause
    exit /b 1
)

set /p MASTER=Masukkan lokasi lengkap master capture .pcapng/.pcap: 
if not exist "%MASTER%" (
    echo ERROR: File master tidak ditemukan.
    pause
    exit /b 1
)

if not exist "%EVIDENCE%" mkdir "%EVIDENCE%"

echo.
echo Membuat lima file PCAP...
"%EDITCAP%" -F pcap -r "%MASTER%" "%EVIDENCE%\PCAP01_%NIM%.pcap" 1-30
if errorlevel 1 goto :error
"%EDITCAP%" -F pcap -r "%MASTER%" "%EVIDENCE%\PCAP02_%NIM%.pcap" 31-80
if errorlevel 1 goto :error
"%EDITCAP%" -F pcap -r "%MASTER%" "%EVIDENCE%\PCAP03_%NIM%.pcap" 81-150
if errorlevel 1 goto :error
"%EDITCAP%" -F pcap -r "%MASTER%" "%EVIDENCE%\PCAP04_%NIM%.pcap" 151-240
if errorlevel 1 goto :error
"%EDITCAP%" -F pcap -r "%MASTER%" "%EVIDENCE%\PCAP05_%NIM%.pcap" 241-340
if errorlevel 1 goto :error

echo.
echo BERHASIL. File tersimpan di:
echo %EVIDENCE%
echo.
dir "%EVIDENCE%\PCAP*.pcap"
pause
exit /b 0

:error
echo.
echo ERROR: editcap gagal membuat file.
echo Pastikan master capture memiliki minimal 340 paket.
pause
exit /b 1
