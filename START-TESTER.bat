@echo off
title ETH Switch Tester
REM Raw frame injection requires Administrator, so self-elevate first.
net session >nul 2>&1
if %errorLevel% == 0 goto :run
powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
exit /b
:run
cd /d "%~dp0"
set PY=C:\Program Files\Python313\python.exe
if not exist "%PY%" set PY=python
if not exist "eth_switch_tester.py" (
  echo eth_switch_tester.py is missing from this folder.
  pause
  exit /b 1
)
"%PY%" eth_switch_tester.py
if errorlevel 1 pause
