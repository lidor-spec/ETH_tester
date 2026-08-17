@echo off
title Verify the tester is not flattering reality
REM Destroys a KNOWN number of frames before they reach the wire, then checks
REM the report matches. Needs both USB adapters cabled into the switch.
net session >nul 2>&1
if %errorLevel% == 0 goto :run
powershell -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
exit /b
:run
cd /d "%~dp0"
"C:\Program Files\Python313\python.exe" eth_switch_tester.py --verify "Ethernet 3" "Ethernet 4"
echo.
pause
