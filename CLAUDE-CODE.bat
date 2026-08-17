@echo off
REM Opens Claude Code in this project folder. It reads CLAUDE.md automatically,
REM so it starts with the full project context.
title Claude Code - ETH Switch Tester
cd /d "%~dp0"
set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where claude >nul 2>&1 || (
  echo Claude Code not found. Install it with:
  echo    irm https://claude.ai/install.ps1 ^| iex
  pause
  exit /b 1
)
echo Project: %CD%
echo.
claude
