@echo off
REM Creates a PRIVATE GitHub repo from this folder and pushes it.
REM Step 1 opens your browser to log in - that part only you can do.
title Push ETH Switch Tester to GitHub
cd /d "%~dp0"
set "PATH=%PROGRAMFILES%\GitHub CLI;%PATH%"

echo ============================================================
echo  1/2  Logging in to GitHub (opens your browser)
echo ============================================================
gh auth status >nul 2>&1
if %errorlevel% == 0 (
  echo Already logged in - skipping.
) else (
  gh auth login --hostname github.com --git-protocol https --web
  if errorlevel 1 goto :fail
)

echo.
echo ============================================================
echo  2/2  Creating PRIVATE repo and pushing
echo ============================================================
git remote get-url origin >nul 2>&1
if %errorlevel% == 0 (
  echo Remote already exists - pushing instead.
  git push -u origin main
) else (
  gh repo create ETH-Switch-Tester --private --source=. --remote=origin --push
)
if errorlevel 1 goto :fail

echo.
echo ---- done ----
git remote -v
gh repo view --web
goto :end

:fail
echo.
echo Something failed above. Common causes:
echo   - login cancelled or timed out
echo   - a repo named ETH-Switch-Tester already exists on your account
echo     (then run:  gh repo create ETH-Switch-Tester-2 --private --source=. --push)
:end
echo.
pause
