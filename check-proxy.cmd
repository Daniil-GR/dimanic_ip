@echo off
chcp 65001 >nul
set "SCRIPT=%~dp0web_app.py"
if /I "%~1"=="--cli" goto cli
if /I "%~1"=="--reset-key" set "SCRIPT=%~dp0check_proxy.py"
if /I "%~1"=="--key-only" set "SCRIPT=%~dp0check_proxy.py"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 "%SCRIPT%" %*
) else (
  python "%SCRIPT%" %*
)
exit /b %errorlevel%

:cli
rem Use Python directly for CLI arguments after --cli
shift
where py >nul 2>&1
if not errorlevel 1 (
  py -3 "%~dp0check_proxy.py" %1 %2 %3 %4 %5 %6 %7 %8 %9
) else (
  python "%~dp0check_proxy.py" %1 %2 %3 %4 %5 %6 %7 %8 %9
)
exit /b %errorlevel%
