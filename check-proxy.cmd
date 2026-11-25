@echo off
chcp 65001 >nul
where py >nul 2>&1
if not errorlevel 1 (
  py -3 "%~dp0check_proxy.py" %*
) else (
  python "%~dp0check_proxy.py" %*
)
exit /b %errorlevel%
