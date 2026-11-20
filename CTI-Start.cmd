@echo off
setlocal
cd /d "%~dp0"
where pyw.exe >nul 2>&1
if not errorlevel 1 (
  start "" pyw.exe -3 "%~dp0CTIPilot.pyw"
  exit /b
)
where pythonw.exe >nul 2>&1
if not errorlevel 1 (
  start "" pythonw.exe "%~dp0CTIPilot.pyw"
  exit /b
)
echo Bitte Python 3.10 oder neuer mit Tk und Python-Launcher installieren.
echo Falls .pyw bereits Python zugeordnet ist, CTIPilot.pyw direkt oeffnen.
pause
