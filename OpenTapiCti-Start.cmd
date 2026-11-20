@echo off
setlocal
cd /d "%~dp0"
where pyw.exe >nul 2>&1
if not errorlevel 1 (
  start "" pyw.exe -3 "%~dp0OpenTapiCti.pyw"
  exit /b
)
where pythonw.exe >nul 2>&1
if not errorlevel 1 (
  start "" pythonw.exe "%~dp0OpenTapiCti.pyw"
  exit /b
)
echo Bitte Python 3.10 oder neuer mit Tk und Python-Launcher installieren.
echo Falls .pyw bereits Python zugeordnet ist, OpenTapiCti.pyw direkt oeffnen.
pause
