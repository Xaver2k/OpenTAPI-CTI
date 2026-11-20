@echo off
setlocal
cd /d "%~dp0"
where cl.exe >nul 2>&1 || (echo x64 Native Tools Command Prompt fuer Visual Studio mit Windows SDK verwenden. & exit /b 1)
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" (echo x64-Zielumgebung erforderlich. & exit /b 1)
cl /nologo /EHsc /std:c++17 /O2 /MT /DUNICODE /D_UNICODE /LD CTIPilot.cpp /link /DEF:CTIPilot.def /OUT:..\FrapuriCTI.tsp
exit /b %errorlevel%
