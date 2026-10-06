@echo off
chcp 65001 >nul
title FlowScope
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo  FlowScope n'est pas encore installe sur cette machine.
    echo  Double-cliquez d'abord sur :  installer-windows.bat
    echo.
    pause
    exit /b 1
)

REM L'adresse d'ecoute et le port sont volontairement explicites : c'est ce que
REM l'utilisateur verra dans son navigateur.
set "ANALYZER_HOST=127.0.0.1"
set "ANALYZER_PORT=8000"

echo.
echo  FlowScope demarre...
echo  Tableau de bord : http://127.0.0.1:8000
echo.
echo  Pour arreter : fermez cette fenetre, ou appuyez sur Ctrl+C.
echo.

start "" "http://127.0.0.1:8000"
".venv\Scripts\python.exe" -m backend.main
pause
