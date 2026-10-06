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

set "ANALYZER_HOST=127.0.0.1"
set "ANALYZER_PORT=8000"

echo.
echo  FlowScope demarre...
echo.
echo  Le serveur se connecte a la base de donnees : cela prend quelques
echo  secondes. Le navigateur s'ouvrira tout seul quand il sera pret.
echo.

REM LE SERVEUR DEMARRE DANS SA PROPRE FENETRE, ET ON ATTEND QU'IL REPONDE AVANT
REM D'OUVRIR LE NAVIGATEUR. La premiere version ouvrait le navigateur d'abord : avec une
REM base distante, le port reste ferme huit a quinze secondes, et l'utilisateur tombait sur
REM ERR_CONNECTION_REFUSED alors que tout allait bien. Attendre coute quinze secondes ;
REM ne pas attendre coute la confiance de celui qui essaie.
start "FlowScope - serveur" /min ".venv\Scripts\python.exe" -m backend.main

set /a essais=0
:attendre
set /a essais+=1
timeout /t 1 /nobreak >nul
REM Un simple test de connexion TCP : plus fiable que d'interroger une route HTTP,
REM et PowerShell est present sur tout Windows depuis la version 7.
powershell -NoProfile -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', %ANALYZER_PORT%); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 goto pret
if %essais% lss 60 goto attendre

echo.
echo  Le serveur n'a pas repondu apres une minute.
echo  Ouvrez la fenetre « FlowScope - serveur » : elle contient l'erreur exacte.
echo.
pause
exit /b 1

:pret
echo  Serveur pret en %essais% seconde(s).
echo.
start "" "http://127.0.0.1:%ANALYZER_PORT%"
echo  Tableau de bord : http://127.0.0.1:%ANALYZER_PORT%
echo.
echo  Pour tout arreter, fermez la fenetre « FlowScope - serveur ».
echo  Cette fenetre-ci peut etre fermee sans consequence.
echo.
pause
