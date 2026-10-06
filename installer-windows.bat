@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Installation de FlowScope - analyseur de trafic reseau

echo.
echo  ============================================================
echo   FlowScope - installation sur Windows
echo  ============================================================
echo.
echo  Ce script prepare tout ce qu'il faut pour lancer FlowScope :
echo    1. il verifie que Python est present
echo    2. il cree un environnement isole (rien n'est installe dans Windows)
echo    3. il installe les dependances du projet
echo    4. il cree le fichier de configuration avec un jeton unique
echo    5. il verifie que la capture reseau est possible
echo.
echo  Rien n'est modifie en dehors de ce dossier.
echo.
pause

cd /d "%~dp0"
echo  Dossier du projet : %CD%
echo.

REM ---------------------------------------------------------------- 1. Python
echo  [1/5] Recherche de Python...
set "PYTHON="
where py >nul 2>&1 && set "PYTHON=py -3"
if not defined PYTHON ( where python >nul 2>&1 && set "PYTHON=python" )
if not defined PYTHON (
    echo.
    echo  [ECHEC] Python n'est pas installe, ou n'est pas dans le PATH.
    echo.
    echo  Installez Python 3.11 ou plus recent depuis :
    echo      https://www.python.org/downloads/
    echo.
    echo  IMPORTANT : a la premiere page de l'installeur, cochez
    echo      "Add python.exe to PATH"
    echo  Sans cette case, ce script ne trouvera pas Python.
    echo.
    pause
    exit /b 1
)
%PYTHON% -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
    echo  [ECHEC] Python est present mais trop ancien.
    %PYTHON% --version
    echo  FlowScope demande Python 3.11 ou plus recent.
    pause
    exit /b 1
)
for /f "delims=" %%v in ('%PYTHON% --version 2^>^&1') do set "VERSION=%%v"
echo        trouve : !VERSION!

REM ---------------------------------------------------------------- 2. environnement
echo  [2/5] Creation de l'environnement isole (.venv)...
if exist ".venv\Scripts\python.exe" (
    echo        deja present, on le reutilise
) else (
    %PYTHON% -m venv .venv
    if errorlevel 1 (
        echo  [ECHEC] Impossible de creer l'environnement.
        echo  Verifiez que vous avez le droit d'ecrire dans ce dossier.
        pause
        exit /b 1
    )
    echo        cree
)

REM ---------------------------------------------------------------- 3. dependances
echo  [3/5] Installation des dependances (cela peut prendre une a trois minutes)...
".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo.
    echo  [ECHEC] L'installation des dependances a echoue.
    echo  Causes les plus frequentes : pas de connexion Internet,
    echo  ou un proxy d'entreprise qui bloque pip.
    echo.
    pause
    exit /b 1
)
echo        installees

REM ---------------------------------------------------------------- 4. configuration
echo  [4/5] Fichier de configuration (.env)...
if exist ".env" (
    echo        .env existe deja : il n'est PAS modifie
) else (
    if not exist ".env.example" (
        echo  [ECHEC] .env.example est absent : le depot est incomplet.
        pause
        exit /b 1
    )
    copy /y ".env.example" ".env" >nul
    REM Un jeton unique par installation. Sans lui, n'importe qui pourrait
    REM injecter de faux paquets dans le tableau de bord.
    for /f "delims=" %%t in ('.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"') do set "JETON=%%t"
    ".venv\Scripts\python.exe" -c "import io,os,sys; p='.env'; s=io.open(p,encoding='utf-8').read(); s=s.replace('ANALYZER_AGENT_TOKEN=', 'ANALYZER_AGENT_TOKEN='+sys.argv[1], 1) if 'ANALYZER_AGENT_TOKEN=' in s else s+'ANALYZER_AGENT_TOKEN='+sys.argv[1]+chr(10); io.open(p,'w',encoding='utf-8').write(s)" "!JETON!"
    echo        .env cree, avec un jeton unique pour cette machine
)

REM ---------------------------------------------------------------- 5. capture
echo  [5/5] Verification de la capture reseau...
".venv\Scripts\python.exe" -c "from scapy.all import get_if_list; n=len(get_if_list()); print('       ' + str(n) + ' interface(s) reseau detectee(s)')" 2>nul
if errorlevel 1 (
    echo        [ATTENTION] La capture reseau n'est pas prete.
    echo.
    echo  FlowScope est installe et demarrera, mais il ne verra aucun paquet.
    echo  Il manque Npcap, le pilote de capture de Windows.
    echo.
    echo  Telechargez-le ici : https://npcap.com/#download
    echo  Installez-le avec l'option "WinPcap API-compatible Mode".
    echo  ATTENTION : cette installation demande les droits d'administrateur.
    echo.
)

echo.
echo  ============================================================
echo   Installation terminee
echo  ============================================================
echo.
echo  Pour lancer FlowScope, double-cliquez sur :  lancer.bat
echo  Le tableau de bord s'ouvrira sur http://127.0.0.1:8000
echo.
echo  Sans base de donnees, FlowScope fonctionne en memoire :
echo  les donnees disparaissent a l'arret. Pour les conserver,
echo  renseignez ANALYZER_DATABASE_URL dans le fichier .env.
echo.
pause
endlocal
