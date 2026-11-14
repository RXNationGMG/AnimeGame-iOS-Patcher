@echo off
setlocal
title Genshin Impact - iOS RSA Patcher
cd /d "%~dp0"

echo.
echo   Genshin Impact - iOS RSA Patcher
echo   -------------------------------
echo.

rem --- find Python -----------------------------------------------------------
set "PY="
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if not defined PY (
    where python >nul 2>nul
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    echo   Python was not found on this computer.
    echo.
    echo   Install it from https://www.python.org/downloads/
    echo   During setup, tick "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

rem --- install the packages once ---------------------------------------------
%PY% -c "import numpy, capstone, keystone" >nul 2>nul
if errorlevel 1 (
    echo   Installing the packages this tool needs ^(one time only^)...
    echo.
    %PY% -m pip install --user --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        echo.
        echo   Could not install the packages. Check your internet connection,
        echo   then double-click this file again.
        echo.
        pause
        exit /b 1
    )
    echo.
)

%PY% rsa_patch.py %*

echo.
pause
