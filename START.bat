@echo off
title AttackGraph Lens
cd /d "%~dp0"
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3.11 or newer was not found.
  echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH", then double-click this file again.
  pause
  exit /b 1
)
%PY% start.py %*
pause
