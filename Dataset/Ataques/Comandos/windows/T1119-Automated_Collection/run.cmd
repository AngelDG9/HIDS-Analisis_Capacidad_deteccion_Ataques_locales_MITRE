@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0evidencias" md "%~dp0evidencias"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ATA108_ataque.ps1" >> "%~dp0evidencias\ejecucion.out" 2>&1
echo RC=%ERRORLEVEL%>> "%~dp0evidencias\ejecucion.out"
