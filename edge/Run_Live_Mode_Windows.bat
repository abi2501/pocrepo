@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 -m app.cli gui
) else (
    python -m app.cli gui
)
if errorlevel 1 pause
