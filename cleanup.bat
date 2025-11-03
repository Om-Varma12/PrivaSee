@echo off
echo Cleaning up Python cache files...

REM Remove __pycache__ directories
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"

REM Remove .pyc files
del /s /q *.pyc 2>nul

REM Remove .pyo files
del /s /q *.pyo 2>nul

echo Done! Python cache files removed.
echo Now you can load the extension in Chrome.
pause