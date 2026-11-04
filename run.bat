@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist ".venv\Scripts\python.exe" (
    echo Project virtual environment not found.
    echo Run these commands in the project folder first:
    echo   python -m venv .venv
    echo   .venv\Scripts\python.exe -m pip install -e .
    pause
    popd
    exit /b 1
)
".venv\Scripts\python.exe" -m connectinator
set "app_exit=%ERRORLEVEL%"
if not "%app_exit%"=="0" pause
popd
exit /b %app_exit%
