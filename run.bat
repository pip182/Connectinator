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
rem Launch without a console window. Use "run.bat debug" to keep the console for errors.
if /i "%~1"=="debug" (
    ".venv\Scripts\python.exe" -m connectinator
    set "app_exit=%ERRORLEVEL%"
    if not "%app_exit%"=="0" pause
    popd
    exit /b %app_exit%
)
start "" ".venv\Scripts\pythonw.exe" -m connectinator
popd
exit /b 0
