@echo off
setlocal
pushd "%~dp0" || exit /b 1
if not exist ".venv\Scripts\python.exe" (
    echo Create the project environment first: python -m venv .venv
    pause
    popd
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install -e ".[build]"
if errorlevel 1 goto failed
".venv\Scripts\python.exe" scripts\build_exe.py
if errorlevel 1 goto failed
echo Ready: dist\Connectinator.exe
popd
exit /b 0
:failed
echo Build failed. See the error above.
pause
popd
exit /b 1
