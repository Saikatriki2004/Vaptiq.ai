@echo off
echo ========================================
echo Vaptiq.ai Backend Setup and Start
echo ========================================
echo.

cd /d "%~dp0"

echo [1/4] Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)
echo.

echo [2/4] Installing Python dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo WARNING: Some dependencies may have failed to install
    echo Continuing anyway...
)
echo.

echo [3/4] Checking if port 8000 is available...
netstat -ano | findstr :8000
if %errorlevel% == 0 (
    echo WARNING: Port 8000 is already in use
    echo Trying to start anyway...
)
echo.

echo [4/4] Starting Backend Server...
echo Server will be available at: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
pause
