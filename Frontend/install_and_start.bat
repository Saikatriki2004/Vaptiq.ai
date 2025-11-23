@echo off
echo ========================================
echo Vaptiq.ai Frontend Setup and Start
echo ========================================
echo.

cd /d "%~dp0"

echo [1/4] Checking Node installation...
node --version
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH
    pause
    exit /b 1
)
echo.

echo [2/4] Installing Node dependencies...
call npm install
if errorlevel 1 (
    echo WARNING: Some dependencies may have failed to install
    echo Continuing anyway...
)
echo.

echo [3/4] Checking if port 3000 is available...
netstat -ano | findstr :3000
if %errorlevel% == 0 (
    echo WARNING: Port 3000 is already in use
    echo Trying to start anyway...
)
echo.

echo [4/4] Starting Frontend Server...
echo Frontend will be available at: http://localhost:3000
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.

call npm run dev
pause
