@echo off
echo ========================================
echo Starting Vaptiq.ai Application
echo ========================================
echo.
echo This will start both Backend and Frontend
echo in separate windows.
echo.
pause

echo Starting Backend Server...
start "Vaptiq.ai Backend" cmd /k "cd /d Backend && install_and_start.bat"

timeout /t 3 /nobreak >nul

echo Starting Frontend Server...
start "Vaptiq.ai Frontend" cmd /k "cd /d Frontend && install_and_start.bat"

echo.
echo ========================================
echo Both servers are starting...
echo.
echo Backend: http://localhost:8000/docs
echo Frontend: http://localhost:3000
echo.
echo Check the opened windows for status.
echo ========================================
pause
