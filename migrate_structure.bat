@echo off
echo ==========================================
echo      Vaptiq.ai Folder Migration
echo ==========================================
echo.
echo This script will complete the restructuring by:
echo 1. Creating Frontend and Backend directories
echo 2. Moving apps\web to Frontend
echo 3. Moving apps\engine to Backend
echo 4. Removing the apps directory
echo.
pause

echo.
echo Moving Web to Frontend...
mkdir Frontend 2>nul
robocopy apps\web Frontend /E /MOVE /IS /IT

echo.
echo Moving Engine to Backend...
mkdir Backend 2>nul
robocopy apps\engine Backend /E /MOVE /IS /IT

echo.
echo Cleaning up apps directory...
rmdir apps /S /Q

echo.
echo ==========================================
echo           Migration Complete!
echo ==========================================
echo.
pause
