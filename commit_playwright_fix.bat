@echo off
echo Committing Playwright config fix...
git add Frontend/playwright.config.ts
git commit -m "fix: resolve Playwright reporter type error"
echo.
echo Pushing to GitHub...
git push origin main
echo.
echo Done!
