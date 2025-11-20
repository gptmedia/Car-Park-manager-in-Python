@echo off
echo ========================================
echo Building CarParkManager.exe...
echo ========================================
echo.
echo This will take 1-2 minutes. Please wait...
echo.

python -m PyInstaller --clean --noconfirm CarParkManager.spec

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build completed!
    echo ========================================
    echo.
    if exist "dist\CarParkManager.exe" (
        echo SUCCESS: CarParkManager.exe created in dist folder
        echo.
        dir dist\CarParkManager.exe
    ) else (
        echo ERROR: CarParkManager.exe was not created
    )
) else (
    echo.
    echo ========================================
    echo Build failed with error code: %ERRORLEVEL%
    echo ========================================
)

echo.
pause

