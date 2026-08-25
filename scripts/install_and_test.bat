@echo off
REM ============================================================
REM  GlobalShutdownHook - Install & Test Script (run inside VM)
REM
REM  Run as Administrator.
REM  Prerequisite: testsigning must be ON (bcdedit /set testsigning on)
REM ============================================================

setlocal

set DRIVER_NAME=GlobalShutdownHook
set DRIVER_PATH=%~dp0GlobalShutdownHook.sys
set CLIENT_PATH=%~dp0ShutdownHookClient.exe

echo.
echo ========================================
echo   GlobalShutdownHook - Install & Test
echo ========================================
echo.

REM ---- Check admin ----
net session >nul 2>&1
if errorlevel 1 (
    echo ERROR: This script must be run as Administrator.
    pause
    exit /b 1
)

REM ---- Check testsigning ----
for /f "tokens=2 delims=:" %%a in ('bcdedit /enum ^| findstr /i "testsigning"') do (
    set TS_VALUE=%%a
)
echo %TS_VALUE% | findstr /i "Yes" >nul
if errorlevel 1 (
    echo WARNING: testsigning appears to be OFF.
    echo The driver will fail to load unless it has a valid signature.
    echo Enable with: bcdedit /set testsigning on  (then reboot)
    echo.
    set /p CONTINUE="Continue anyway? (y/n): "
    if /i not "!CONTINUE!"=="y" exit /b 1
)

REM ---- Check driver file ----
if not exist "%DRIVER_PATH%" (
    echo ERROR: Driver not found at %DRIVER_PATH%
    echo Please build the project and copy GlobalShutdownHook.sys here.
    pause
    exit /b 1
)

REM ---- Stop existing service ----
sc query %DRIVER_NAME% >nul 2>&1
if not errorlevel 1 (
    echo Stopping existing service...
    sc stop %DRIVER_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
    sc delete %DRIVER_NAME% >nul 2>&1
)

REM ---- Create and start service ----
echo Creating service %DRIVER_NAME%...
sc create %DRIVER_NAME% type= kernel binPath= "%DRIVER_PATH%" >nul
if errorlevel 1 (
    echo ERROR: Failed to create service.
    pause
    exit /b 1
)

echo Starting driver...
sc start %DRIVER_NAME%
if errorlevel 1 (
    echo.
    echo ERROR: Failed to start driver.
    echo Check Event Viewer -^> Windows Logs -^> System for details.
    echo Common causes:
    echo   - testsigning is off
    echo   - driver built for wrong architecture
    echo   - missing WDK runtime
    sc delete %DRIVER_NAME% >nul 2>&1
    pause
    exit /b 1
)

echo.
echo Driver started successfully.
echo.

REM ---- Wait for worker thread to process initial enqueue ----
echo Waiting 3 seconds for initial hook processing...
timeout /t 3 /nobreak >nul

REM ---- Run client status ----
if exist "%CLIENT_PATH%" (
    echo.
    echo === Driver Status ===
    "%CLIENT_PATH%" status
    echo.
    echo === Hook List (first 30 lines) ===
    "%CLIENT_PATH%" list
    echo.
    echo === Failure Log ===
    "%CLIENT_PATH%" failures
) else (
    echo (Client exe not found, skipping status display)
)

echo.
echo ========================================
echo   Installation complete.
echo
echo   Useful commands:
echo     %CLIENT_PATH% status
echo     %CLIENT_PATH% list
echo     %CLIENT_PATH% failures
echo     %CLIENT_PATH% test        (test ExitWindowsEx interception)
echo     %CLIENT_PATH% monitor     (live monitoring)
echo
echo   To stop:   sc stop %DRIVER_NAME%
echo   To remove: sc delete %DRIVER_NAME%
echo ========================================
echo.

endlocal
pause
