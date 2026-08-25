@echo off
REM ============================================================
REM  GlobalShutdownHook - Build Script
REM
REM  Usage:
REM    Open "x64 Native Tools Command Prompt for VS 2022"
REM    (or any VS Developer Prompt with WDK installed)
REM    Then run: build.bat [Debug|Release]
REM
REM  Prerequisites:
REM    - Visual Studio 2022 (17.x) with C++ workload
REM    - Windows Driver Kit (WDK) 10.0.22621+ or matching SDK
REM    - MSBuild in PATH (Developer Prompt sets this up)
REM ============================================================

setlocal enabledelayedexpansion

set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release

set PLATFORM=x64
set SOLUTION=%~dp0..\GlobalShutdownHook.sln

echo.
echo ========================================
echo   Building GlobalShutdownHook
echo   Configuration: %CONFIG%
echo   Platform:      %PLATFORM%
echo ========================================
echo.

where msbuild >nul 2>&1
if errorlevel 1 (
    echo ERROR: MSBuild not found in PATH.
    echo Please run this script from a Visual Studio Developer Command Prompt.
    exit /b 1
)

msbuild "%SOLUTION%" /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% /m /v:minimal

if errorlevel 1 (
    echo.
    echo BUILD FAILED.
    exit /b 1
)

echo.
echo ========================================
echo   Build succeeded.
echo   Output: %~dp0..\bin\%PLATFORM%\%CONFIG%\
echo ========================================
echo.

dir /b "%~dp0..\bin\%PLATFORM%\%CONFIG%\" 2>nul

endlocal
