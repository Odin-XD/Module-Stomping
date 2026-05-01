@echo off
setlocal enabledelayedexpansion
echo ========================================
echo   Module Stomper Build Script
echo   Building with MSBuild (Visual Studio)
echo ========================================
echo.

REM Check if MSBuild is available
where msbuild >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] MSBuild not found in PATH
    echo [*] Searching for Visual Studio installations...
    goto :FindVS
) else (
    echo [+] MSBuild found in PATH
    goto :Build
)

:FindVS
REM Try common Visual Studio paths
set "VS2022=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set "VS2019=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
set "VS2017=C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\MSBuild.exe"

if exist "%VS2022%" (
    echo [+] Found Visual Studio 2022
    set "MSBUILD=%VS2022%"
    goto :Build
)

if exist "%VS2019%" (
    echo [+] Found Visual Studio 2019
    set "MSBUILD=%VS2019%"
    goto :Build
)

if exist "%VS2017%" (
    echo [+] Found Visual Studio 2017
    set "MSBUILD=%VS2017%"
    goto :Build
)

REM Try using vswhere to find VS installation
if exist "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" (
    echo [*] Using vswhere to locate Visual Studio...
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        set "MSBUILD=%%i"
        echo [+] Found MSBuild at: %%i
        goto :Build
    )
)

echo [!] ERROR: Could not find MSBuild or Visual Studio installation
echo [*] Please install Visual Studio 2017 or later with C++ build tools
echo [*] Or add MSBuild to your PATH
pause
exit /b 1

:Build
echo.
echo ========================================
echo   Building Module Stomper
echo ========================================
echo.

REM Set solution path
set "SOLUTION=ModuleStomper.sln"

if not exist "%SOLUTION%" (
    echo [!] ERROR: Solution file not found: %SOLUTION%
    echo [*] Make sure you're running this from the ModuleStomper directory
    pause
    exit /b 1
)

echo [*] Solution: %SOLUTION%
echo [*] Configuration: Release
echo [*] Platform: x64
echo.

REM Detect Visual Studio version and set platform toolset
echo [*] Detecting Visual Studio version...
if defined MSBUILD (
    echo %MSBUILD% | findstr "2022" >nul
    if !ERRORLEVEL! EQU 0 (
        set "TOOLSET=v143"
        echo [+] Using Visual Studio 2022 toolset (v143)
        goto :StartBuild
    )
    echo %MSBUILD% | findstr "2019" >nul
    if !ERRORLEVEL! EQU 0 (
        set "TOOLSET=v142"
        echo [+] Using Visual Studio 2019 toolset (v142)
        goto :StartBuild
    )
    set "TOOLSET=v141"
    echo [+] Using Visual Studio 2017 toolset (v141)
    goto :StartBuild
) else (
    REM Default to v143 if using system MSBuild
    set "TOOLSET=v143"
    echo [+] Using default toolset (v143)
)

:StartBuild

REM Clean previous build
echo [*] Cleaning previous build...
if defined MSBUILD (
    "%MSBUILD%" "%SOLUTION%" /t:Clean /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%TOOLSET% /v:minimal
) else (
    msbuild "%SOLUTION%" /t:Clean /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%TOOLSET% /v:minimal
)

echo.
echo [*] Building Release x64 with toolset %TOOLSET%...
if defined MSBUILD (
    "%MSBUILD%" "%SOLUTION%" /t:Build /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%TOOLSET% /v:minimal /m
) else (
    msbuild "%SOLUTION%" /t:Build /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=%TOOLSET% /v:minimal /m
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] BUILD FAILED
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Build Successful!
echo ========================================
echo.

REM Find the output executable
set "OUTPUT=x64\Release\ModuleStomper.exe"
if exist "%OUTPUT%" (
    echo [+] Executable: %OUTPUT%
    echo [+] Size: 
    dir "%OUTPUT%" | findstr "ModuleStomper.exe"
    echo.
    echo [*] Copying to root directory...
    copy /Y "%OUTPUT%" "ModuleStomper.exe" >nul
    if exist "ModuleStomper.exe" (
        echo [+] Copied to: ModuleStomper.exe
    )
) else (
    echo [!] Warning: Could not find output executable at expected location
    echo [*] Check x64\Release\ or Release\
)

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo [*] To run: ModuleStomper.exe
echo.
pause
