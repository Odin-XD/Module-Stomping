@echo off
setlocal enabledelayedexpansion
where msbuild >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist "!MSBUILD!" set "MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist "!MSBUILD!" (
echo MSBuild not found
pause
exit /b 1
)
) else (
set "MSBUILD=msbuild"
)
"!MSBUILD!" ModuleStomper.sln /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /m
if %ERRORLEVEL% NEQ 0 (
echo BUILD FAILED
pause
exit /b 1
)
copy /Y x64\Release\ModuleStomper.exe ModuleStomper.exe >nul
echo BUILD SUCCESS
pause
