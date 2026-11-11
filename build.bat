@echo off
rem Builds build\version.dll from src\%1.cpp (default: probe)
setlocal
set SRC=%~1
if "%SRC%"=="" set SRC=probe
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
rem MinHook is downloaded on first build
if not exist deps\minhook\lib\libMinHook.x64.lib (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deps\fetch_minhook.ps1" || exit /b 1
)
if not exist build mkdir build
cl /nologo /O2 /MT /LD /EHsc /std:c++17 /W3 /I deps\minhook\include src\%SRC%.cpp ^
   /Fo:build\ /Fe:build\version.dll /link deps\minhook\lib\libMinHook.x64.lib
