@echo off
rem Copies build\version.dll into the HOI4 folder. Run uninstall.bat to remove it.
rem Set HOI4_DIR to use a folder other than the default Steam one.
if "%HOI4_DIR%"=="" set "HOI4_DIR=C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV"
copy /y "%~dp0build\version.dll" "%HOI4_DIR%\version.dll"
