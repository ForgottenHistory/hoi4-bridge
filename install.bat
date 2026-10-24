@echo off
rem Copies build\version.dll into the HOI4 folder. Run uninstall.bat to remove it.
copy /y "%~dp0build\version.dll" "C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV\version.dll"
