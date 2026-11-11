@echo off
rem Removes the bridge from the HOI4 folder. Set HOI4_DIR to use a folder other than the default Steam one.
if "%HOI4_DIR%"=="" set "HOI4_DIR=C:\Program Files (x86)\Steam\steamapps\common\Hearts of Iron IV"
del "%HOI4_DIR%\version.dll"
del "%HOI4_DIR%\version.old.dll" 2>nul
