# Downloads MinHook 1.3.4 (BSD-2-Clause, see deps/minhook/LICENSE.txt) into deps/minhook/include and lib.
# Run by build.bat when the files are missing.
$ErrorActionPreference = 'Stop'
$dest = Join-Path $PSScriptRoot 'minhook'
$url  = 'https://github.com/TsudaKageyu/minhook/releases/download/v1.3.4/MinHook_134_lib.zip'
$sha  = '8dba3053104942b72208330395f9107910d306eb89263b3f2b3d0747a40c92ac'
$zip  = Join-Path ([IO.Path]::GetTempPath()) 'MinHook_134_lib.zip'
$tmp  = Join-Path ([IO.Path]::GetTempPath()) 'MinHook_134_lib'
Invoke-WebRequest $url -OutFile $zip
if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne $sha) { throw 'MinHook download hash mismatch' }
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
Expand-Archive $zip $tmp
New-Item -ItemType Directory -Force "$dest\include", "$dest\lib" | Out-Null
Copy-Item "$tmp\include\MinHook.h" "$dest\include\" -Force
Copy-Item "$tmp\lib\libMinHook.x64.lib" "$dest\lib\" -Force
Remove-Item $zip, $tmp -Recurse -Force
Write-Host 'MinHook 1.3.4 installed in' $dest
