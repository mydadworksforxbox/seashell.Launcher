@echo off
setlocal
set "CARGO_EXE=%USERPROFILE%\.cargo\bin\cargo.exe"
if not exist "%CARGO_EXE%" set "CARGO_EXE=cargo"
"%CARGO_EXE%" test || exit /b 1
"%CARGO_EXE%" build --release || exit /b 1
echo Built target\release\SeashellPlayerLauncher.exe
