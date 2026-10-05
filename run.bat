@echo off
cd /d "%~dp0"
if not exist "bin\Release\net10.0-windows\tlk-hex.exe" (
    echo tlk-hex derleniyor...
    dotnet build -c Release
)
start "" "bin\Release\net10.0-windows\tlk-hex.exe" %*
