@echo off
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
) else (
    echo "ERROR: vcvarsall.bat not found at expected location."
    exit /b 1
)

cl nob.c && nob.exe
