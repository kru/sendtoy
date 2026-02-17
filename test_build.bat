@echo off
if not defined DevEnvDir (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

mkdir build 2>NUL

echo Building Tests...
cl.exe /nologo /Zi /W4 /wd4100 /wd4996 /std:c11 /I src /I src/core src/test_main.c /Fe:build/test_sendtoy.exe

if %errorlevel% neq 0 (
    echo Build Failed with error %errorlevel%
    exit /b %errorlevel%
)

echo Build Success. Running Tests...
build\test_sendtoy.exe
