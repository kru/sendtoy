@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /c /W4 /std:c11 /I src\core src\core\state.c > compile_log.txt 2>&1
