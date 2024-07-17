@echo off
if not "%1"=="min" start /min cmd /c %0 min & Exit /b
python main.py
pause & exit