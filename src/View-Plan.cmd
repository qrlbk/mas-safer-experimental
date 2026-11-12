@echo off
setlocal EnableExtensions DisableDelayedExpansion
call "%~dp0MAS\All-In-One-Version-KL\MAS_AIO.cmd" /Plan "%~1"
set "plan_result=%errorlevel%"
echo.
echo Plan view finished. No activation follows.
pause
exit /b %plan_result%
