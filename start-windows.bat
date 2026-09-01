@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_COMMAND="
set "PYTHON_DETECTED="

where /q py
if errorlevel 1 goto :try_python
set "PYTHON_DETECTED=1"
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 set "PYTHON_COMMAND=py -3"

:try_python
if defined PYTHON_COMMAND goto :run
where /q python
if errorlevel 1 goto :python_check
set "PYTHON_DETECTED=1"
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 set "PYTHON_COMMAND=python"

:python_check
if defined PYTHON_COMMAND goto :run
if defined PYTHON_DETECTED goto :python_too_old
goto :python_missing

:run
where /q go
if errorlevel 1 goto :go_missing
%PYTHON_COMMAND% rr_optimizer.py ui %*
goto :end

:go_missing
echo.
echo [RR Edge Hunter] 源码运行需要 Go 1.22 或更高版本。
echo 正式便携版已内置参考程序，不需要安装 Go。
echo.
pause
goto :end

:python_missing
echo.
echo [RR Edge Hunter] 未找到 Python 3。
echo 请先从 https://www.python.org/downloads/ 安装 Python 3.11 或更高版本。
echo 安装时请勾选 Add Python to PATH。
echo.
pause
goto :end

:python_too_old
echo.
echo [RR Edge Hunter] 检测到的 Python 版本低于 3.11。
echo 请安装 Python 3.11 或更高版本后重试。
echo.
pause

:end
endlocal
