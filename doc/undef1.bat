@echo off
%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
cd /d "%~dp0"
setlocal enabledelayedexpansion
set  gw=192.168.40.1
set  connect=150.95.137.46
echo !connect!
echo !gw!
route delete 0.0.0.0 mask 0.0.0.0 10.0.0.1 METRIC 1
route delete !connect! mask 255.255.255.255 !gw!
pause