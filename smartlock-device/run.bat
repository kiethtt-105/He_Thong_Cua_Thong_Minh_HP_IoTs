@echo off
cd /d "%~dp0firmware"
if not exist device.conf python -m smartlock_fw init
python -m smartlock_fw run
