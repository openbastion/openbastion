@echo off
rem Run by dockur/windows at the last step of the unattended installation (ADR-0071).
powershell -NoProfile -ExecutionPolicy Bypass -File C:\OEM\rdp-setup.ps1 > C:\OEM\rdp-setup.log 2>&1
