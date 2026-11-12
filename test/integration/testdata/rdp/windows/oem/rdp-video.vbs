' Starts rdp-video.ps1 with no window (0) and without waiting (False): see rdp-setup.ps1's Run entry.
CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\rdp-video.ps1", 0, False
