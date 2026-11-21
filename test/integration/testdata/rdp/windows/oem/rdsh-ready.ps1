# After the roles' restart (rdsh-setup.ps1), from the readiness task, as SYSTEM, before the pinned
# certificate is installed (ADR-0099, increment 2): how this host licenses, for the CI's record.
$log = 'C:\OEM\rdsh-ready.log'
for ($i = 0; $i -lt 60; $i++) {
  if ((Get-Service TermServLicensing -ErrorAction SilentlyContinue).Status -eq 'Running') { break }
  Start-Sleep -Seconds 5
}
"license server: $((Get-Service TermServLicensing -ErrorAction SilentlyContinue).Status) at $(Get-Date -Format o)" | Out-File $log -Encoding utf8
try {
  $ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TerminalServiceSetting
  "licensing type $($ts.LicensingType) ($($ts.LicensingName)), grace period days $((Invoke-CimMethod -InputObject $ts -MethodName GetGracePeriodDays).DaysLeft)" | Out-File $log -Append -Encoding utf8
} catch {
  "licensing settings unreadable: $_" | Out-File $log -Append -Encoding utf8
}
New-Item -ItemType Directory -Force 'C:\OEM\rdp-events' | Out-Null
Copy-Item $log 'C:\OEM\rdp-events\rdsh-ready.log' -Force -ErrorAction SilentlyContinue
# Once: a later restart of this machine does not run the readiness task again.
Unregister-ScheduledTask -TaskName 'OpenBastionRdpReady' -Confirm:$false
