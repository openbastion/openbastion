# The RDP target of the Windows interop test (ADR-0071): RDP on, Network Level Authentication
# required, the certificate the test pinned, and a window to type into at each logon. Run once by
# install.bat, at the end of the installation: until it has run, the target does not present the
# pinned certificate, which is how the test knows the installation is over.
$ErrorActionPreference = 'Stop'

$password = ConvertTo-SecureString (Get-Content 'C:\OEM\rdp.pfx.pass' -Raw).Trim() -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath 'C:\OEM\rdp.pfx' -CertStoreLocation Cert:\LocalMachine\My -Password $password
Remove-Item 'C:\OEM\rdp.pfx', 'C:\OEM\rdp.pfx.pass' -Force

# Remote Desktop Services runs as NETWORK SERVICE: it must read the private key, CNG or CSP alike.
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($rsa -is [System.Security.Cryptography.RSACng]) { $key = $rsa.Key.UniqueName } else { $key = $rsa.CspKeyContainerInfo.UniqueKeyContainerName }
foreach ($path in @("$env:ProgramData\Microsoft\Crypto\Keys\$key", "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$key")) {
  if (Test-Path $path) { icacls $path /grant '*S-1-5-20:R' | Out-Null }
}

$ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
Set-CimInstance -InputObject $ts -Property @{ SSLCertificateSHA1Hash = $cert.Thumbprint }

$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty $rdp -Name fDenyTSConnections -Value 0
Set-ItemProperty "$rdp\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1   # NLA: CredSSP before any session
Set-ItemProperty "$rdp\WinStations\RDP-Tcp" -Name SecurityLayer -Value 2        # TLS
Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' | Enable-NetFirewallRule

# Something the test can type into and see: Notepad, at every logon.
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name OpenBastionNotepad -Value 'notepad.exe'

Restart-Service TermService -Force
Write-Output "rdp-setup: done, certificate $($cert.Thumbprint)"

# What Windows says about each RDP connection, for the CI (ADR-0071): every minute, the RDP logs as
# text, copied to the share dockur exports (the container's /shared, \\host.lan\Data). The share
# is a guest one, which Windows Server refuses by default: allowed for this test machine only. A
# failure here is written down and leaves the target as it is.
try {
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 1 -Type DWord
  $export = @'
$out = Join-Path $env:TEMP 'rdp-events'
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($log in 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
                 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin',
                 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
                 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin',
                 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational') {
  # As XML too: the text form drops the event data (the error codes) when a message is not rendered.
  $base = Join-Path $out ($log -replace '[/ ]', '_')
  wevtutil qe $log /c:400 /rd:true /f:text 2>&1 | Out-File "$base.txt" -Encoding utf8
  wevtutil qe $log /c:400 /rd:true /f:xml 2>&1 | Out-File "$base.xml" -Encoding utf8
}
$file = Join-Path $out 'System-rdp.txt'
wevtutil qe System "/q:*[System[Provider[@Name='TermDD' or @Name='Schannel' or @Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager']]]" /c:400 /rd:true /f:text 2>&1 | Out-File $file -Encoding utf8
foreach ($share in '\\host.lan\Data', '\\20.20.20.1\Data') {
  try { Copy-Item (Join-Path $out '*') $share -Force -ErrorAction Stop; break } catch { $_ | Out-File (Join-Path $out 'copy-error.txt') -Append }
}
'@
  Set-Content 'C:\OEM\export-rdp-events.ps1' $export
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\export-rdp-events.ps1'
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName 'OpenBastionRdpEvents' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Write-Output 'rdp-setup: RDP events exported every minute'
} catch {
  Write-Output "rdp-setup: no RDP event export: $_"
}
