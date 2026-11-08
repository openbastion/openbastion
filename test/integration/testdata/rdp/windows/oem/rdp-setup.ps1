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

# Colour depth (ADR-0071, CI run #29): to this client, which does not advertise the graphics
# pipeline, Windows offered a 16-bpp session, which the client refuses (it decodes 32 bpp only).
# What the machine says before any change goes to the event export; then 32 bpp is allowed, by the
# RDP-Tcp setting and by the policy. A test-target choice, reversible: a default Windows may cap
# such a client at 16 bpp, and docs/security/known-limitations.md says so.
try {
  $depth = 'C:\OEM\rdp-events'
  New-Item -ItemType Directory -Force $depth | Out-Null
  & {
    'RDP-Tcp:'; Get-ItemProperty "$rdp\WinStations\RDP-Tcp" | Select-Object ColorDepth, fInheritColorDepth | Format-List | Out-String
    'Policy:'; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue | Select-Object ColorDepth | Format-List | Out-String
    'Win32_TSClientSetting:'; Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSClientSetting -Filter "TerminalName='RDP-tcp'" | Select-Object ColorDepth, ColorDepthPolicy | Format-List | Out-String
  } 2>&1 | Out-File (Join-Path $depth 'color-depth-before.txt') -Encoding utf8
  try {
    $client = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSClientSetting -Filter "TerminalName='RDP-tcp'"
    Invoke-CimMethod -InputObject $client -MethodName SetColorDepthPolicy -Arguments @{ ColorDepthPolicy = 1 } | Out-Null
    Invoke-CimMethod -InputObject $client -MethodName SetColorDepth -Arguments @{ ColorDepth = 5 } | Out-Null   # 5: 32 bpp
  } catch { "WMI: $_" | Out-File (Join-Path $depth 'color-depth-error.txt') -Append }
  $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  New-Item -Path $policy -Force | Out-Null
  Set-ItemProperty $policy -Name ColorDepth -Value 5 -Type DWord   # Limit maximum color depth: 32 bpp
  & {
    'RDP-Tcp:'; Get-ItemProperty "$rdp\WinStations\RDP-Tcp" | Select-Object ColorDepth, fInheritColorDepth | Format-List | Out-String
    'Policy:'; Get-ItemProperty $policy | Select-Object ColorDepth | Format-List | Out-String
    'Win32_TSClientSetting:'; Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSClientSetting -Filter "TerminalName='RDP-tcp'" | Select-Object ColorDepth, ColorDepthPolicy | Format-List | Out-String
  } 2>&1 | Out-File (Join-Path $depth 'color-depth-after.txt') -Encoding utf8
} catch {
  Write-Output "rdp-setup: colour depth left as it was: $_"
}

# Something the test can type into and see: Notepad, at every logon.
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name OpenBastionNotepad -Value 'notepad.exe'

Restart-Service TermService -Force
Write-Output "rdp-setup: done, certificate $($cert.Thumbprint)"

# What Windows says about each RDP connection, for the CI (ADR-0071): every 30 s, the RDP logs as
# text and XML (the text drops the event data, where the error codes are), copied to the share
# dockur exports (the container's /shared, \\host.lan\Data). A loop that sleeps, not a repeating
# trigger: the clock of the machine jumps by hours during installation, and a trigger set before
# the jump may never fire. The share is a guest one, which Windows Server refuses by default:
# allowed for this test machine only. A failure here is written down and leaves the target as it is.
try {
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name AllowInsecureGuestAuth -Value 1 -Type DWord
  $export = @'
$out = 'C:\OEM\rdp-events'
New-Item -ItemType Directory -Force $out | Out-Null
$logs = 'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational',
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin',
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
$system = "/q:*[System[Provider[@Name='TermDD' or @Name='Schannel' or @Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager']]]"
while ($true) {
  foreach ($log in $logs) {
    $base = Join-Path $out ($log -replace '[/ ]', '_')
    wevtutil qe $log /c:400 /rd:true /f:text 2>&1 | Out-File "$base.txt" -Encoding utf8
    wevtutil qe $log /c:400 /rd:true /f:xml 2>&1 | Out-File "$base.xml" -Encoding utf8
  }
  wevtutil qe System $system /c:400 /rd:true /f:text 2>&1 | Out-File (Join-Path $out 'System-rdp.txt') -Encoding utf8
  wevtutil qe System $system /c:400 /rd:true /f:xml 2>&1 | Out-File (Join-Path $out 'System-rdp.xml') -Encoding utf8
  $shares = @('\\host.lan\Data')
  $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
  if ($gateway) { $shares += "\\$gateway\Data" }
  $errors = @()
  foreach ($share in $shares) {
    try { Copy-Item (Join-Path $out '*') $share -Force -ErrorAction Stop; $errors = @(); break } catch { $errors += "$share : $_" }
  }
  "$(Get-Date -Format o) shares $($shares -join ', ') errors $($errors -join ' | ')" | Out-File (Join-Path $out 'export-status.txt') -Encoding utf8
  Start-Sleep -Seconds 30
}
'@
  Set-Content 'C:\OEM\export-rdp-events.ps1' $export
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\export-rdp-events.ps1'
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName 'OpenBastionRdpEvents' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName 'OpenBastionRdpEvents'
  Write-Output 'rdp-setup: RDP events exported every 30 s'
} catch {
  Write-Output "rdp-setup: no RDP event export: $_"
}
