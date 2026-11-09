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


$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty $rdp -Name fDenyTSConnections -Value 0
Set-ItemProperty "$rdp\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1   # NLA: CredSSP before any session
Set-ItemProperty "$rdp\WinStations\RDP-Tcp" -Name SecurityLayer -Value 2        # TLS
Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' | Enable-NetFirewallRule

# Colour depth (ADR-0086): left as Windows installs it, unless prepare.sh was given 32. To a client without the graphics pipeline,
# this Windows offers 16 bpp (RDP-Tcp\ColorDepth 3, fInheritColorDepth 0, measured in CI runs #29
# and #30), which the client decodes: the test runs the real case. What the machine says goes to
# the event export, as evidence of the depth the run was made at.
try {
  $depth = 'C:\OEM\rdp-events'
  New-Item -ItemType Directory -Force $depth | Out-Null
  & {
    'RDP-Tcp:'; Get-ItemProperty "$rdp\WinStations\RDP-Tcp" | Select-Object ColorDepth, fInheritColorDepth | Format-List | Out-String
    'Policy:'; Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue | Select-Object ColorDepth | Format-List | Out-String
    'Win32_TSClientSetting:'; Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSClientSetting -Filter "TerminalName='RDP-tcp'" | Select-Object ColorDepth, ColorDepthPolicy | Format-List | Out-String
  } 2>&1 | Out-File (Join-Path $depth 'color-depth.txt') -Encoding utf8
  # prepare.sh DIR 32: 32 bpp allowed by the policy "Limit maximum color depth", which alone was
  # enough in CI run #30 (the WMI method SetColorDepthPolicy is refused there).
  if ((Get-Content 'C:\OEM\color-depth' -Raw -ErrorAction SilentlyContinue) -eq '32') {
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    New-Item -Path $policy -Force | Out-Null
    Set-ItemProperty $policy -Name ColorDepth -Value 5 -Type DWord   # 5: 32 bpp
    "Policy set to 32 bpp" | Out-File (Join-Path $depth 'color-depth.txt') -Append -Encoding utf8
  }
} catch {
  Write-Output "rdp-setup: colour depth not recorded: $_"
}

# The user's keyboard layout (prepare.sh KEYBOARD, ADR-0088): the operator sends physical keys,
# which the target reads with this layout. This script runs in the user's first session, where
# Set-WinUserLanguageList applies. What the machine ends up with goes to the event export.
try {
  $keyboard = (Get-Content 'C:\OEM\keyboard' -Raw -ErrorAction SilentlyContinue)
  if ($keyboard -eq 'fr-FR') {
    Set-WinUserLanguageList -LanguageList fr-FR -Force
  }
  New-Item -ItemType Directory -Force 'C:\OEM\rdp-events' | Out-Null
  "asked: $keyboard" | Out-File 'C:\OEM\rdp-events\keyboard.txt' -Encoding utf8
  Get-WinUserLanguageList | Format-List | Out-String | Out-File 'C:\OEM\rdp-events\keyboard.txt' -Append -Encoding utf8
} catch {
  Write-Output "rdp-setup: keyboard layout not set: $_"
}

# Something the test can type into and see: Notepad, at every logon.
Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name OpenBastionNotepad -Value 'notepad.exe'

# Ready, in a known state (ADR-0071, CI runs #39 to #42): dockur logs the user on at the console to
# run this script, and a test that came while that session was there found Windows' logon screen in
# some runs and the desktop in others. A server's common case is no interactive session: a task
# running as SYSTEM, once this script is over, logs every session off, turns dockur's autologon
# off, and only then installs the pinned certificate and restarts Remote Desktop Services. The
# certificate is the test's sign that the target is ready: when it comes, no session is open.
# prepare.sh DIR DEPTH console keeps that session, to validate taking it over by RDP.
$ready = @"
Start-Sleep -Seconds 20
`$ids = @()
if ((Get-Content 'C:\OEM\session' -Raw -ErrorAction SilentlyContinue) -ne 'console') {
  Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value '0'
  `$ids = (query session) -split "``n" | ForEach-Object { if (`$_ -match '\s(\d+)\s+(Active|Disc|Conn)') { [int]`$Matches[1] } } | Where-Object { `$_ -ge 1 -and `$_ -lt 65536 }
  foreach (`$id in `$ids) { logoff `$id }
}
(query session) 2>&1 | Out-File 'C:\OEM\rdp-sessions.log' -Encoding utf8
Start-Sleep -Seconds 10
`$ts = Get-CimInstance -Namespace root\cimv2\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'"
Set-CimInstance -InputObject `$ts -Property @{ SSLCertificateSHA1Hash = '$($cert.Thumbprint)' }
Restart-Service TermService -Force
"logged off: `$(`$ids -join ', ')" | Out-File 'C:\OEM\rdp-ready.log' -Encoding utf8
"@
Set-Content 'C:\OEM\rdp-ready.ps1' $ready
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\OEM\rdp-ready.ps1'
Register-ScheduledTask -TaskName 'OpenBastionRdpReady' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'OpenBastionRdpReady'
Write-Output "rdp-setup: done; certificate $($cert.Thumbprint) once every session is logged off"

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
  # What the keyboard test saved from Notepad (ADR-0088): the text the target read from the keys.
  # Where Notepad saves depends on how it was started (PR #97: not in Documents), so the file is
  # looked for, and where it was found is written down.
  $kbd = @(Get-ChildItem 'C:\Users' -Filter 'kbd.txt' -Recurse -Depth 8 -Force -ErrorAction SilentlyContinue) +
         @(Get-Item 'C:\Windows\System32\kbd.txt', 'C:\Windows\kbd.txt', 'C:\kbd.txt' -ErrorAction SilentlyContinue)
  if ($kbd.Count -gt 0) {
    Copy-Item $kbd[0].FullName (Join-Path $out 'kbd.txt') -Force -ErrorAction SilentlyContinue
    $kbd.FullName -join "`n" | Out-File (Join-Path $out 'kbd-where.txt') -Encoding utf8
  }
  $shares = @('\\host.lan\Data')
  $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
  if ($gateway) { $shares += "\\$gateway\Data" }
  $errors = @()
  foreach ($share in $shares) {
    try { Copy-Item (Join-Path $out '*') $share -Force -ErrorAction Stop; $errors = @(); break } catch { $errors += "$share : $_" }
  }
  "$(Get-Date -Format o) shares $($shares -join ', ') errors $($errors -join ' | ')" | Out-File (Join-Path $out 'export-status.txt') -Encoding utf8
  # The logoff test (ADR-0071 §3, "Fin"): the runner asks by a file on the share, and Windows itself
  # logs the user's sessions off; no key is needed (the Windows key did not reach the shell, PR #101).
  foreach ($share in $shares) {
    if (Test-Path (Join-Path $share 'logoff-request') -ErrorAction SilentlyContinue) {
      $ids = (query session) -split "`n" | ForEach-Object { if ($_ -match '\s(\d+)\s+(Active|Disc)') { [int]$Matches[1] } } | Where-Object { $_ -ge 1 -and $_ -lt 65536 }
      foreach ($id in $ids) { logoff $id }
      Remove-Item (Join-Path $share 'logoff-request') -Force -ErrorAction SilentlyContinue
      "$(Get-Date -Format o) logged off: $($ids -join ', ')" | Out-File (Join-Path $out 'logoff-done.txt') -Encoding utf8
      break
    }
  }
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
