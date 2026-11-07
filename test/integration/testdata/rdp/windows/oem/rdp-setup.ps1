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
