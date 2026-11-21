# The licensing target of ADR-0099, increment 2: this Windows made a Remote Desktop Session Host
# with its own Remote Desktop license server, so that it leads the whole licensing exchange of
# MS-RDPELE (platform challenge, a license issued, the license presented again). Run by
# rdp-setup.ps1, last, when prepare.sh was given ROLE=rdsh: the roles' installation restarts
# Windows; rdsh-ready.ps1 says, after that restart, how licensing is set.
$ErrorActionPreference = 'Stop'
Write-Output 'rdsh-setup: the session host and license server roles'
Install-WindowsFeature RDS-RD-Server, RDS-Licensing -IncludeManagementTools | Out-Null
# Licensing by policy (Computer Configuration > Administrative Templates > Remote Desktop
# Services > Licensing): the license server is this machine. The mode is per device here, a test
# machine of one run: it is the mode in which a host issues a license to the client and asks for it
# back at the next connection, which is the exchange this target is for. A deployment uses per user
# (ADR-0099, docs/administration/privileged-accounts.md).
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
New-Item -Path $policy -Force | Out-Null
New-ItemProperty $policy -Name LicensingMode -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty $policy -Name LicenseServers -Value $env:COMPUTERNAME -PropertyType String -Force | Out-Null
Write-Output 'rdsh-setup: restarting'
Restart-Computer -Force
