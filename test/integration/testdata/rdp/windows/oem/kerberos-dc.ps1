# The Kerberos target of ADR-0100, increment 4: this Windows made its own domain controller, so the
# KDC that issues the tickets is Microsoft's, on the same machine. Run by rdp-setup.ps1 when
# prepare.sh was given DOMAIN=kerberos: the AD DS role, then a new forest. The promotion restarts
# Windows; what needs the domain up (the test's user, the service principal, NTLM closed) is done
# by kerberos-ready.ps1, from the readiness task, after that restart.
$ErrorActionPreference = 'Stop'
$domain = (Get-Content 'C:\OEM\domain' -Raw).Trim()
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
# The Directory Services Restore Mode password: never used, made here and dropped.
$bytes = New-Object byte[] 24
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$dsrm = ConvertTo-SecureString ('Ds-' + [BitConverter]::ToString($bytes).Replace('-', '') + '-r1') -AsPlainText -Force
Write-Output "kerberos-dc: promoting to the forest $domain"
Install-ADDSForest -DomainName $domain -DomainNetbiosName 'OPENBASTION' -InstallDns -SafeModeAdministratorPassword $dsrm `
  -NoRebootOnCompletion:$false -Force | Out-Null
