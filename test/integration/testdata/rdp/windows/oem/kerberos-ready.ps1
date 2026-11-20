# After the promotion's restart (kerberos-dc.ps1), from the readiness task, as SYSTEM, before the
# pinned certificate is installed (ADR-0100, increment 4): the certificate is the test's sign that
# all of this is done.
#   - a user of the domain for the test, with its AES keys (an account carried over from the local
#     database at the promotion has only its NT hash, and the client asks for AES alone);
#   - TERMSRV/<the pinned name>, the service principal the proxy asks a ticket for, on this machine;
#   - incoming NTLM refused, as in a domain that has closed it: what ADR-0100 is for.
$log = 'C:\OEM\kerberos-ready.log'
for ($i = 0; $i -lt 90; $i++) {
  try { Get-ADDomain | Out-Null; break } catch { Start-Sleep -Seconds 10 }
}
"domain: $((Get-ADDomain).DNSRoot) at $(Get-Date -Format o)" | Out-File $log -Encoding utf8
if (Test-Path 'C:\OEM\kerberos.pass') {
  $password = ConvertTo-SecureString (Get-Content 'C:\OEM\kerberos.pass' -Raw).Trim() -AsPlainText -Force
  New-ADUser -Name 'krbop' -SamAccountName 'krbop' -UserPrincipalName "krbop@$((Get-ADDomain).DNSRoot)" -AccountPassword $password `
    -Enabled $true -PasswordNeverExpires $true -KerberosEncryptionType AES128, AES256
  # On a domain controller, Remote Desktop logon is for Administrators.
  Add-ADGroupMember -Identity 'Administrators' -Members 'krbop'
  Remove-Item 'C:\OEM\kerberos.pass' -Force
  "user krbop made" | Out-File $log -Append -Encoding utf8
}
$name = (Get-Content 'C:\OEM\server-name' -Raw).Trim()
setspn -S "TERMSRV/$name" $env:COMPUTERNAME 2>&1 | Out-File $log -Append -Encoding utf8
New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name RestrictReceivingNTLMTraffic -Value 2 -PropertyType DWord -Force | Out-Null
"incoming NTLM refused (RestrictReceivingNTLMTraffic 2)" | Out-File $log -Append -Encoding utf8
setspn -L $env:COMPUTERNAME 2>&1 | Out-File $log -Append -Encoding utf8
Copy-Item $log 'C:\OEM\rdp-events\kerberos-ready.log' -Force -ErrorAction SilentlyContinue
# Once: a later restart of this machine does not run the readiness task again.
Unregister-ScheduledTask -TaskName 'OpenBastionRdpReady' -Confirm:$false
