# NSP.Win.LocalAccount

Local SAM service-account preparation for Windows PowerShell 5.1 and PowerShell 7 (64-bit).
Separate from AD gMSA creation. Import has no provisioning effects or required NSP dependencies.

All mutations are plan-only without `-Execute`, and support WhatIf/Confirm. New accounts are
disabled unless `-Enable` is specified; no administrator membership or password persistence.
Existing accounts are never silently reset, enabled or adopted. Password expiry policy is
unchanged unless `-PasswordNeverExpires` is explicitly requested; plan rotation for scheduled
task credentials as well as Windows passwords. Creating an account does not grant batch logon.

If NSP.Toolkit is already loaded and its DRY RUN setting is on, mutations remain plans even
with Execute. Use `Set-NSPDryRun -Enabled $false` deliberately for apply mode. This module does
not import Toolkit or install anything to check that setting.

```powershell
New-NSPLocalServiceAccount -Name svc_scan
$password = Read-Host 'Password' -AsSecureString
New-NSPLocalServiceAccount -Name svc_scan -Password $password -Enable -Execute
Grant-NSPLocalAccountBatchLogon -Name svc_scan       # plan only
Grant-NSPLocalAccountBatchLogon -Name svc_scan -Execute
Grant-NSPLocalAccountPathAccess -Name svc_scan -LiteralPath C:\Jobs\Spool -Rights Modify
Grant-NSPLocalAccountCertificateAccess -Name svc_scan -Thumbprint ('A' * 40)
```

Batch-logon uses additive LSA rights, preserving existing assignments. Direct deny-batch logon
blocks the grant. Group/MDM/GPO deny rights can still override a direct grant: the output never
claims effective task-account access. Policy changes need elevation. Run an explicit fresh
task-account check before unattended work. No rights are revoked by this module.

Resource grants preserve existing ACL/inheritance. They do not secure an otherwise broad ACL or
prove effective access; choose restricted storage first. Reparse-point paths are rejected. The
certificate helper supports an existing LocalMachine software RSA key only (CNG Microsoft
Software KSP or legacy software CAPI). It adds read access to the key file without exporting,
copying or creating keys. CurrentUser/HSM/unknown providers need separate provisioning. The
existing operator's CurrentUser certificate cannot be made a machine key with an ACL change.

`Start-NSPLocalAccountManager`, also available through `Start-NSPToolkit -Tool LocalAccounts`,
provides interactive plans and separately confirmed actions. Passwords are never toolkit answers.
Supported names use 1-20 ASCII letters/digits/dot/underscore/hyphen, starting with a letter/digit.

`tools/Test-Offline.ps1` uses synthetic accounts and fake native/ACL writes. No accounts or
rights are created by the tests. Native interop compilation is checked separately from policy
execution; real task-account, certificate-provider and policy behavior needs endpoint validation.

## Certificate setup under the run account

An alternative to a LocalMachine private-key grant is to open a CLI as the service account
with its profile loaded and perform approved CurrentUser certificate setup there:

```powershell
$credential = Get-Credential "$env:COMPUTERNAME\svc_scan"
$shell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
Start-Process -FilePath $shell -Credential $credential -LoadUserProfile
```

That shell needs its own dependency discovery and approved setup instructions. Verify whoami
before changing anything. Reuse the existing app/site grant when already provisioned: create
and register a new public certificate for that app through its approved workflow, rather than
blindly re-running app creation. Local CurrentUser records are account-specific; the shared
registration helper intentionally stops at ExistingUnrecorded when an app already exists.
Do not copy the operator's private key/DPAPI secrets, recreate identity/grants, or assume a
successful interactive shell proves batch-logon/task execution. NSP.Win.RunAs currently accepts
SYSTEM/gMSA only; the Windows credentialed CLI above is the local-account path, without
changing that helper's authentication contract.
