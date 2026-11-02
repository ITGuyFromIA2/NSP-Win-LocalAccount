[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets','',Justification='Scoped offline fakes prevent any real account or ACL changes.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter','',Justification='Fakes preserve native command parameter signatures.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Fake commands mutate only in-memory test state.')]
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$module=Import-Module (Join-Path $root 'NSP.Win.LocalAccount.psd1') -Force -PassThru
try {
    & $module {
        $state=@{Checks=0;Exists=$false;Created=0;Grants=0;Rights=@();AclWrites=0}
        function Check($condition,$message) { if(-not $condition) { throw $message }; $state.Checks++ }
        function Get-NSPDryRun { [bool]$state.DryRun }
        function Reject([scriptblock]$action) { $failed=$false;try { &$action|Out-Null } catch {$failed=$true};Check $failed 'Expected rejection.' }
        function Get-LocalUser { [CmdletBinding()]param() if($state.Exists) { [pscustomobject]@{Name='svc_test';SID='S-1-5-21-100-200-300-1001';Enabled=$true;PasswordExpires=$null;Description='synthetic'} } }
        function New-LocalUser {
            [CmdletBinding()]param($Name,[securestring]$Password,$Description,[switch]$Disabled,[switch]$PasswordNeverExpires,[switch]$UserMayNotChangePassword)
            $state.Created++;$state.Exists=$true;$state.Disabled=[bool]$Disabled;$state.NeverExpires=[bool]$PasswordNeverExpires
        }
        function Invoke-NSPLocalAccountRights { param($SID,$Operation='Get') if($Operation -eq 'GrantBatch') {$state.Grants++;$state.Rights+=@('SeBatchLogonRight')} else {$state.Rights} }
        $plan=New-NSPLocalServiceAccount -Name svc_test
        Check ($plan.Status -eq 'PlanOnly' -and -not $plan.Enabled -and $state.Created -eq 0) 'Default plan created/enabled an account.'
        $null=New-NSPLocalServiceAccount -Name svc_test -Execute -WhatIf
        Check ($state.Created -eq 0) 'WhatIf created account.'
        Reject {New-NSPLocalServiceAccount -Name svc_test -Execute -Confirm:$false}
        Reject {New-NSPLocalServiceAccount -Name 'bad\name'}
        $state.DryRun=$true
        $dryPlan=New-NSPLocalServiceAccount -Name svc_test -Execute -Confirm:$false
        Check ($dryPlan.Status -eq 'PlanOnly' -and $state.Created -eq 0) 'Toolkit dry run was bypassed.'
        $state.DryRun=$false
        $password=New-Object securestring; foreach($character in 'synthetic'.ToCharArray()){$password.AppendChar($character)}
        $created=New-NSPLocalServiceAccount -Name svc_test -Password $password -Execute -Confirm:$false
        Check ($created.Status -eq 'Created' -and $state.Disabled -and -not $state.NeverExpires) 'Creation defaults changed.'
        Check ($created.PSObject.Properties.Name -notcontains 'Password') 'Password appeared in result.'
        $existing=New-NSPLocalServiceAccount -Name svc_test -Password $password -Enable -Execute -Confirm:$false
        Check ($existing.Status -eq 'AlreadyExists' -and $state.Created -eq 1) 'Existing account mutated.'
        $null=Grant-NSPLocalAccountBatchLogon -Name svc_test
        Check ($state.Grants -eq 0) 'Plan granted rights.'
        $state.DryRun=$true
        $null=Grant-NSPLocalAccountBatchLogon -Name svc_test -Execute -Confirm:$false
        Check ($state.Grants -eq 0) 'Toolkit dry run granted rights.'
        $state.DryRun=$false
        $state.Rights=@('SeDenyBatchLogonRight')
        Reject {Grant-NSPLocalAccountBatchLogon -Name svc_test -Execute -Confirm:$false}
        Check ($state.Grants -eq 0) 'Deny assignment overwritten.'
        $state.Rights=@('SyntheticOtherRight')
        $null=Grant-NSPLocalAccountBatchLogon -Name svc_test -Execute -WhatIf
        Check ($state.Grants -eq 0) 'WhatIf granted rights.'
        $grant=Grant-NSPLocalAccountBatchLogon -Name svc_test -Execute -Confirm:$false
        Check ($grant.Status -eq 'Assigned' -and 'SyntheticOtherRight' -in $state.Rights -and -not $grant.EffectiveAccessVerified) 'Rights grant lost policy or overclaimed effective access.'
        $null=Grant-NSPLocalAccountBatchLogon -Name svc_test -Execute -Confirm:$false
        Check ($state.Grants -eq 1) 'Repeated rights grant not idempotent.'
        $fixture=Join-Path ([IO.Path]::GetTempPath()) ('nsp-local-account-'+[guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($fixture)
        try {
            function Set-Acl { [CmdletBinding()]param($LiteralPath,$AclObject) $state.AclWrites++;$state.Acl=$AclObject }
            $aclPlan=Grant-NSPLocalAccountPathAccess -Name svc_test -LiteralPath $fixture -Rights Modify
            Check ($state.AclWrites -eq 0 -and $aclPlan.Status -eq 'PlanOnly') 'ACL plan wrote.'
            $null=Grant-NSPLocalAccountPathAccess -Name svc_test -LiteralPath $fixture -Rights Modify -Execute -WhatIf
            Check ($state.AclWrites -eq 0) 'ACL WhatIf wrote.'
            $null=Grant-NSPLocalAccountPathAccess -Name svc_test -LiteralPath $fixture -Rights Modify -Execute -Confirm:$false
            Check ($state.AclWrites -eq 1) 'ACL grant not forwarded.'
            $rules=@($state.Acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])|Where-Object {$_.IdentityReference.Value -eq 'S-1-5-21-100-200-300-1001'})
            Check ($rules.Count -gt 0 -and ($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify)) 'Wrong principal/rights.'
            Reject {Grant-NSPLocalAccountPathAccess -Name svc_test -LiteralPath $fixture -Rights FullControl}
        } finally { [IO.Directory]::Delete($fixture,$true) }
        function Get-Item {
            [CmdletBinding()]param($LiteralPath,[switch]$Force)
            if($LiteralPath -like 'Cert:*') { return [pscustomobject]@{HasPrivateKey=$false} }
            Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
        }
        Reject {Grant-NSPLocalAccountCertificateAccess -Name svc_test -Thumbprint ('A'*40) -Execute -Confirm:$false}
        Check ($state.AclWrites -eq 1) 'Certificate without private key reached ACL mutation.'
        # Compile interop without opening a policy handle or assigning a right.
        Initialize-NSPLocalAccountNative
        Check ([bool]('NSP.LocalAccount.NativeRights' -as [type])) 'Native bridge did not compile.'
        Write-Host ('Passed: {0} local-account offline checks in {1}; account/policy/ACL writes mocked.' -f $state.Checks,$PSVersionTable.PSVersion)
    }
} finally { Remove-Module $module.Name -Force }
