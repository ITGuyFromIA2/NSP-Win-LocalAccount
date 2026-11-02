function Get-NSPLocalAccountRight {
    <# .SYNOPSIS
        Reads rights assigned directly to a local account; does not compute group/GPO effective rights.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $account=Get-NSPLocalServiceAccount -Name $Name
    if(-not $account) { throw 'The local account does not exist.' }
    $rights=@(Invoke-NSPLocalAccountRights -SID $account.SID)
    [pscustomobject]@{Account=$account.Account;SID=$account.SID;DirectRights=$rights;DirectBatchLogon=('SeBatchLogonRight' -in $rights);DirectDenyBatchLogon=('SeDenyBatchLogonRight' -in $rights);EffectiveAccessVerified=$false}
}
