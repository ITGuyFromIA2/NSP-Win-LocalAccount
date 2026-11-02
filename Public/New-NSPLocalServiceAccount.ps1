function New-NSPLocalServiceAccount {
    <#
    .SYNOPSIS
        Plans a local service account; creates it only with Execute and ShouldProcess approval.
    .DESCRIPTION
        Creates disabled unless Enable is specified. No administrator membership, password reset,
        policy change or password persistence. Existing accounts are returned unchanged.
        PasswordNeverExpires is explicit; otherwise Windows password policy applies.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$')][string]$Name,
        [securestring]$Password,
        [string]$Description='NSP unattended job account',
        [switch]$Enable,
        [switch]$PasswordNeverExpires,
        [switch]$Execute
    )
    $existing=Get-NSPLocalServiceAccount -Name $Name
    if($existing) { return [pscustomobject]@{Status='AlreadyExists';Account=$existing;Changed=$false} }
    $result=[pscustomobject]@{Status='PlanOnly';Name=$Name;ComputerName=[Environment]::MachineName;Enabled=[bool]$Enable;PasswordNeverExpires=[bool]$PasswordNeverExpires;Changed=$false}
    if(-not (Test-NSPLocalAccountApplyMode -Execute:$Execute)) { return $result }
    if(-not $PSCmdlet.ShouldProcess($Name,'Create local service account without administrator membership')) { return $result }
    if(-not $Password -or $Password.Length -eq 0) { throw 'A nonempty SecureString password is required to create the account.' }
    $null=New-LocalUser -Name $Name -Password $Password -Description $Description -Disabled:(-not $Enable) -PasswordNeverExpires:$PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
    [pscustomobject]@{Status='Created';Account=(Get-NSPLocalServiceAccount -Name $Name);Changed=$true}
}
