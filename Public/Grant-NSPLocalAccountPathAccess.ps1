function Grant-NSPLocalAccountPathAccess {
    <#
    .SYNOPSIS
        Plans an additive allow ACE for a local account on one existing file/directory.
    .DESCRIPTION
        Preserves inheritance and existing ACLs. Does not remove broad or deny entries, follow
        a reparse-point target intentionally, or prove effective access for the task account.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$LiteralPath,[ValidateSet('Read','ReadAndExecute','Modify')][string]$Rights='Read',[switch]$Execute)
    $account=Get-NSPLocalServiceAccount -Name $Name
    if(-not $account) { throw 'The local account does not exist.' }
    $item=Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    # Reject links in every path component; grants must not be redirected by an existing junction.
    $component=$item
    while($component) {
        if($component.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point resource paths require separate review.' }
        $parent=Split-Path -Parent $component.FullName
        if(-not $parent -or $parent -eq $component.FullName) { break }
        $component=Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
    $acl=Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
    $sid=New-Object Security.Principal.SecurityIdentifier($account.SID)
    $access=[Security.AccessControl.FileSystemRights]$Rights
    $inherit=if($item.PSIsContainer) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$access,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $result=[pscustomobject]@{Status='PlanOnly';Account=$account.Account;Path=$item.FullName;Rights=$Rights;EffectiveAccessVerified=$false}
    if((Test-NSPLocalAccountApplyMode -Execute:$Execute) -and $PSCmdlet.ShouldProcess($item.FullName,"Add $Rights access for $($account.Account); preserve existing ACL")) {
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
        $result.Status='Granted'
    }
    $result
}
