function Grant-NSPLocalAccountBatchLogon {
    <# .SYNOPSIS
        Adds only SeBatchLogonRight; preserves other assignments and never removes deny rights.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name,[switch]$Execute)
    $current=Get-NSPLocalAccountRight -Name $Name
    if($current.DirectDenyBatchLogon) { throw 'Direct deny-batch-logon assignment must be reviewed; it was not removed.' }
    if($current.DirectBatchLogon) { return [pscustomobject]@{Status='AlreadyAssigned';Account=$current.Account;EffectiveAccessVerified=$false} }
    $result=[pscustomobject]@{Status='PlanOnly';Account=$current.Account;EffectiveAccessVerified=$false}
    if((Test-NSPLocalAccountApplyMode -Execute:$Execute) -and $PSCmdlet.ShouldProcess($current.Account,'Add direct batch-logon right; preserve existing policy')) {
        Invoke-NSPLocalAccountRights -SID $current.SID -Operation GrantBatch
        $verified=Get-NSPLocalAccountRight -Name $Name
        if(-not $verified.DirectBatchLogon) { throw 'Batch-logon assignment did not verify.' }
        $result.Status='Assigned'
    }
    $result
}
