function Start-NSPLocalAccountManager {
    <# .SYNOPSIS
        Interactive local-account preparation; each mutation is separately selected and confirmed.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Menu delegates mutations to Execute-gated ShouldProcess-enabled commands.')]
    [CmdletBinding()]
    param()
    while($true) {
        Write-Host "`nLocal service accounts on $([Environment]::MachineName)" -ForegroundColor Cyan
        Write-Host '1 Inspect account  2 Plan creation  3 Create account  4 Batch-logon rights  5 Folder/file access  6 Certificate-key access  Q Back'
        $choice=Read-Host 'Select'
        if($choice -in @('q','Q','')) { return }
        if($choice -notin @('1','2','3','4','5','6')) { continue }
        $name=Read-Host 'Local account name (without computer/domain prefix)'
        try {
            switch($choice) {
                '1' { Get-NSPLocalServiceAccount -Name $name | Format-List }
                '2' { New-NSPLocalServiceAccount -Name $name | Format-List }
                '3' {
                    $password=Read-Host 'Password (not saved by this tool)' -AsSecureString
                    try { New-NSPLocalServiceAccount -Name $name -Password $password -Enable -Execute -Confirm | Format-List }
                    finally { if($password) { $password.Dispose() }; $password=$null }
                }
                '4' {
                    Grant-NSPLocalAccountBatchLogon -Name $name | Format-List
                    if((Read-Host 'Apply this additive grant? Type APPLY') -ceq 'APPLY') { Grant-NSPLocalAccountBatchLogon -Name $name -Execute -Confirm | Format-List }
                }
                '5' {
                    $path=Read-Host 'Existing resource path'
                    $rights=Read-Host 'Rights: Read, ReadAndExecute or Modify'
                    Grant-NSPLocalAccountPathAccess -Name $name -LiteralPath $path -Rights $rights | Format-List
                    if((Read-Host 'Apply this additive grant? Type APPLY') -ceq 'APPLY') { Grant-NSPLocalAccountPathAccess -Name $name -LiteralPath $path -Rights $rights -Execute -Confirm | Format-List }
                }
                '6' {
                    $thumbprint=Read-Host 'Existing LocalMachine certificate thumbprint'
                    Grant-NSPLocalAccountCertificateAccess -Name $name -Thumbprint $thumbprint | Format-List
                    if((Read-Host 'Apply this additive grant? Type APPLY') -ceq 'APPLY') { Grant-NSPLocalAccountCertificateAccess -Name $name -Thumbprint $thumbprint -Execute -Confirm | Format-List }
                }
            }
        } catch { Write-Warning $_.Exception.Message }
    }
}
