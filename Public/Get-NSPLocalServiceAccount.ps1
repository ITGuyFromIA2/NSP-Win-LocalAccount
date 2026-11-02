function Get-NSPLocalServiceAccount {
    <# .SYNOPSIS
        Reads one local SAM account by literal name; never resolves a similarly named domain account.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$')][string]$Name)
    # Enumerate to distinguish not-found from access/platform errors, without wildcard matching.
    $accounts=@(Get-LocalUser -ErrorAction Stop | Where-Object Name -IEQ $Name)
    if($accounts.Count -gt 1) { throw 'Local account lookup was ambiguous.' }
    if($accounts.Count) {
        $user=$accounts[0]
        [pscustomobject]@{Name=$user.Name;Account=([Environment]::MachineName+'\'+$user.Name);SID=[string]$user.SID;Enabled=[bool]$user.Enabled;PasswordExpires=$user.PasswordExpires;Description=$user.Description}
    }
}
