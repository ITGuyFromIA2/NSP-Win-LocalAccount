function Test-NSPLocalAccountApplyMode {
    param([switch]$Execute)
    if(-not $Execute){return $false}
    # Optional coordination with an already loaded toolkit; never import/install it here.
    if(Get-Command Get-NSPDryRun -ErrorAction SilentlyContinue) {
        if(Get-NSPDryRun){Write-Verbose 'Toolkit DRY RUN remains active; returning a plan.';return $false}
    }
    return $true
}
