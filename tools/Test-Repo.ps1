$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$failures=@(foreach($file in (Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object Extension -In @('.ps1','.psm1','.psd1'))) {
    $errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$null,[ref]$errors)
    foreach($entry in $errors) { '{0}:{1} {2}' -f $file.Name,$entry.Extent.StartLineNumber,$entry.Message }
})
if($failures.Count){throw ($failures -join "`n")}
$manifest=Join-Path $root 'NSP.Win.LocalAccount.psd1'
$null=Test-ModuleManifest -Path $manifest -ErrorAction Stop
$module=Import-Module $manifest -Force -PassThru
try {
    $expected=@(Get-ChildItem -LiteralPath (Join-Path $root 'Public') -Filter '*.ps1' -File|ForEach-Object BaseName|Sort-Object)
    $actual=@($module.ExportedCommands.Keys|Sort-Object)
    if(($expected -join ',') -ne ($actual -join ',')){throw 'Public files and manifest exports differ.'}
} finally {Remove-Module $module.Name -Force}
& (Join-Path $PSScriptRoot 'Test-Offline.ps1')
