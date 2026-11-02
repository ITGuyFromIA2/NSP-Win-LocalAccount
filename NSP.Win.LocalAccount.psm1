foreach($folder in 'Private','Public') {
    foreach($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' -File) { . $file.FullName }
}
