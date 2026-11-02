function Resolve-NSPLocalAccountMachineKeyPath {
    <#
        Maps a machine RSA key to its key file. CNG Software Key Storage Provider keys live in
        Microsoft\Crypto\Keys. Software CryptoAPI provider keys live in Microsoft\Crypto\RSA\MachineKeys,
        however .NET presents them: New-SelfSignedCertificate -KeySpec makes such keys, and .NET
        returns them as RSACng in both editions. Hardware, smart-card and unknown providers, user
        keys, and container names that are not a plain file name are refused.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Provider,
        [Parameter(Mandatory)][bool]$IsMachineKey,
        [AllowEmptyString()][string]$UniqueName,
        [bool]$HardwareDevice,
        [string]$Base=[Environment]::GetFolderPath('CommonApplicationData')
    )
    $capi=@('Microsoft Base Cryptographic Provider v1.0','Microsoft Enhanced Cryptographic Provider v1.0','Microsoft Strong Cryptographic Provider','Microsoft Enhanced RSA and AES Cryptographic Provider','Microsoft RSA SChannel Cryptographic Provider')
    $folder=if($Provider -eq 'Microsoft Software Key Storage Provider'){'Microsoft\Crypto\Keys'}elseif($Provider -in $capi){'Microsoft\Crypto\RSA\MachineKeys'}else{$null}
    if(-not $folder -or $HardwareDevice -or -not $IsMachineKey) { throw "Only LocalMachine software RSA keys are supported (this key: provider '$Provider', machine key $IsMachineKey). Provision the certificate for the task account separately." }
    if(-not $UniqueName -or [IO.Path]::GetFileName($UniqueName) -ne $UniqueName) { throw 'Unexpected private-key container name.' }
    $path=Join-Path (Join-Path $Base $folder) $UniqueName
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "The private-key file for provider '$Provider' was not found where that provider stores machine keys." }
    $path
}
