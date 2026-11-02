function Grant-NSPLocalAccountCertificateAccess {
    <#
    .SYNOPSIS
        Plans read access to one existing LocalMachine software RSA private-key file.
    .DESCRIPTION
        No key export, copy or certificate creation. CurrentUser, hardware/unknown providers
        and certificates without a supported machine RSA key are rejected. Access applies
        only to the selected local account and preserves existing ACLs.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,[switch]$Execute)
    $certificate=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$Thumbprint) -ErrorAction Stop
    if(-not $certificate.HasPrivateKey) { throw 'Certificate has no private key.' }
    $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        if($rsa -is [Security.Cryptography.RSACng] -and $rsa.Key.IsMachineKey -and $rsa.Key.Provider.Provider -eq 'Microsoft Software Key Storage Provider') {
            $base=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft/Crypto/Keys'
            $keyName=$rsa.Key.UniqueName
        } elseif($rsa -is [Security.Cryptography.RSACryptoServiceProvider] -and $rsa.CspKeyContainerInfo.MachineKeyStore -and -not $rsa.CspKeyContainerInfo.HardwareDevice) {
            $base=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft/Crypto/RSA/MachineKeys'
            $keyName=$rsa.CspKeyContainerInfo.UniqueKeyContainerName
        } else { throw 'Only LocalMachine software RSA keys are supported; provision the certificate for the task account separately.' }
        if(-not $keyName -or [IO.Path]::GetFileName($keyName) -ne $keyName) { throw 'Unexpected private-key container name.' }
        $keyPath=Join-Path $base $keyName
    } finally { if($rsa) { $rsa.Dispose() } }
    if(-not $PSCmdlet.ShouldProcess($Thumbprint,"Plan/apply private-key read access for local account $Name")) { return }
    Grant-NSPLocalAccountPathAccess -Name $Name -LiteralPath $keyPath -Rights Read -Execute:$Execute -Confirm:$false
}
