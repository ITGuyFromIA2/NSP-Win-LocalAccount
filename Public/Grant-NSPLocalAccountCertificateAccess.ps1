function Grant-NSPLocalAccountCertificateAccess {
    <#
    .SYNOPSIS
        Plans read access to one existing LocalMachine software RSA private-key file.
    .DESCRIPTION
        No key export, copy or certificate creation. CurrentUser, hardware/unknown providers
        and certificates without a supported machine RSA key are rejected. Software keys from
        the CNG Software Key Storage Provider and from the Microsoft software CryptoAPI providers
        (as New-SelfSignedCertificate -KeySpec creates) are supported in both editions. Access
        applies only to the selected local account and preserves existing ACLs.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$Thumbprint,[switch]$Execute)
    $certificate=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$Thumbprint) -ErrorAction Stop
    if(-not $certificate.HasPrivateKey) { throw 'Certificate has no private key.' }
    $rsa=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        $key=if($rsa -is [Security.Cryptography.RSACng]) {
            @{Provider=[string]$rsa.Key.Provider.Provider;IsMachineKey=[bool]$rsa.Key.IsMachineKey;UniqueName=[string]$rsa.Key.UniqueName;HardwareDevice=$false}
        } elseif($rsa -is [Security.Cryptography.RSACryptoServiceProvider]) {
            $info=$rsa.CspKeyContainerInfo
            @{Provider=[string]$info.ProviderName;IsMachineKey=[bool]$info.MachineKeyStore;UniqueName=[string]$info.UniqueKeyContainerName;HardwareDevice=[bool]$info.HardwareDevice}
        } else { throw 'Only LocalMachine software RSA keys are supported; provision the certificate for the task account separately.' }
        $keyPath=Resolve-NSPLocalAccountMachineKeyPath @key
    } finally { if($rsa) { $rsa.Dispose() } }
    if(-not $PSCmdlet.ShouldProcess($Thumbprint,"Plan/apply private-key read access for local account $Name")) { return }
    Grant-NSPLocalAccountPathAccess -Name $Name -LiteralPath $keyPath -Rights Read -Execute:$Execute -Confirm:$false
}
