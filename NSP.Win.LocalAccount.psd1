@{
 RootModule='NSP.Win.LocalAccount.psm1'
 ModuleVersion='0.1.1'
 GUID='6546f116-3c3b-4bb3-b47d-b2c09bc5f194'
 Author='Network Systems Plus'
 CompanyName='Network Systems Plus'
 Copyright='(c) 2026 Network Systems Plus. All rights reserved.'
 Description='Plan-first local service-account creation, direct batch-logon rights and resource access.'
 PowerShellVersion='5.1'
 FunctionsToExport=@('Get-NSPLocalServiceAccount','New-NSPLocalServiceAccount','Get-NSPLocalAccountRight','Grant-NSPLocalAccountBatchLogon','Grant-NSPLocalAccountPathAccess','Grant-NSPLocalAccountCertificateAccess','Start-NSPLocalAccountManager')
 CmdletsToExport=@(); VariablesToExport=@(); AliasesToExport=@()
 PrivateData=@{
  PSData=@{
   Tags=@('LocalAccount','ServiceAccount','LogonAsBatch','ACL','Windows','NSP')
   ProjectUri='https://github.com/ITGuyFromIA2/NSP-Win-LocalAccount'
   LicenseUri='https://github.com/ITGuyFromIA2/NSP-Win-LocalAccount/blob/main/LICENSE'
   ReleaseNotes='0.1.1: Machine-key read access also for software CryptoAPI keys (as New-SelfSignedCertificate -KeySpec creates), which .NET presents as RSACng.'
  }
 }
}
