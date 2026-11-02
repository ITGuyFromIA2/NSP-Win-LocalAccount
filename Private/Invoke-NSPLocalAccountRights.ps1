function Initialize-NSPLocalAccountNative {
    if('NSP.LocalAccount.NativeRights' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace NSP.LocalAccount {
 public static class NativeRights {
  [StructLayout(LayoutKind.Sequential)] struct Attributes {
   public int Length; public IntPtr RootDirectory, ObjectName; public uint Flags;
   public IntPtr SecurityDescriptor, SecurityQualityOfService;
  }
  [StructLayout(LayoutKind.Sequential)] struct Text {
   public ushort Length, MaximumLength; public IntPtr Buffer;
  }
  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref Attributes attributes, uint access, out IntPtr handle);
  [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountRights(IntPtr handle, byte[] sid, out IntPtr rights, out uint count);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr handle, byte[] sid, Text[] rights, uint count);
  [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
  [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr pointer);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
  static void Check(uint status) { if(status!=0) throw new Win32Exception((int)LsaNtStatusToWinError(status)); }
  static IntPtr Open(bool write) {
   Attributes a=new Attributes(); a.Length=Marshal.SizeOf(typeof(Attributes)); IntPtr handle;
   Check(LsaOpenPolicy(IntPtr.Zero,ref a,0x800u | (write ? 0x10u : 0u),out handle)); return handle;
  }
  public static string[] Get(byte[] sid) {
   IntPtr handle=Open(false), buffer=IntPtr.Zero;
   try {
    uint count; uint status=LsaEnumerateAccountRights(handle,sid,out buffer,out count);
    if(status!=0 && LsaNtStatusToWinError(status)==2) return new string[0];
    Check(status); string[] result=new string[count]; int size=Marshal.SizeOf(typeof(Text));
    for(int i=0;i<count;i++) { Text t=(Text)Marshal.PtrToStructure(IntPtr.Add(buffer,i*size),typeof(Text)); result[i]=Marshal.PtrToStringUni(t.Buffer,t.Length/2); }
    return result;
   } finally { if(buffer!=IntPtr.Zero) LsaFreeMemory(buffer); LsaClose(handle); }
  }
  public static void GrantBatch(byte[] sid) {
   IntPtr handle=Open(true); Text t=new Text();
   try {
    string right="SeBatchLogonRight"; t.Buffer=Marshal.StringToHGlobalUni(right);
    t.Length=(ushort)(right.Length*2); t.MaximumLength=(ushort)(t.Length+2);
    Check(LsaAddAccountRights(handle,sid,new Text[]{t},1));
   } finally { if(t.Buffer!=IntPtr.Zero) Marshal.FreeHGlobal(t.Buffer); LsaClose(handle); }
  }
 }
}
'@ -ErrorAction Stop
}
function Invoke-NSPLocalAccountRights {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SID,[ValidateSet('Get','GrantBatch')][string]$Operation='Get')
    Initialize-NSPLocalAccountNative
    $identity=New-Object Security.Principal.SecurityIdentifier($SID)
    $bytes=New-Object byte[] $identity.BinaryLength
    $identity.GetBinaryForm($bytes,0)
    if($Operation -eq 'Get') { [NSP.LocalAccount.NativeRights]::Get($bytes) }
    else { [NSP.LocalAccount.NativeRights]::GrantBatch($bytes) }
}
