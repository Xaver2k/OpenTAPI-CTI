#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param()
$ErrorActionPreference='Stop'
if (![Environment]::Is64BitProcess) { throw '64-Bit-PowerShell verwenden.' }
$reg='HKLM:\SOFTWARE\OpenTapiCti'
$p=Get-ItemProperty -LiteralPath $reg
if ($null -eq $p.ProviderId) { throw 'Keine gespeicherte Provider-ID. In Telefon und Modem die registrierten Anbieter prüfen.' }
if (!$PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Pilotanbieter $($p.ProviderId) aus Windows-TAPI entfernen")) { return }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CtiRemove {
 [DllImport("tapi32.dll")] public static extern int lineRemoveProvider(uint provider,IntPtr window);
 [DllImport("tapi32.dll",ExactSpelling=true)] static extern int lineGetProviderListW(uint v,IntPtr buffer);
 public static bool Matches(uint id,string basename){
  int size=4096;
  while(size<=1048576){
   IntPtr ptr=Marshal.AllocHGlobal(size);
   try {
    Marshal.WriteInt32(ptr,size);
    if(lineGetProviderListW(0x20000,ptr)!=0)return false;
    int needed=Marshal.ReadInt32(ptr,4);if(needed>size){size=needed;continue;}
    int count=Marshal.ReadInt32(ptr,12),offset=Marshal.ReadInt32(ptr,20);
    for(int i=0;i<count;i++){
     int entry=offset+12*i;
     if((uint)Marshal.ReadInt32(ptr,entry)==id){
      string path=Marshal.PtrToStringUni(IntPtr.Add(ptr,Marshal.ReadInt32(ptr,entry+8)));
      return String.Equals(System.IO.Path.GetFileName(path),basename,StringComparison.OrdinalIgnoreCase);
     }
    }
    return false;
   }finally{Marshal.FreeHGlobal(ptr);}
  }
  return false;
 }
}
'@
if (![CtiRemove]::Matches($p.ProviderId,'OpenTapiCti.tsp')) { throw 'Die gespeicherte ID gehört aktuell nicht nachweislich zu OpenTapiCti.tsp.' }
$result=[CtiRemove]::lineRemoveProvider($p.ProviderId,[IntPtr]::Zero)
if ($result -ne 0) { throw ('lineRemoveProvider: 0x{0:X8}' -f $result) }
Remove-Item -LiteralPath $reg -Recurse
Remove-Item -LiteralPath (Join-Path ([Environment]::SystemDirectory) 'OpenTapiCti.tsp')
