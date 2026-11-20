#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param([string]$AdapterKonfiguration = "$env:LOCALAPPDATA\OpenTapiCti\adapter.json")
$ErrorActionPreference='Stop'
if (![Environment]::Is64BitProcess) { throw '64-Bit-PowerShell verwenden.' }
$source=Join-Path $PSScriptRoot 'OpenTapiCti.tsp'
if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Zuerst Quelle\Bauen.cmd in der x64-Entwicklerkonsole ausführen.' }
$config=Get-Content -LiteralPath $AdapterKonfiguration -Raw | ConvertFrom-Json
if ($config.lokal -cnotmatch '^[a-f0-9]{48}$') { throw 'Adapterkonfiguration ungültig.' }
$reg='HKLM:\SOFTWARE\OpenTapiCti'
$target=Join-Path ([Environment]::SystemDirectory) 'OpenTapiCti.tsp'
if ((Test-Path -LiteralPath $reg) -or (Test-Path -LiteralPath $target)) { throw 'Vorhandene Installation oder Reste gefunden. Kein Überschreiben.' }
if (!$PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Nativen Pilotanbieter in System32 kopieren und bei Windows-TAPI registrieren')) { return }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CtiSetup {
 [DllImport("tapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true)]
 public static extern int lineAddProviderW(string file, IntPtr window, out uint provider);
}
'@
$registered=$false
try {
    Copy-Item -LiteralPath $source -Destination $target
    New-Item -Path $reg -Force | Out-Null
    $acl = Get-Acl -LiteralPath $reg
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-19','S-1-5-20')) {
        $rights = if ($sid -in @('S-1-5-18','S-1-5-32-544')) { 'FullControl' } else { 'ReadKey' }
        $who = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($who,$rights,'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $reg -AclObject $acl
    New-ItemProperty -Path $reg -Name LocalToken -Value $config.lokal -PropertyType String | Out-Null
    [uint32]$id=0
    $result=[CtiSetup]::lineAddProviderW($target,[IntPtr]::Zero,[ref]$id)
    if ($result -ne 0) { throw ('lineAddProviderW: 0x{0:X8}' -f $result) }
    $registered=$true
    New-ItemProperty -Path $reg -Name ProviderId -Value $id -PropertyType DWord | Out-Null
    Write-Host "TAPI-Anbieter OpenTapiCti registriert (ID $id)."
} catch {
    if (!$registered) {
        if (Test-Path $reg) { Remove-Item -LiteralPath $reg -Recurse }
        if (Test-Path $target) { Remove-Item -LiteralPath $target }
    }
    throw
}
