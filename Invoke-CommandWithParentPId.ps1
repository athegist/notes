# Invoke-CommandWithParentPId: A PowerShell port of Didier Stevens' SelectMyParent

function Invoke-CommandWithParentPId {
<#
    .SYNOPSIS
    Based on Didier Stevens' SelectMyParent tool. This script spawns a new process, spoofing its parent process.
    
    .DESCRIPTION
    Invoke-CommandWithParentPId creates a new process, spoofing the parent process id to be one of the user's choosing.
    
    .EXAMPLE
    Invoke-CommandWithParentPId <program> <pid>
    
    .LINK
    https://github.com/athegist/Set-ParentPId
    
    .NOTES
    Didier Stevens did it first. Some code and inspiration from Matt Graeber and Niklas Goude.
#>
    [CmdletBinding()]
    param()
    <#
        [Parameter(Mandatory=$True,Position=0)]
        [String]$program,
        [Parameter(Mandatory=$True,Position=1)]
        [int]$pid
    )
    #>

# Protions of signature below from Niklas Goude via
# https://blogs.technet.microsoft.com/heyscriptingguy/2012/07/05/use-powershell-to-duplicate-process-tokens-via-pinvoke/
$EVD = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int length; public IntPtr lpSecurityDescriptor; public bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
    public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
    public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
    public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
    public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFOEX
{
    public STARTUPINFO StartupInfo;
    public IntPtr lpAttributeList;
}
 
public static class EVD
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        String lpFileName,
        UInt32 dwDesiredAccess,
        UInt32 dwShareMode,
        IntPtr lpSecurityAttributes,
        UInt32 dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);
 
    [DllImport("Kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        int IoControlCode,
        byte[] InBuffer,
        int nInBufferSize,
        IntPtr OutBuffer,
        int nOutBufferSize,
        ref int pBytesReturned,
        IntPtr Overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        int dwAttributeCount,
        int dwFlags,
        ref int lpSize);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        uint dwFlags,
        uint Attribute,
        ref IntPtr lpValue,
        uint cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfoEx,
        out PROCESS_INFORMATION lpProcessInformation);
}
"@

    Add-Type -MemberDefinition $evd -Name EVD
    $AttribSize = 0
    $CallResult = [EVD]::InitializeProcThreadAttributeList([IntPtr]::Zero,1,0,[ref]$AttribSize) # Get size
    [IntPtr]$ProcThreadAttributeListPointer = [EVD]::VirtualAlloc([System.IntPtr]::Zero, $AttribSize, 0x3000, 0x40)
    $CallResult = [EVD]::InitializeProcThreadAttributeList($ProcThreadAttributeListPointer,1,0,[ref]$AttribSize) # Init
    if (!$CallResult) {
    echo "`n[!] Failed to InitializeProcThreadAttributeList..`n"
    Return
    }
    
    # PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
    $CallResult = [EVD]::UpdateProcThreadAttribute($ProcThreadAttributeListPointer,0,0x00020000,[ref]$SystemProcHandle,[System.IntPtr]::Size,[IntPtr]::Zero,[IntPtr]::Zero)
    if (!$CallResult) {
    echo "`n[!] Failed to UpdateProcThreadAttribute..`n"
    Return
    }
    
    $StartupInfoEx = New-Object STARTUPINFOEX
    $StartupInfo = New-Object STARTUPINFO
    $StartupInfo.dwFlags = 0
    $StartupInfo.wShowWindow = 1
    $StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
    
    
    $StartupInfoEx.StartupInfo = $StartupInfo
    $StartupInfoEx.lpAttributeList = $ProcThreadAttributeListPointer
    
    # ProcessInfo Struct
    $ProcessInfo = New-Object PROCESS_INFORMATION
    
    # SECURITY_ATTRIBUTES Struct (Process & Thread)
    $SecAttr = New-Object SECURITY_ATTRIBUTES
    $SecAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttr)
    
    # CreateProcess --> lpCurrentDirectory
    $GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    [EVD]::CreateProcess("C:\Windows\System32\cmd.exe","/c calc.exe", [ref]$SecAttr, [ref]$SecAttr, $false, 0x00080000, [IntPtr]::Zero, "C:\Windows\", [ref]$StartupInfoEx, [ref]$ProcessInfo)