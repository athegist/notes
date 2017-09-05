# SelectMyParent: A PowerShell port of Didier Stevens' SelectMyParent

function CurrentProcessAdjustToken {
    # Declare function variables
    # Handle htoken
    [IntPtr]$htoken = [IntPtr]::Zero
    # Open the process to adjust privs, return the process handle
    $adjPriv::OpenProcessToken($adjPriv::GetCurrentProcess(), [AdjPriv.AdjPriv]::TOKEN_ADJUST_PRIVILEGES, [ref]$htoken) 
}

# Main
#
# Set up signature for the Add-Type call
$signature = @"
    [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)] 
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)] 
        public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("kernel32.dll", ExactSpelling = true)] 
        public static extern IntPtr GetCurrentProcess();
"@

Add-Type -MemberDefinition $signature -Name AdjPriv -Namespace AdjPriv



$adjpriv = [AdjPriv.AdjPriv]


