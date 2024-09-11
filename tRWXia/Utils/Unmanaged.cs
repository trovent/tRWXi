using System;
using System.Runtime.InteropServices;

namespace tRWXia.Utils
{
    internal class Unmanaged
    {
        internal const int SECTION_MAP_WRITE = 0x02;
        internal const int SECTION_MAP_READ = 0x04;
        internal const int SECTION_MAP_EXECUTE = 0x08;
        internal const int PAGE_EXECUTE_READWRITE = 0x40;
        internal const int SEC_COMMIT = 0x08000000;
        internal const int PAGE_READWRITE = 0x04;
        internal const int PAGE_EXECUTE_READ = 0x20;
        internal const int PROCESS_ALL_ACCESS = 0x1F0FFF;

        internal const uint INFINITE = 4294967295;

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        internal static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
