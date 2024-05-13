using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Collections.Generic;

namespace tRWXi
{
    public class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        public static void Main(string[] args)
        {
            Console.WriteLine("[+] Started enumeration");

            try
            {
                PROCESSENTRY32 pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(pe);

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                IntPtr lpAddress = IntPtr.Zero;

                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000002, 0); //SnapshotFlags 0x02 -> TH32CS_SNAPPROCESS

                bool hResult = Process32First(hSnapshot, ref pe);

                Dictionary<int, string> processes = new Dictionary<int, string>();

                while (hResult)
                {
                    IntPtr hProcess = OpenProcess(0x001F0FFF, false, (int) pe.th32ProcessID);
                    while (VirtualQueryEx(hProcess, lpAddress, out mbi, Marshal.SizeOf(mbi)) != 0)
                    {
                        lpAddress = new IntPtr (mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                        if (mbi.AllocationProtect == 0x40 && mbi.State == 0x1000 && mbi.Type == 0x20000) // 0x40 -> PAGE_EXECUTE_READ_WRITE
                        {
                            if (!processes.ContainsKey((int)pe.th32ProcessID))
                            {
                                processes.Add((int) pe.th32ProcessID, pe.szExeFile);
                            }
                        }
                    }
                    CloseHandle(hProcess);
                    hResult = Process32Next(hSnapshot, ref pe);
                    lpAddress = IntPtr.Zero;
                }
                CloseHandle(hSnapshot);
                foreach(KeyValuePair<int, string> pair in processes)
                {
                    Console.WriteLine(String.Format("[+] Found RWX regions in PID: {0} -> {1}", pair.Key, pair.Value));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
