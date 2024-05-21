using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

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

            if (parameters.ContainsKey("trigger"))
            {
                if (parameters.ContainsKey("pid") && parameters.ContainsKey("address"))
                {
                    IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Convert.ToInt32(parameters["pid"]));
                    IntPtr res = CreateRemoteThread(hProcess, IntPtr.Zero, 0, new IntPtr(Convert.ToInt64(parameters["address"], 16)), IntPtr.Zero, 0, IntPtr.Zero);
                    Console.WriteLine("[!] Trying to execute code from provided memory");
                    if (res != null)
                    {
                        Console.WriteLine(String.Format("[+] Successfully executed code. Thread handle [{0}] has been created", res.ToInt64()));
                    }
                    Environment.Exit(1);
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
