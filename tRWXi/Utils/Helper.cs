using System;

namespace tRWXi.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("Usage: \n\t.\\tRWXi.exe /enumerate " +
                                     "\n\t.\\tRWXi.exe /inject /pid=<pid> /address=<hex address> /url=<remote shellcode>|/data=<comma-separated hex code>|/file=<local shellcode [/execute]" +
                                     "\n\t.\\tRWXi.exe /trigger /pid=<pid> /address=<hex address> " +
                                     "\n\t.\\tRWXi.exe /read    /pid=<pid> /address=<hex address> /size=<size> "
                                     );
        }
    }
}
