using System;

namespace tRWXix.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("Usage:\n\t.\\tRWXix.exe /enumerate ;" +
                              "\t.\\tRWXix.exe /trigger /pid=<pid> /address=<hex address> /data=<comma-separated hex> ;");
        }
    }
}
