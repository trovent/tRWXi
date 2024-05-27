using System;

namespace tRWXix.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("Usage:\n\t.\\tRWXix.exe /enumerate ;\n" +
                              "\t.\\tRWXix.exe /inject  /pid=<pid> /address=<address> /data=<comma-separated hex> ;\n" +
                              "\t.\\tRWXix.exe /inject  /pid=<pid> /address=<address> /url=<url to comma-separated hex> ;\n" +
                              "\t.\\tRWXix.exe /read    /pid=<pid> /address=<address> /size=<int> ;\n" +
                              "\t.\\tRWXix.exe /trigger /pid=<pid> /address=<address> ;");
        }
    }
}
