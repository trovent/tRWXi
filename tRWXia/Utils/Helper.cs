using System;

namespace tRWXia.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("\ntRWXi[a]llocator: \n\tallocates RWX memory -> maps RW section to the current process -> writes code to the mapped section -> maps RX copy to the external process -> executes code from that section. \n\nUsage: \n\t.\\tRWXi.exe /pid=<pid> /url=<url>|/data=<hex>|/file=<path>");
        }
    }
}
