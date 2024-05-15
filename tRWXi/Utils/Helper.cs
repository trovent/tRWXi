using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace tRWXi.Utils
{
    internal class Helper
    {
        internal static void help()
        {
            Console.WriteLine("Usage: \n\t.\\tRWXi.exe /enumerate -> enumerate memory regions only;" +
                                     "\n\t.\\tRWXi.exe /pid=<pid> /url=<remote shell code>");
        }
    }
}
