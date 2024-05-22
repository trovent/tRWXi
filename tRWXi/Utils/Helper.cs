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
            Console.WriteLine("Usage: \n\t.\\tRWXi.exe /enumerate ;" +
                                     "\n\t.\\tRWXi.exe /inject /pid=<pid> /url=<remote shellcode> ;" +
                                     "\n\t.\\tRWXi.exe /trigger /pid=<pid> /address=<hex address w/ shellcode> ;");
        }
    }
}
