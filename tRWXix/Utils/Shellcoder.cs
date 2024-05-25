using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace tRWXix.Utils
{
    internal class Shellcoder
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
    }
}
