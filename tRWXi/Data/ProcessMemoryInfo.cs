using System;

namespace tRWXi.Data
{
    internal class ProcessMemoryInfo
    {
        internal int pid { get; set; }
        internal string processName { get; set; }
        internal IntPtr handler { get; set; }
        internal IntPtr baseAddress { get; set; }
        internal IntPtr size { get; set; }

        internal ProcessMemoryInfo(int pid, string processName, IntPtr handler, IntPtr baseAddress, IntPtr size)
        {
            this.pid = pid;
            this.processName = processName;
            this.handler = handler;
            this.baseAddress = baseAddress;
            this.size = size;
        }
    }
}
