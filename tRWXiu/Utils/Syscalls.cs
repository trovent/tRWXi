using System;
using System.Runtime.InteropServices;

namespace tRWXiu.Utils
{
    class Syscalls
    {
        public struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect);

        }

        public static byte[] bNtOpenProcess =
        {
            0x4c, 0x8b, 0xd1,                            // mov     r10,rcx
            0xb8, 0x26, 0x00, 0x00, 0x00,                // mov     eax,26h
            0x0f, 0x05,                                  // syscall
            0xc3                                         // ret
        };

        [StructLayout(LayoutKind.Sequential, Pack=0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int lenght;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        public static uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId)
        {
            unsafe
            {
                fixed (byte* ptr = bNtOpenProcess)
                {
                    allocatePtr((IntPtr)ptr, bNtOpenProcess);

                    Delegates.NtOpenProcess assembledFunction = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(Delegates.NtOpenProcess));

                    return (uint)assembledFunction(ref ProcessHandle, AccessMask, ref ObjectAttributes, ref ClientId);
                }
            }
        }

        static byte[] bNtReadVirtualMemory =
        {
            0x4c, 0x8b, 0xd1,                           // mov     r10,rcx
            0xb8, 0x3f, 0x00, 0x00, 0x00,               // mov     eax,3Fh
            0x0f, 0x05,                                 // syscall
            0xc3                                        // ret
        };

        public static uint NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref UInt32 NumberOfBytesRead)
        {
            unsafe
            {
                fixed (byte* ptr = bNtReadVirtualMemory)
                {
                    allocatePtr((IntPtr)ptr, bNtReadVirtualMemory);

                    Delegates.NtReadVirtualMemory assembledFunction = (Delegates.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(Delegates.NtReadVirtualMemory));

                    return (uint)assembledFunction(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, ref NumberOfBytesRead);
                }
            }
        }

        static byte[] bNtWriteVirtualMemory =
        {
            0x4c, 0x8b, 0xd1,               // mov     r10,rcx
            0xb8, 0x3a, 0x00, 0x00, 0x00,   // mov     eax,3Ah
            0x0f, 0x05,                     // syscall
            0xc3                            // ret
        };

        public static uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten)
        {
            unsafe
            {
                fixed (byte* ptr = bNtWriteVirtualMemory)
                {
                    allocatePtr((IntPtr)ptr, bNtWriteVirtualMemory);

                    Delegates.NtWriteVirtualMemory assembledFunction = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(Delegates.NtWriteVirtualMemory));

                    return (uint)assembledFunction(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, ref NumberOfBytesWritten);
                }
            }
        }

        static byte[] bNtCreateThreadEx =
        {            
            0x4c, 0x8b, 0xd1,                // mov     r10,rcx
            0xb8, 0xc7, 0x00, 0x00, 0x00,    // mov     eax,0C7h
            0x0f, 0x05,                      // syscall
            0xc3                             // ret
        };

        public static uint NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList)
        {
            unsafe
            {
                fixed (byte* ptr = bNtCreateThreadEx)
                {
                    allocatePtr((IntPtr)ptr, bNtCreateThreadEx);

                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(Delegates.NtCreateThreadEx));

                    return (uint)assembledFunction(ref threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, inCreateSuspended, stackZeroBits, sizeOfStack, maximumStackSize, attributeList);
                }
            }
        }

        static byte[] bNtAllocateVirtualMemory =
        {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 0x18 (NtAllocateVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionZize, UInt32 AllocationType, UInt32 Protect)
        {
            unsafe
            {
                fixed (byte* ptr = bNtAllocateVirtualMemory)
                {
                    allocatePtr((IntPtr)ptr, bNtAllocateVirtualMemory);

                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer((IntPtr)ptr, typeof(Delegates.NtAllocateVirtualMemory));

                    return (uint)assembledFunction(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionZize, AllocationType, Protect);
                }
            }
        }

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static void allocatePtr(IntPtr memoryAddress, byte[] syscall)
        {
            if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, 0x00000040, out uint lpflOldProtect))
            {
                throw new System.ComponentModel.Win32Exception();
            }
        }
    }
}
