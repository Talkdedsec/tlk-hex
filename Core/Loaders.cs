using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace tlk_hex.Core;

public sealed class LoadOptions
{
    public string Loader = "auto";        // auto / pe / elf / bin
    public int BinBitness = 64;
    public ulong BinBase = 0;
    public bool SplitIdata = true;        // "Make imports segment"
    public bool LoadResources = false;
    public bool Analyze = true;
}

public static class Loaders
{
    public static string Detect(byte[] b)
    {
        if (b.Length > 0x40 && b[0] == 'M' && b[1] == 'Z')
        {
            int pe = BitConverter.ToInt32(b, 0x3C);
            if (pe > 0 && pe + 4 < b.Length && b[pe] == 'P' && b[pe + 1] == 'E' && b[pe + 2] == 0 && b[pe + 3] == 0)
                return "pe";
        }
        if (b.Length > 0x34 && b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') return "elf";
        return "bin";
    }

    // Load dialogunda gosterilen bicim adi
    public static string Describe(byte[] b, string id)
    {
        try
        {
            if (id == "pe")
            {
                int pe = BitConverter.ToInt32(b, 0x3C);
                ushort mach = BitConverter.ToUInt16(b, pe + 4);
                return mach switch
                {
                    0x8664 => "Portable executable for AMD64 (PE)",
                    0x14C => "Portable executable for 80386 (PE)",
                    0xAA64 => "Portable executable for ARM64 (PE)",
                    _ => $"Portable executable (machine {mach:X4})",
                };
            }
            if (id == "elf")
                return b[4] == 2 ? "ELF64 for x86-64" : "ELF for Intel 386";
        }
        catch { }
        return "Binary file";
    }

    public static Db Load(string path, LoadOptions opt, Action<string> log)
    {
        var bytes = File.ReadAllBytes(path);
        string id = opt.Loader == "auto" ? Detect(bytes) : opt.Loader;
        var db = new Db { FilePath = path, FileBytes = bytes, LoaderId = id };

        switch (id)
        {
            case "pe": LoadPe(db, opt, log); break;
            case "elf": LoadElf(db, log); break;
            default: LoadBin(db, opt, log); break;
        }

        for (int i = 0; i < db.Segs.Count; i++) db.Segs[i].Index = i;
        foreach (var s in db.Segs)
        {
            s.F = new byte[s.Size];
            if (s.X)
            {
                s.Owner = new int[s.Size];
                Array.Fill(s.Owner, -1);
            }
        }
        return db;
    }

    private static Segment NewSeg(string name, ulong start, ulong size, byte[] file, long foff, long rawSize)
    {
        if (size > 0x2000_0000) size = 0x2000_0000; // 512MB tavan
        var s = new Segment { Name = name, Start = start, End = start + size, FileOffset = foff };
        s.Data = new byte[size];
        if (foff >= 0 && foff < file.Length && rawSize > 0)
        {
            long n = Math.Min(Math.Min(rawSize, (long)size), file.Length - foff);
            Array.Copy(file, foff, s.Data, 0, n);
            s.InitSize = (int)n;
        }
        return s;
    }

    // ================= Binary =================

    private static void LoadBin(Db db, LoadOptions opt, Action<string> log)
    {
        db.Format = "Binary file";
        db.Bitness = opt.BinBitness;
        db.ImageBase = opt.BinBase;
        db.FileType = "BIN";
        db.Machine = opt.BinBitness == 64 ? "x64" : opt.BinBitness == 32 ? "x86" : "x86-16";
        var s = NewSeg("seg000", opt.BinBase, (ulong)Math.Max(1, db.FileBytes.Length), db.FileBytes, 0, db.FileBytes.Length);
        s.R = s.W = s.X = true;
        s.Class = "CODE";
        s.SegType = "Regular";
        db.Segs.Add(s);
        db.Entry = opt.BinBase;
        db.LoaderNames[opt.BinBase] = "start";
        db.Entries.Add((opt.BinBase, "start", 0));
        db.OsType = "-";
        db.AppType = "Binary";
        log($"  0. Segment oluşturuluyor ({db.AddrStr(s.Start)}-{db.AddrStr(s.End)}) seg000 ... OK");
    }

    // ================= PE =================

    private static void LoadPe(Db db, LoadOptions opt, Action<string> log)
    {
        var b = db.FileBytes;
        int pe = BitConverter.ToInt32(b, 0x3C);
        int fh = pe + 4;
        ushort machine = U16(b, fh);
        int nsec = U16(b, fh + 2);
        uint tstamp = U32(b, fh + 4);
        int optSize = U16(b, fh + 16);
        ushort chars = U16(b, fh + 18);
        int oh = fh + 20;
        ushort magic = U16(b, oh);
        bool is64 = magic == 0x20B;

        db.Bitness = is64 ? 64 : 32;
        db.Machine = machine switch { 0x8664 => "x64", 0x14C => "x86", 0xAA64 => "ARM64", 0x1C4 => "ARM", _ => $"0x{machine:X}" };
        db.CanDisasm = machine is 0x8664 or 0x14C;
        if (machine == 0xAA64) db.Bitness = 64;
        db.Format = Describe(b, "pe");

        uint entryRva = U32(b, oh + 16);
        db.ImageBase = is64 ? U64(b, oh + 24) : U32(b, oh + 28);
        uint secAlign = Math.Max(U32(b, oh + 32), 0x200);
        ushort subsys = U16(b, oh + 68);
        int nDirs = (int)U32(b, oh + (is64 ? 108 : 92));
        int dirOff = oh + (is64 ? 112 : 96);

        db.Subsystem = subsys switch
        {
            1 => "Native", 2 => "Windows GUI", 3 => "Windows CUI", 9 => "Windows CE GUI",
            10 => "EFI application", 11 => "EFI boot driver", 12 => "EFI runtime driver", _ => subsys.ToString(),
        };
        db.Timestamp = DateTimeOffset.FromUnixTimeSeconds(tstamp).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
        bool isDll = (chars & 0x2000) != 0;
        db.FileType = isDll ? "DLL" : subsys == 1 ? "Driver (SYS)" : "EXE";
        db.OsType = "MS Windows";
        db.AppType = (isDll ? "DLL " : subsys == 2 ? "Graphics " : subsys == 1 ? "Native " : "Console ") + (is64 ? "64bit" : "32bit");

        (uint rva, uint size) Dir(int i) => i < nDirs && dirOff + i * 8 + 8 <= b.Length
            ? (U32(b, dirOff + i * 8), U32(b, dirOff + i * 8 + 4)) : (0u, 0u);

        // ---- sectionlar ----
        int secOff = oh + optSize;
        var secs = new List<(string name, uint va, uint vs, uint raw, uint rawPtr, uint ch)>();
        for (int i = 0; i < nsec; i++)
        {
            int p = secOff + i * 40;
            if (p + 40 > b.Length) break;
            string name = Encoding.ASCII.GetString(b, p, 8).TrimEnd('\0');
            secs.Add((name, U32(b, p + 12), U32(b, p + 8), U32(b, p + 16), U32(b, p + 20), U32(b, p + 36)));
            db.PeSections.Add(U32(b, p + 12));
        }

        var (iatRva, iatSize) = Dir(12);
        var (relRva, relSize) = Dir(5);
        var (rsrcRva, rsrcSize) = Dir(2);
        db.IsSigned = Dir(4).size > 0;
        db.IsDotNet = Dir(14).size > 0;

        int segNo = 0;
        foreach (var sc in secs)
        {
            uint vsize = sc.vs != 0 ? sc.vs : sc.raw;
            if (vsize == 0) continue;
            // IDA varsayilani: .reloc yuklenmez, kaynaklar istege bagli
            if (relRva != 0 && sc.va == relRva && sc.name.StartsWith(".reloc")) continue;
            if (!opt.LoadResources && rsrcRva != 0 && sc.va == rsrcRva) continue;

            ulong size = AlignUp(vsize, secAlign);
            long raw = Math.Min(sc.raw, vsize);
            long rawPtr = sc.rawPtr & ~0x1FFu;
            if (sc.rawPtr == 0) raw = 0;

            bool x = (sc.ch & 0x20000000) != 0 || (sc.ch & 0x20) != 0;
            bool r = (sc.ch & 0x40000000) != 0;
            bool w = (sc.ch & 0x80000000) != 0;

            var add = new List<Segment>();
            // .idata ayir: IAT section basindaysa
            if (opt.SplitIdata && iatRva != 0 && iatRva == sc.va && iatSize > 0 && iatSize < vsize && !x)
            {
                ulong isz = AlignUp(iatSize, 16);
                var si = NewSeg(".idata", db.ImageBase + sc.va, isz, b, rawPtr, Math.Min(raw, (long)isz));
                si.IsExtern = true;
                si.Class = "XTRN";
                si.SegType = "Externs";
                si.R = true;
                add.Add(si);
                long rest = raw - (long)isz;
                var s2 = NewSeg(sc.name, db.ImageBase + sc.va + isz, size - isz, b, rawPtr + (long)isz, Math.Max(0, rest));
                add.Add(s2);
                s2.R = r; s2.W = w; s2.X = x;
                s2.Class = w ? "DATA" : "CONST";
                s2.SegType = "Pure data";
            }
            else
            {
                var s = NewSeg(sc.name, db.ImageBase + sc.va, size, b, rawPtr, raw);
                s.R = r; s.W = w; s.X = x;
                if (x) { s.Class = "CODE"; s.SegType = "Pure code"; }
                else if ((sc.ch & 0x80) != 0 && raw == 0) { s.Class = "BSS"; s.SegType = "Uninitialized"; }
                else { s.Class = w ? "DATA" : "CONST"; s.SegType = "Pure data"; }
                add.Add(s);
            }

            segNo++;
            var info = add[0].Info;
            info.Add($"; Section {segNo}. (virtual address {sc.va:X8})");
            info.Add($"; Virtual size                  : {sc.vs:X8} ({sc.vs,8}.)");
            info.Add($"; Section size in file          : {sc.raw:X8} ({sc.raw,8}.)");
            info.Add($"; Offset to raw data for section: {sc.rawPtr:X8}");
            info.Add($"; Flags {sc.ch:X8}: {SecFlagText(sc.ch)}");
            info.Add("; Alignment     : default");
            foreach (var s in add)
            {
                db.Segs.Add(s);
                log($"  {db.Segs.Count - 1}. Segment oluşturuluyor ({db.AddrStr(s.Start)}-{db.AddrStr(s.End)}) {s.Name} ... OK");
            }
        }
        db.Segs.Sort((a, c) => a.Start.CompareTo(c.Start));

        // ---- import ----
        var (impRva, impSize) = Dir(1);
        if (impRva != 0)
        {
            for (int i = 0; i < 4096; i++)
            {
                ulong d = db.ImageBase + impRva + (ulong)(i * 20);
                if (!db.TryRead(d, 4, out var oft) || !db.TryRead(d + 12, 4, out var nameRva) || !db.TryRead(d + 16, 4, out var ft))
                    break;
                if (oft == 0 && nameRva == 0 && ft == 0) break;
                string dll = db.ReadAscii(db.ImageBase + nameRva, 260);
                ulong lookup = oft != 0 ? oft : ft;
                for (int k = 0; k < 65536; k++)
                {
                    ulong slot = db.ImageBase + ft + (ulong)(k * db.Ptr);
                    if (!db.TryRead(db.ImageBase + lookup + (ulong)(k * db.Ptr), db.Ptr, out var th) || th == 0) break;
                    var imp = new ImportInfo { Ea = slot, Dll = dll };
                    ulong ordFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
                    if ((th & ordFlag) != 0)
                    {
                        imp.Ordinal = (int)(th & 0xFFFF);
                        imp.Name = $"{Path.GetFileNameWithoutExtension(dll)}_{imp.Ordinal}";
                    }
                    else
                    {
                        imp.Name = db.ReadAscii(db.ImageBase + (th & 0x7FFFFFFF) + 2, 512);
                        db.TryRead(db.ImageBase + (th & 0x7FFFFFFF), 2, out var hint);
                        imp.Ordinal = (int)hint;
                    }
                    if (string.IsNullOrEmpty(imp.Name)) continue;
                    AddImport(db, imp);
                }
            }
        }

        // ---- gecikmeli import ----
        var (dlRva, _) = Dir(13);
        if (dlRva != 0)
        {
            for (int i = 0; i < 1024; i++)
            {
                ulong d = db.ImageBase + dlRva + (ulong)(i * 32);
                if (!db.TryRead(d, 4, out var attr) || !db.TryRead(d + 4, 4, out var dllName)) break;
                if (dllName == 0) break;
                db.TryRead(d + 12, 4, out var iat);
                db.TryRead(d + 16, 4, out var intRva);
                ulong rb = (attr & 1) != 0 ? db.ImageBase : 0;
                string dll = db.ReadAscii(rb + dllName, 260);
                for (int k = 0; k < 65536; k++)
                {
                    if (!db.TryRead(rb + intRva + (ulong)(k * db.Ptr), db.Ptr, out var th) || th == 0) break;
                    var imp = new ImportInfo { Ea = rb + iat + (ulong)(k * db.Ptr), Dll = dll, Delay = true };
                    ulong ordFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
                    if ((th & ordFlag) != 0)
                    {
                        imp.Ordinal = (int)(th & 0xFFFF);
                        imp.Name = $"{Path.GetFileNameWithoutExtension(dll)}_{imp.Ordinal}";
                    }
                    else imp.Name = db.ReadAscii(rb + (th & 0x7FFFFFFF) + 2, 512);
                    if (string.IsNullOrEmpty(imp.Name)) continue;
                    AddImport(db, imp);
                }
            }
        }
        if (db.Imports.Count > 0) log($"  {db.Imports.Count} import, {db.Imports.Select(i => i.Dll).Distinct().Count()} DLL");

        // ---- export ----
        var (expRva, expSize) = Dir(0);
        if (expRva != 0 && db.TryRead(db.ImageBase + expRva + 16, 4, out var obase))
        {
            ulong e = db.ImageBase + expRva;
            db.TryRead(e + 20, 4, out var nFuncs);
            db.TryRead(e + 24, 4, out var nNames);
            db.TryRead(e + 28, 4, out var aFuncs);
            db.TryRead(e + 32, 4, out var aNames);
            db.TryRead(e + 36, 4, out var aOrds);
            var names = new Dictionary<uint, string>();
            for (uint i = 0; i < Math.Min(nNames, 200000); i++)
            {
                if (!db.TryRead(db.ImageBase + aNames + i * 4, 4, out var nr)) break;
                if (!db.TryRead(db.ImageBase + aOrds + i * 2, 2, out var ord)) break;
                names[(uint)ord] = db.ReadAscii(db.ImageBase + nr, 512);
            }
            for (uint i = 0; i < Math.Min(nFuncs, 200000); i++)
            {
                if (!db.TryRead(db.ImageBase + aFuncs + i * 4, 4, out var fr) || fr == 0) continue;
                var ex = new ExportInfo { Ordinal = (int)(obase + i), Ea = db.ImageBase + fr };
                ex.Name = names.TryGetValue(i, out var n) && n.Length > 0 ? n : $"Ordinal_{ex.Ordinal}";
                if (fr >= expRva && fr < expRva + expSize) ex.Forwarder = db.ReadAscii(db.ImageBase + fr, 512);
                db.Exports.Add(ex);
                if (ex.Forwarder == null && db.IsMapped(ex.Ea))
                {
                    if (!db.LoaderNames.ContainsKey(ex.Ea)) db.LoaderNames[ex.Ea] = ex.Name;
                    db.PublicNames.Add(ex.Ea);
                    db.Entries.Add((ex.Ea, ex.Name, ex.Ordinal));
                }
            }
            log($"  {db.Exports.Count} export");
        }

        // ---- giris noktasi ----
        if (entryRva != 0)
        {
            db.Entry = db.ImageBase + entryRva;
            string en = isDll ? "DllEntryPoint" : subsys == 1 ? "DriverEntry" : "start";
            if (!db.LoaderNames.ContainsKey(db.Entry)) db.LoaderNames[db.Entry] = en;
            db.PublicNames.Add(db.Entry);
            db.Entries.Add((db.Entry, db.LoaderNames[db.Entry], 0));
        }

        // ---- TLS geri cagirmalari ----
        var (tlsRva, _) = Dir(9);
        if (tlsRva != 0)
        {
            ulong t = db.ImageBase + tlsRva;
            if (db.TryRead(t + (ulong)(3 * db.Ptr), db.Ptr, out var cbArr) && cbArr != 0)
            {
                for (int i = 0; i < 64; i++)
                {
                    if (!db.TryReadPtr(cbArr + (ulong)(i * db.Ptr), out var cb) || cb == 0) break;
                    if (!db.IsMapped(cb)) break;
                    string n = $"TlsCallback_{i}";
                    db.LoaderNames.TryAdd(cb, n);
                    db.Entries.Add((cb, n, 0));
                }
            }
        }

        // ---- .pdata (x64) ----
        var (excRva, excSize) = Dir(3);
        if (excRva != 0 && is64)
        {
            for (uint i = 0; i < excSize / 12; i++)
            {
                ulong p = db.ImageBase + excRva + i * 12;
                if (!db.TryRead(p, 4, out var beg) || !db.TryRead(p + 4, 4, out var end) || !db.TryRead(p + 8, 4, out var unw))
                    break;
                if (beg == 0 || end <= beg) continue;
                // chained unwind -> fonksiyon parcasi, baslangic degil
                bool chained = false;
                if ((unw & 1) == 0 && db.TryByte(db.ImageBase + unw, out var vf))
                    chained = ((vf >> 3) & 4) != 0;
                if (!chained) db.PdataEnds[db.ImageBase + beg] = db.ImageBase + end;
            }
            log($"  .pdata: {db.PdataEnds.Count} fonksiyon kaydı");
        }

        // ---- relocation ----
        if (relRva != 0 && relSize > 0)
        {
            long ro = RvaToFile(secs, relRva);
            if (ro >= 0)
            {
                long end = Math.Min(b.Length, ro + relSize);
                long p = ro;
                while (p + 8 <= end)
                {
                    uint page = U32(b, (int)p);
                    uint bsz = U32(b, (int)p + 4);
                    if (bsz < 8) break;
                    for (long q = p + 8; q + 2 <= p + bsz && q + 2 <= end; q += 2)
                    {
                        ushort en = U16(b, (int)q);
                        int type = en >> 12;
                        if (type is 3 or 10) db.Relocs.Add(db.ImageBase + page + (uint)(en & 0xFFF));
                    }
                    p += bsz;
                }
            }
        }

        // ---- debug (PDB yolu) ----
        var (dbgRva, dbgSize) = Dir(6);
        for (uint i = 0; dbgRva != 0 && i < dbgSize / 28 && i < 16; i++)
        {
            ulong d = db.ImageBase + dbgRva + i * 28;
            if (!db.TryRead(d + 12, 4, out var type) || type != 2) continue;
            db.TryRead(d + 24, 4, out var ptr);
            db.TryRead(d + 16, 4, out var sz);
            if ((long)ptr + 24 < b.Length && b[ptr] == 'R' && b[ptr + 1] == 'S' && b[ptr + 2] == 'D' && b[ptr + 3] == 'S')
            {
                db.PdbGuid = new Guid(b.AsSpan((int)ptr + 4, 16));
                db.PdbAge = U32(b, (int)ptr + 20);
                db.PdbPath = ReadZ(b, (int)ptr + 24, (int)Math.Min(sz, 1024));
            }
        }
    }

    private static void AddImport(Db db, ImportInfo imp)
    {
        if (db.ImportAt.ContainsKey(imp.Ea)) return;
        db.Imports.Add(imp);
        db.ImportAt[imp.Ea] = imp;
        string nm = imp.Delay ? "__imp_" + imp.Name : imp.Name;
        if (db.LoaderNames.ContainsValue(nm)) nm = nm + "_" + Db.Hx(imp.Ea);
        db.LoaderNames[imp.Ea] = nm;
    }

    private static string SecFlagText(uint c)
    {
        var l = new List<string>();
        if ((c & 0x20) != 0) l.Add("Text");
        if ((c & 0x40) != 0) l.Add("Data");
        if ((c & 0x80) != 0) l.Add("Bss");
        if ((c & 0x20000000) != 0) l.Add("Executable");
        if ((c & 0x40000000) != 0) l.Add("Readable");
        if ((c & 0x80000000) != 0) l.Add("Writable");
        return string.Join(" ", l);
    }

    private static long RvaToFile(List<(string name, uint va, uint vs, uint raw, uint rawPtr, uint ch)> secs, uint rva)
    {
        foreach (var s in secs)
        {
            uint sz = Math.Max(s.vs, s.raw);
            if (rva >= s.va && rva < s.va + sz) return (s.rawPtr & ~0x1FFu) + (rva - s.va);
        }
        return -1;
    }

    // ================= ELF =================

    private static void LoadElf(Db db, Action<string> log)
    {
        var b = db.FileBytes;
        bool is64 = b[4] == 2;
        db.Bitness = is64 ? 64 : 32;
        ushort type = U16(b, 16);
        ushort mach = U16(b, 18);
        db.Machine = mach switch { 62 => "x64", 3 => "x86", 183 => "ARM64", 40 => "ARM", _ => $"0x{mach:X}" };
        db.CanDisasm = mach is 62 or 3;
        db.Format = Describe(b, "elf") + (type == 3 ? " (Shared object)" : " (Executable)");
        db.FileType = type == 3 ? "SO" : "ELF";
        db.OsType = "Linux/Unix";
        db.AppType = (type == 3 ? "Shared object " : "Executable ") + (is64 ? "64bit" : "32bit");

        ulong entry = is64 ? U64(b, 24) : U32(b, 24);
        ulong shoff = is64 ? U64(b, 40) : U32(b, 32);
        int shentsize = U16(b, is64 ? 58 : 46);
        int shnum = U16(b, is64 ? 60 : 48);
        int shstrndx = U16(b, is64 ? 62 : 50);

        var shs = new List<(string name, uint type, ulong flags, ulong addr, ulong off, ulong size, uint link, ulong entsize)>();
        (uint nameOff, uint type, ulong flags, ulong addr, ulong off, ulong size, uint link, ulong entsize) Sh(int i)
        {
            long p = (long)shoff + (long)i * shentsize;
            if (is64)
                return (U32(b, (int)p), U32(b, (int)p + 4), U64(b, (int)p + 8), U64(b, (int)p + 16),
                    U64(b, (int)p + 24), U64(b, (int)p + 32), U32(b, (int)p + 40), U64(b, (int)p + 56));
            return (U32(b, (int)p), U32(b, (int)p + 4), U32(b, (int)p + 8), U32(b, (int)p + 12),
                U32(b, (int)p + 16), U32(b, (int)p + 20), U32(b, (int)p + 24), U32(b, (int)p + 36));
        }

        if (shoff > 0 && shnum > 0 && (long)shoff + (long)shnum * shentsize <= b.Length)
        {
            var strtab = Sh(shstrndx);
            for (int i = 0; i < shnum; i++)
            {
                var h = Sh(i);
                string name = ReadZ(b, (int)(strtab.off + h.nameOff), 128);
                shs.Add((name, h.type, h.flags, h.addr, h.off, h.size, h.link, h.entsize));
            }
        }

        foreach (var h in shs)
        {
            if ((h.flags & 2) == 0 || h.size == 0) continue; // SHF_ALLOC
            bool nobits = h.type == 8;
            var s = NewSeg(h.name.Length > 0 ? h.name : "seg", h.addr, h.size, b, nobits ? -1 : (long)h.off,
                nobits ? 0 : (long)h.size);
            s.R = true;
            s.W = (h.flags & 1) != 0;
            s.X = (h.flags & 4) != 0;
            s.Class = s.X ? "CODE" : nobits ? "BSS" : s.W ? "DATA" : "CONST";
            s.SegType = s.X ? "Pure code" : nobits ? "Uninitialized" : "Pure data";
            if (db.Segs.Any(o => s.Start < o.End && o.Start < s.End)) continue;
            db.Segs.Add(s);
            log($"  {db.Segs.Count - 1}. Segment oluşturuluyor ({db.AddrStr(s.Start)}-{db.AddrStr(s.End)}) {s.Name} ... OK");
        }
        db.Segs.Sort((a, c) => a.Start.CompareTo(c.Start));
        if (db.Segs.Count > 0) db.ImageBase = db.Segs.Min(s => s.Start);

        // semboller
        var dynsymNames = new List<string>();
        foreach (var h in shs)
        {
            if (h.type != 2 && h.type != 11) continue; // SYMTAB / DYNSYM
            if (h.link >= shs.Count) continue;
            var str = shs[(int)h.link];
            int es = is64 ? 24 : 16;
            long n = (long)h.size / es;
            for (long i = 0; i < n && i < 500000; i++)
            {
                long p = (long)h.off + i * es;
                if (p + es > b.Length) break;
                uint nameOff = U32(b, (int)p);
                ulong value; byte info; ushort shndx;
                if (is64) { info = b[p + 4]; shndx = U16(b, (int)p + 6); value = U64(b, (int)p + 8); }
                else { value = U32(b, (int)p + 4); info = b[p + 12]; shndx = U16(b, (int)p + 14); }
                string name = ReadZ(b, (int)(str.off + nameOff), 512);
                if (h.type == 11) dynsymNames.Add(name);
                if (name.Length == 0 || value == 0 || shndx == 0) continue;
                int st = info & 0xF;
                if (st is not (1 or 2)) continue; // OBJECT / FUNC
                if (!db.IsMapped(value)) continue;
                db.LoaderNames.TryAdd(value, name);
                if (st == 2)
                {
                    db.Entries.Add((value, name, 0));
                    if ((info >> 4) == 1) db.PublicNames.Add(value);
                }
            }
        }

        // PLT/GOT importlari (.rela.plt / .rel.plt)
        foreach (var h in shs)
        {
            if (!(h.name is ".rela.plt" or ".rel.plt")) continue;
            bool rela = h.type == 4;
            int es = is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
            for (long i = 0; i < (long)h.size / es; i++)
            {
                long p = (long)h.off + i * es;
                if (p + es > b.Length) break;
                ulong off = is64 ? U64(b, (int)p) : U32(b, (int)p);
                ulong info = is64 ? U64(b, (int)p + 8) : U32(b, (int)p + 4);
                int sym = (int)(is64 ? info >> 32 : info >> 8);
                if (sym <= 0 || sym >= dynsymNames.Count) continue;
                string name = dynsymNames[sym];
                if (name.Length == 0 || !db.IsMapped(off)) continue;
                var imp = new ImportInfo { Ea = off, Dll = "", Name = name };
                db.Imports.Add(imp);
                db.ImportAt[off] = imp;
                db.LoaderNames[off] = name + "_ptr";
            }
        }

        if (entry != 0 && db.IsMapped(entry))
        {
            db.Entry = entry;
            db.LoaderNames.TryAdd(entry, "start");
            db.PublicNames.Add(entry);
            db.Entries.Add((entry, db.LoaderNames[entry], 0));
        }
    }

    // ================= Yardimcilar =================

    public static ushort U16(byte[] b, int o) => o >= 0 && o + 2 <= b.Length ? BitConverter.ToUInt16(b, o) : (ushort)0;
    public static uint U32(byte[] b, int o) => o >= 0 && o + 4 <= b.Length ? BitConverter.ToUInt32(b, o) : 0;
    public static ulong U64(byte[] b, int o) => o >= 0 && o + 8 <= b.Length ? BitConverter.ToUInt64(b, o) : 0;

    private static ulong AlignUp(ulong v, ulong a) => a == 0 ? v : (v + a - 1) / a * a;

    private static string ReadZ(byte[] b, int o, int max)
    {
        if (o < 0 || o >= b.Length) return "";
        int e = o;
        while (e < b.Length && e - o < max && b[e] != 0) e++;
        return Encoding.UTF8.GetString(b, o, e - o);
    }

    public static (string sha256, string md5, string crc32) Hashes(byte[] b)
    {
        string sha = Convert.ToHexString(SHA256.HashData(b));
        string md5 = Convert.ToHexString(MD5.HashData(b));
        return (sha, md5, Crc32(b).ToString("X8"));
    }

    private static uint[]? _crcTab;
    private static uint Crc32(byte[] data)
    {
        if (_crcTab == null)
        {
            _crcTab = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                _crcTab[i] = c;
            }
        }
        uint crc = 0xFFFFFFFF;
        foreach (byte x in data) crc = _crcTab[(crc ^ x) & 0xFF] ^ (crc >> 8);
        return ~crc;
    }
}
