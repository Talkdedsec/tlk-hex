using System.IO;

namespace tlk_hex.Core;

// Acik dosyanin tum durumu: veritabani + analiz + listing
public sealed class Session
{
    public Db Db { get; }
    public Disasm Dis { get; }
    public AutoAnalysis Au { get; }
    public Listing List { get; }
    public Pseudo Pseudo { get; }
    public LoadOptions Opt { get; }
    public ulong? StartEa { get; private set; }

    private Session(Db db, LoadOptions opt)
    {
        Db = db;
        Opt = opt;
        Dis = new Disasm(db);
        Au = new AutoAnalysis(db, Dis);
        List = new Listing(db, Dis);
        Pseudo = new Pseudo(db, Dis);
    }

    public static Session Open(string path, LoadOptions opt, IdbFile? idb, int minStr,
        Action<string> log, Action<string> progress, Action<Listing>? configure = null)
    {
        log($"Dosya yükleniyor: {path}");
        var db = Loaders.Load(path, opt, log);
        log($"Biçim: {db.Format}  ({db.Machine}, {db.Bitness}-bit)");
        var s = new Session(db, opt);
        s.Au.Progress = progress;
        s.Au.MinStrLen = minStr;

        if (idb != null)
        {
            IdbStore.ApplyPatches(db, idb);
            if (idb.Patches.Count > 0) log($"  {idb.Patches.Count} yamalı bayt uygulandı.");
        }

        // yerel / onbellekteki PDB
        try
        {
            if (db.LoaderId == "pe" && Pdb.FindLocal(db) is string pdbPath)
            {
                var syms = Pdb.ReadSymbols(File.ReadAllBytes(pdbPath));
                var (n, funcs) = Pdb.Apply(db, syms);
                s.Au.ExtraSeeds.AddRange(funcs);
                db.SymbolSource = pdbPath;
                log($"Semboller yüklendi: {Path.GetFileName(pdbPath)} ({n:N0} isim, {funcs.Count:N0} fonksiyon)");
            }
        }
        catch (Exception ex) { log("PDB okunamadı: " + ex.Message); }

        if (opt.Analyze)
        {
            log("Otomatik analiz başladı...");
            progress("AU: analiz ediliyor");
            s.Au.Run(log);
        }
        else
        {
            s.Au.Run(_ => { });
        }

        if (idb != null)
        {
            IdbStore.ApplyUser(db, s.Au, idb);
            s.Au.FinalizeFunctions();
            s.Au.BuildStrings();
            s.StartEa = IdbStore.LastEa(idb);
            log($"Kayıtlı veritabanı yüklendi: {idb.Ops.Count} işlem, {idb.Names.Count} isim, {idb.Comments.Count} yorum.");
        }

        progress("Listing hazırlanıyor...");
        configure?.Invoke(s.List);
        s.List.Build();
        log($"Listing: {s.List.TotalLines:N0} satır.");
        return s;
    }

    // Analizden sonra PDB uygula (indirme veya elle secim)
    public (int Names, int NewFuncs) ApplyPdb(string path)
    {
        var syms = Pdb.ReadSymbols(File.ReadAllBytes(path));
        var (n, funcs) = Pdb.Apply(Db, syms);
        int nf = Au.AddFunctions(funcs);
        Db.SymbolSource = path;
        Au.BuildStrings();
        Rebuild();
        return (n, nf);
    }

    // Kullanici islemi sonrasi yeniden duzen
    public void Rebuild()
    {
        Au.FinalizeFunctions();
        Db.InvalidateNames();
        List.Build();
    }

    public ulong DefaultEa()
    {
        if (StartEa is ulong se && Db.IsMapped(se)) return se;
        if (Db.Entry != ulong.MaxValue && Db.IsMapped(Db.Entry)) return Db.Entry;
        var fs = Db.Segs.FirstOrDefault(s => s.X) ?? Db.Segs.FirstOrDefault();
        return fs?.Start ?? 0;
    }

    // Eski bulgu motoru icin model
    public AnalysisResult ToResult()
    {
        var r = new AnalysisResult
        {
            FilePath = Db.FilePath,
            FileSize = Db.FileBytes.Length,
            Architecture = Db.Machine,
            FileType = Db.FileType,
            IsDotNet = Db.IsDotNet,
            IsSigned = Db.IsSigned,
            Subsystem = Db.Subsystem,
            Timestamp = Db.Timestamp,
            EntryPoint = Db.Entry == ulong.MaxValue ? "-" : "0x" + Db.AddrStr(Db.Entry),
            ImageBase = "0x" + Db.Hx(Db.ImageBase),
        };
        foreach (var s in Db.Segs)
        {
            var flags = new List<string>();
            if (s.X) flags.Add("X");
            if (s.R) flags.Add("R");
            if (s.W) flags.Add("W");
            r.Sections.Add(new SectionInfo
            {
                Name = s.Name,
                VirtualAddress = "0x" + Db.Hx(s.Start),
                VirtualSize = "0x" + Db.Hx((ulong)s.Size),
                RawSize = "0x" + s.InitSize.ToString("X"),
                Entropy = Entropy(s).ToString("0.00", System.Globalization.CultureInfo.InvariantCulture),
                Flags = string.Join(" | ", flags),
            });
        }
        foreach (var i in Db.Imports) r.Imports.Add(new ImportEntry { Dll = i.Dll, Function = i.Name });
        foreach (var e in Db.Exports) r.Exports.Add(new ExportEntry { Function = e.Name, Ordinal = e.Ordinal.ToString() });
        foreach (var f in Db.Funcs.Values) r.Functions.Add(new FunctionEntry { Address = "0x" + Db.Hx(f.Start) });
        foreach (var s in Db.Strings) r.Strings.Add(new StringEntry { Value = s.Value, Encoding = s.Type, Length = s.Value.Length });
        r.Findings = FindingsEngine.Analyze(r);
        return r;
    }

    private static double Entropy(Segment s)
    {
        if (s.InitSize <= 0) return 0;
        var c = new long[256];
        int n = Math.Min(s.InitSize, 1_000_000);
        for (int i = 0; i < n; i++) c[s.Data[i]]++;
        double e = 0;
        foreach (var x in c)
        {
            if (x == 0) continue;
            double p = (double)x / n;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    public void ExportAsm(string path, bool lst)
    {
        using var w = new StreamWriter(path);
        List.Export(w, lst);
    }

    // IDA DIF bicimi
    public void ExportDif(string path)
    {
        using var w = new StreamWriter(path);
        w.WriteLine("This difference file was created by tlk-hex");
        w.WriteLine();
        w.WriteLine(Path.GetFileName(Db.FilePath));
        foreach (var kv in Db.Patches.OrderBy(k => k.Key))
        {
            long off = Db.FileOffsetOf(kv.Key);
            if (off < 0 || !Db.TryByte(kv.Key, out var nb)) continue;
            w.WriteLine($"{off:X8}: {kv.Value:X2} {nb:X2}");
        }
    }

    public int ApplyPatchesToFile(string outPath)
    {
        var bytes = (byte[])Db.FileBytes.Clone();
        int n = 0;
        foreach (var kv in Db.Patches)
        {
            long off = Db.FileOffsetOf(kv.Key);
            if (off < 0 || off >= bytes.Length || !Db.TryByte(kv.Key, out var nb)) continue;
            bytes[off] = nb;
            n++;
        }
        File.WriteAllBytes(outPath, bytes);
        return n;
    }
}
