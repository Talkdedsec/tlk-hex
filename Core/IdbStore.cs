using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace tlk_hex.Core;

// Kullanici degisikliklerinin kaydi (isimler, yorumlar, C/D/U/A/P islemleri, yamalar)
public sealed class IdbFile
{
    public int Version { get; set; } = 1;
    public string FilePath { get; set; } = "";
    public long FileSize { get; set; }
    public string Loader { get; set; } = "";
    public int BinBitness { get; set; }
    public ulong BinBase { get; set; }
    public Dictionary<string, string> Names { get; set; } = new();
    public Dictionary<string, string> Comments { get; set; } = new();
    public Dictionary<string, string> RepComments { get; set; } = new();
    public List<string> DecimalOps { get; set; } = new();
    public Dictionary<string, string> Patches { get; set; } = new();   // ea -> "orijinal,yeni"
    public List<UserOp> Ops { get; set; } = new();
    public List<Bookmark> Marks { get; set; } = new();
    public Dictionary<string, List<string>> Folders { get; set; } = new();
    public Dictionary<string, string> StackNames { get; set; } = new();  // "fonksiyon:L" -> isim
    public string? LastEa { get; set; }
}

public static class IdbStore
{
    private static readonly string Dir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tlk-hex", "idb");

    public static string PathFor(string file)
    {
        string full = Path.GetFullPath(file).ToLowerInvariant();
        string h = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(full)))[..12];
        string name = Path.GetFileName(file);
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return Path.Combine(Dir, $"{name}.{h}.tlkdb");
    }

    public static bool Exists(string file) => File.Exists(PathFor(file));

    public static IdbFile? Load(string file)
    {
        try
        {
            var p = PathFor(file);
            if (!File.Exists(p)) return null;
            return JsonSerializer.Deserialize<IdbFile>(File.ReadAllText(p));
        }
        catch { return null; }
    }

    public static void Delete(string file)
    {
        try
        {
            var p = PathFor(file);
            if (File.Exists(p)) File.Delete(p);
        }
        catch { }
    }

    private static string K(ulong ea) => ea.ToString("X");
    private static ulong P(string s) => ulong.Parse(s, System.Globalization.NumberStyles.HexNumber);

    public static void Save(Db db, LoadOptions opt, ulong lastEa)
    {
        var f = new IdbFile
        {
            FilePath = db.FilePath,
            FileSize = db.FileBytes.Length,
            Loader = db.LoaderId,
            BinBitness = opt.BinBitness,
            BinBase = opt.BinBase,
            Ops = db.Ops,
            Marks = db.Marks,
            LastEa = K(lastEa),
        };
        foreach (var kv in db.UserNames) f.Names[K(kv.Key)] = kv.Value;
        foreach (var kv in db.Comments) f.Comments[K(kv.Key)] = kv.Value;
        foreach (var kv in db.RepComments) f.RepComments[K(kv.Key)] = kv.Value;
        foreach (var e in db.DecimalOps) f.DecimalOps.Add(K(e));
        foreach (var kv in db.Patches)
            if (db.TryByte(kv.Key, out var nb)) f.Patches[K(kv.Key)] = $"{kv.Value:X2},{nb:X2}";
        foreach (var kv in db.Folders) f.Folders[kv.Key] = kv.Value.Select(K).ToList();
        foreach (var kv in db.StackNames) f.StackNames[$"{K(kv.Key.Func)}:{kv.Key.L}"] = kv.Value;

        Directory.CreateDirectory(Dir);
        File.WriteAllText(PathFor(db.FilePath), JsonSerializer.Serialize(f, new JsonSerializerOptions { WriteIndented = true }));
        db.Dirty = false;
    }

    // Analizden ONCE: yamalar
    public static void ApplyPatches(Db db, IdbFile f)
    {
        foreach (var kv in f.Patches)
        {
            var parts = kv.Value.Split(',');
            if (parts.Length != 2) continue;
            db.PatchByte(P(kv.Key), Convert.ToByte(parts[1], 16));
        }
    }

    // Analizden SONRA: islemler, isimler, yorumlar
    public static void ApplyUser(Db db, AutoAnalysis au, IdbFile f)
    {
        foreach (var op in f.Ops)
        {
            try { au.Apply(op); } catch { }
            db.Ops.Add(op);
        }
        foreach (var kv in f.Names) db.UserNames[P(kv.Key)] = kv.Value;
        foreach (var kv in f.Comments) db.Comments[P(kv.Key)] = kv.Value;
        foreach (var kv in f.RepComments) db.RepComments[P(kv.Key)] = kv.Value;
        foreach (var e in f.DecimalOps) db.DecimalOps.Add(P(e));
        db.Marks = f.Marks ?? new();
        foreach (var kv in f.Folders) db.Folders[kv.Key] = kv.Value.Select(P).ToList();
        foreach (var kv in f.StackNames ?? new())
        {
            var parts = kv.Key.Split(':');
            if (parts.Length == 2 && int.TryParse(parts[1], out var l)) db.StackNames[(P(parts[0]), l)] = kv.Value;
        }
        db.InvalidateNames();
        db.Dirty = false;
    }

    public static ulong? LastEa(IdbFile f) => f.LastEa != null ? P(f.LastEa) : null;
}
