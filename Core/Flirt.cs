using System.IO;
using System.Text.Json;
using Iced.Intel;

namespace tlk_hex.Core;

// Hafif kutuphane imzasi (FLIRT benzeri): bir fonksiyonun ilk baytlarindan
// desen + maske uretir; adrese bagli baytlar (dallanma hedefi, RIP-goreli yer
// degistirme) joker isaretlenir. Bilinen isimli bir dosyadan imza uret, isimsiz
// bir dosyaya uygula.
public sealed class Signature
{
    public byte[] Pattern = Array.Empty<byte>();
    public byte[] Mask = Array.Empty<byte>();    // 0xFF = sabit, 0x00 = joker
    public string Name = "";
    public int Fixed;                            // sabit (maskeli) bayt sayisi

    public bool Matches(byte[] win)
    {
        if (win.Length < Pattern.Length) return false;
        for (int i = 0; i < Pattern.Length; i++)
            if (Mask[i] != 0 && win[i] != Pattern[i]) return false;
        return true;
    }
}

public static class Flirt
{
    private const int Window = 32;   // imza penceresi (bayt)
    private const int MinFixed = 8;  // en az sabit bayt (yanlis eslesmeyi onler)

    // ---- pencere baytlari ve maske ----

    // Bir fonksiyonun ilk <=32 baytini oku; maske doldur (true = sabit).
    private static (byte[] pat, byte[] mask) Window32(Db db, Disasm dis, Function f)
    {
        var pat = new byte[Window];
        var mask = new byte[Window];
        int got = 0;
        ulong ea = f.Start;
        while (got < Window && ea < f.End)
        {
            if (!dis.TryDecode(ea, out var ins)) break;
            int len = ins.Length;
            if (len <= 0) break;
            bool wildBranch = IsNearBranch(ins);
            int relBytes = wildBranch ? (len >= 5 ? 4 : 1) : 0;
            bool wildRip = !wildBranch && ins.IsIPRelativeMemoryOperand && !HasImmediate(ins);
            for (int k = 0; k < len && got < Window; k++, got++)
            {
                if (!db.TryByte(ea + (ulong)k, out var b)) { b = 0; }
                pat[got] = b;
                bool wild = (wildBranch && k >= len - relBytes) || (wildRip && k >= len - 4);
                mask[got] = wild ? (byte)0 : (byte)0xFF;
            }
            ea += (ulong)len;
        }
        if (got < Window) { Array.Resize(ref pat, got); Array.Resize(ref mask, got); }
        return (pat, mask);
    }

    private static bool IsNearBranch(in Instruction ins)
    {
        for (int i = 0; i < ins.OpCount; i++)
            if (ins.GetOpKind(i) is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
                return true;
        return false;
    }

    private static bool HasImmediate(in Instruction ins)
    {
        for (int i = 0; i < ins.OpCount; i++)
            switch (ins.GetOpKind(i))
            {
                case OpKind.Immediate8:
                case OpKind.Immediate8_2nd:
                case OpKind.Immediate16:
                case OpKind.Immediate32:
                case OpKind.Immediate64:
                case OpKind.Immediate8to16:
                case OpKind.Immediate8to32:
                case OpKind.Immediate8to64:
                case OpKind.Immediate32to64:
                    return true;
            }
        return false;
    }

    private static int CountFixed(byte[] mask)
    {
        int n = 0;
        foreach (var m in mask) if (m != 0) n++;
        return n;
    }

    // ---- uretim ----

    // Isimli, thunk/import olmayan fonksiyonlardan imza uret.
    public static List<Signature> Generate(Db db, Disasm dis)
    {
        var sigs = new List<Signature>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var f in db.FuncList)
        {
            if (f.IsThunk) continue;
            if (db.IsDummyName(f.Start)) continue;
            var name = db.NameAt(f.Start);
            if (string.IsNullOrEmpty(name) || name!.StartsWith("sub_") || name.StartsWith("loc_")) continue;
            if (!seen.Add(name)) continue;                 // ayni isimden tek imza
            var (pat, mask) = Window32(db, dis, f);
            int fix = CountFixed(mask);
            if (pat.Length < MinFixed || fix < MinFixed) continue;
            sigs.Add(new Signature { Pattern = pat, Mask = mask, Name = name, Fixed = fix });
        }
        return sigs;
    }

    // ---- uygulama ----

    // Isimsiz (dummy) fonksiyonlari imzalarla adlandir. Uygulanan sayisini dondurur.
    public static int Apply(Db db, Disasm dis, IReadOnlyList<Signature> sigs, Action<ulong, string> name)
    {
        // uzun (daha ayirt edici) imzalar once
        var ordered = sigs.OrderByDescending(s => s.Fixed).ToList();
        int applied = 0;
        foreach (var f in db.FuncList)
        {
            if (!db.IsDummyName(f.Start)) continue;
            var (win, _) = Window32(db, dis, f);         // aday baytlar (hepsi sabit)
            Signature? best = null;
            bool ambiguous = false;
            foreach (var s in ordered)
            {
                if (!s.Matches(win)) continue;
                if (best == null) best = s;
                else if (best.Fixed == s.Fixed && best.Name != s.Name) { ambiguous = true; break; }
                else break; // ordered: ilk eslesme en ayirt edici olan
            }
            if (best != null && !ambiguous)
            {
                name(f.Start, best.Name);
                applied++;
            }
        }
        return applied;
    }

    // ---- serilestirme (.sig = JSON) ----

    private sealed record Dto(string n, string p, string m);

    public static void Save(string path, IReadOnlyList<Signature> sigs)
    {
        var dto = sigs.Select(s => new Dto(s.Name, Convert.ToHexString(s.Pattern), Convert.ToHexString(s.Mask))).ToList();
        File.WriteAllText(path, JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = false }));
    }

    public static List<Signature> Load(string path)
    {
        var dto = JsonSerializer.Deserialize<List<Dto>>(File.ReadAllText(path)) ?? new();
        var list = new List<Signature>(dto.Count);
        foreach (var d in dto)
        {
            var p = Convert.FromHexString(d.p);
            var m = Convert.FromHexString(d.m);
            if (p.Length != m.Length || p.Length == 0) continue;
            list.Add(new Signature { Pattern = p, Mask = m, Name = d.n, Fixed = CountFixed(m) });
        }
        return list;
    }
}
