using System.IO;
using System.Net.Http;
using System.Text;

namespace tlk_hex.Core;

public sealed record PdbSymbol(int Section, uint Offset, string Name, bool IsFunction, bool IsData);

// MSF 7.0 (PDB) okuyucu: genel semboller (S_PUB32) ve global veriler
public static class Pdb
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0");

    private static uint U32(byte[] b, long o) => o + 4 <= b.Length ? BitConverter.ToUInt32(b, (int)o) : 0;
    private static ushort U16(byte[] b, long o) => o + 2 <= b.Length ? BitConverter.ToUInt16(b, (int)o) : (ushort)0;

    public static bool IsPdb(byte[] f) => f.Length > 64 && f.AsSpan(0, Magic.Length).SequenceEqual(Magic);

    private sealed class Msf
    {
        private readonly byte[] _f;
        private readonly uint _bs;
        private readonly uint[] _sizes;
        private readonly List<uint[]> _blocks = new();

        public Msf(byte[] f)
        {
            _f = f;
            _bs = U32(f, 32);
            uint dirBytes = U32(f, 44);
            uint mapAddr = U32(f, 52);
            if (_bs < 512 || _bs > 65536) throw new InvalidDataException("Gecersiz PDB blok boyutu");
            int dirBlocks = (int)((dirBytes + _bs - 1) / _bs);
            var dir = new byte[dirBlocks * _bs];
            for (int i = 0; i < dirBlocks; i++)
            {
                uint blk = U32(f, (long)mapAddr * _bs + i * 4);
                Copy(blk, dir, i * _bs);
            }
            uint n = U32(dir, 0);
            if (n > 100000) throw new InvalidDataException("Gecersiz PDB dizini");
            _sizes = new uint[n];
            for (int i = 0; i < n; i++) _sizes[i] = U32(dir, 4 + i * 4);
            long p = 4 + n * 4;
            for (int i = 0; i < n; i++)
            {
                uint sz = _sizes[i] == 0xFFFFFFFF ? 0 : _sizes[i];
                int cnt = (int)((sz + _bs - 1) / _bs);
                var arr = new uint[cnt];
                for (int k = 0; k < cnt; k++) { arr[k] = U32(dir, p); p += 4; }
                _blocks.Add(arr);
            }
        }

        private void Copy(uint blk, byte[] dst, long dstOff)
        {
            long src = (long)blk * _bs;
            long n = Math.Min(_bs, Math.Min(_f.Length - src, dst.Length - dstOff));
            if (n > 0 && src >= 0) Array.Copy(_f, src, dst, dstOff, n);
        }

        public int Count => _sizes.Length;

        public byte[] Stream(int i)
        {
            if (i < 0 || i >= _sizes.Length || _sizes[i] == 0xFFFFFFFF) return Array.Empty<byte>();
            var res = new byte[_sizes[i]];
            for (int k = 0; k < _blocks[i].Length; k++) Copy(_blocks[i][k], res, (long)k * _bs);
            return res;
        }
    }

    // PDB kimligi (GUID + yas) - exe ile eslesme kontrolu icin
    public static (Guid Guid, uint Age) Identity(byte[] f)
    {
        var msf = new Msf(f);
        var info = msf.Stream(1);
        if (info.Length < 28) return (Guid.Empty, 0);
        return (new Guid(info.AsSpan(12, 16)), U32(info, 8));
    }

    public static List<PdbSymbol> ReadSymbols(byte[] f)
    {
        var res = new List<PdbSymbol>();
        var msf = new Msf(f);
        var dbi = msf.Stream(3);
        if (dbi.Length < 64) return res;
        int symRec = U16(dbi, 20);
        var recs = msf.Stream(symRec);
        long p = 0;
        while (p + 4 <= recs.Length)
        {
            int len = U16(recs, p);
            int kind = U16(recs, p + 2);
            if (len < 2) break;
            long d = p + 4;
            switch (kind)
            {
                case 0x110E: // S_PUB32
                {
                    uint flags = U32(recs, d);
                    uint off = U32(recs, d + 4);
                    int seg = U16(recs, d + 8);
                    string name = Z(recs, d + 10, p + 2 + len);
                    bool code = (flags & 1) != 0 || (flags & 2) != 0;
                    res.Add(new PdbSymbol(seg, off, name, (flags & 2) != 0 || code, !code));
                    break;
                }
                case 0x110C: // S_LDATA32
                case 0x110D: // S_GDATA32
                {
                    uint off = U32(recs, d + 4);
                    int seg = U16(recs, d + 8);
                    string name = Z(recs, d + 10, p + 2 + len);
                    res.Add(new PdbSymbol(seg, off, name, false, true));
                    break;
                }
            }
            p += 2 + len;
        }
        return res;
    }

    private static string Z(byte[] b, long o, long end)
    {
        long e = o;
        end = Math.Min(end, b.Length);
        while (e < end && b[e] != 0) e++;
        return Encoding.UTF8.GetString(b, (int)o, (int)(e - o));
    }

    // ================= MSVC isimlerini sadelestir =================

    public static string Demangle(string n)
    {
        if (n.Length == 0) return n;
        if (n[0] != '?')
        {
            // __stdcall: _Func@8  -> Func
            if (n[0] == '_' && n.LastIndexOf('@') is int at and > 1 && n[(at + 1)..].All(char.IsDigit) && at + 1 < n.Length)
                return n[1..at];
            return n;
        }
        if (n.Contains("?$") || n.Contains("@?")) return Simplify(n); // sablonlar / ic ice: kisa ad
        string prefix = "";
        string body;
        if (n.StartsWith("??0")) { prefix = "ctor"; body = n[3..]; }
        else if (n.StartsWith("??1")) { prefix = "dtor"; body = n[3..]; }
        else if (n.StartsWith("??_G")) { prefix = "sdtor"; body = n[4..]; }
        else if (n.StartsWith("??_E")) { prefix = "vdtor"; body = n[4..]; }
        else if (n.StartsWith("??_7")) { prefix = "vftable"; body = n[4..]; }
        else if (n.StartsWith("??")) return n;
        else body = n[1..];
        int end = body.IndexOf("@@", StringComparison.Ordinal);
        if (end <= 0) return n;
        var parts = body[..end].Split('@');
        if (parts.Any(p => p.Length == 0 || !p.All(c => char.IsLetterOrDigit(c) || c == '_'))) return n;
        Array.Reverse(parts);
        string scope = string.Join("::", parts);
        string last = parts[^1];
        return prefix switch
        {
            "ctor" => scope + "::" + last,
            "dtor" => scope + "::~" + last,
            "sdtor" => scope + "::scalar_deleting_dtor",
            "vdtor" => scope + "::vector_deleting_dtor",
            "vftable" => scope + "::vftable",
            _ => scope,
        };
    }

    private static readonly System.Text.RegularExpressions.Regex Ident = new(@"[A-Za-z_][A-Za-z0-9_]*");

    private static readonly Dictionary<string, string> Ops = new()
    {
        ["2"] = "operator_new", ["3"] = "operator_delete", ["4"] = "operator_assign", ["8"] = "operator_eq", ["9"] = "operator_ne",
        ["A"] = "operator_index", ["R"] = "operator_call", ["_U"] = "operator_new_array", ["_V"] = "operator_delete_array",
        ["5"] = "operator_shr", ["6"] = "operator_shl", ["7"] = "operator_not", ["C"] = "operator_arrow", ["D"] = "operator_deref",
        ["E"] = "operator_inc", ["F"] = "operator_dec", ["G"] = "operator_sub", ["H"] = "operator_add", ["M"] = "operator_lt",
        ["O"] = "operator_gt", ["Y"] = "operator_add_assign", ["B"] = "operator_cast",
    };

    // Sablon / karmasik MSVC isimleri: okunur kisa bicim (Sinif<>::Metot, Fonk<>)
    private static string Simplify(string n)
    {
        if (n.StartsWith("??$"))
        {
            var m = Ident.Match(n, 3);
            return m.Success ? m.Value + "<>" : n;
        }
        if (n.StartsWith("??") && n.Length > 3)
        {
            string code = n[2] == '_' ? n.Substring(2, 2) : n.Substring(2, 1);
            string rest = n[(2 + code.Length)..];
            string cls = rest.StartsWith("?$") ? (Ident.Match(rest, 2) is { Success: true } c1 ? c1.Value + "<>" : "")
                : Ident.Match(rest) is { Success: true } c2 && c2.Index == 0 ? c2.Value : "";
            string what = code switch
            {
                "0" => cls.TrimEnd('<', '>'),
                "1" => "~" + cls.TrimEnd('<', '>'),
                "_G" => "scalar_deleting_dtor",
                "_E" => "vector_deleting_dtor",
                "_7" => "vftable",
                _ => Ops.GetValueOrDefault(code) ?? "op_" + code,
            };
            return cls.Length > 0 ? cls + "::" + what : what;
        }
        // ?Metot@?$Sinif@...  veya  ?Fonk@...
        var f = Ident.Match(n, 1);
        if (!f.Success || f.Index != 1) return n;
        int after = f.Index + f.Length;
        if (n.Length > after + 3 && n.Substring(after, 3) == "@?$" && Ident.Match(n, after + 3) is { Success: true } t)
            return t.Value + "<>::" + f.Value;
        return f.Value;
    }

    // ================= Bulma / indirme =================

    public static string CacheDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tlk-hex", "symbols");

    public static string? Key(Db db) =>
        db.PdbGuid == Guid.Empty ? null : db.PdbGuid.ToString("N").ToUpperInvariant() + db.PdbAge.ToString("X");

    public static string PdbFileName(Db db) => Path.GetFileName(db.PdbPath.Replace('/', '\\'));

    // Yerel: tam yol, exe yaninda, onbellek
    public static string? FindLocal(Db db)
    {
        if (db.PdbPath.Length == 0) return null;
        string name = PdbFileName(db);
        var cands = new List<string>();
        try { if (Path.IsPathRooted(db.PdbPath)) cands.Add(db.PdbPath); } catch { }
        cands.Add(Path.Combine(Path.GetDirectoryName(db.FilePath) ?? "", name));
        if (Key(db) is string k) cands.Add(Path.Combine(CacheDir, name, k, name));
        foreach (var c in cands)
        {
            try
            {
                if (!File.Exists(c)) continue;
                var bytes = File.ReadAllBytes(c);
                if (!IsPdb(bytes)) continue;
                var (g, _) = Identity(bytes);
                if (db.PdbGuid == Guid.Empty || g == db.PdbGuid) return c;
            }
            catch { }
        }
        return null;
    }

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(120) };

    // Microsoft sembol sunucusundan indir (yalnizca PDB adi + GUID gonderilir)
    public static async Task<string?> DownloadAsync(Db db, Action<string> log, CancellationToken ct)
    {
        string? key = Key(db);
        if (key == null || db.PdbPath.Length == 0) return null;
        string name = PdbFileName(db);
        string url = $"https://msdl.microsoft.com/download/symbols/{Uri.EscapeDataString(name)}/{key}/{Uri.EscapeDataString(name)}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.UserAgent.ParseAdd("Microsoft-Symbol-Server/10.0.0.0");
        log($"Sembol indiriliyor: {name} ({key})");
        using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode)
        {
            log($"  Sembol sunucusunda yok (HTTP {(int)resp.StatusCode}).");
            return null;
        }
        var data = await resp.Content.ReadAsByteArrayAsync(ct);
        if (!IsPdb(data))
        {
            log("  Gelen dosya PDB degil (sikistirilmis olabilir); atlandi.");
            return null;
        }
        string dir = Path.Combine(CacheDir, name, key);
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, name);
        await File.WriteAllBytesAsync(path, data, ct);
        log($"  {data.Length / 1024:N0} KB indirildi: {path}");
        return path;
    }

    // Sembolleri veritabanina uygula; fonksiyon adreslerini dondurur
    public static (int Names, List<ulong> Funcs) Apply(Db db, List<PdbSymbol> syms)
    {
        var funcs = new List<ulong>();
        int n = 0;
        var used = new HashSet<string>(db.LoaderNames.Values);
        foreach (var s in syms)
        {
            if (s.Section <= 0 || s.Section > db.PeSections.Count) continue;
            ulong ea = db.ImageBase + db.PeSections[s.Section - 1] + s.Offset;
            if (!db.IsMapped(ea) || string.IsNullOrEmpty(s.Name)) continue;
            if (db.ImportAt.ContainsKey(ea)) continue;
            if (s.Name.StartsWith("__imp_")) continue;
            string name = Demangle(s.Name);
            if (!db.IsValidName(name)) name = s.Name;
            if (!db.IsValidName(name)) continue;
            if (db.LoaderNames.ContainsKey(ea))
            {
                if (s.IsFunction && db.IsCodeSeg(ea)) funcs.Add(ea);
                continue;
            }
            string un = name;
            for (int i = 1; used.Contains(un); i++) un = name + "_" + i;
            used.Add(un);
            db.LoaderNames[ea] = un;
            n++;
            if (s.IsFunction && db.IsCodeSeg(ea)) funcs.Add(ea);
        }
        db.InvalidateNames();
        return (n, funcs);
    }
}
