using System.Text;

namespace tlk_hex.Core;

// Bayt basina tutulan oge turu (IDA'daki flags dizisinin sade hali)
public enum ItemKind : byte
{
    Unknown = 0, Code = 1, Byte = 2, Word = 3, Dword = 4, Qword = 5, Oword = 6,
    Float = 7, Double = 8, Ascii = 9, Utf16 = 10, Align = 11, Extern = 12,
}

public static class FF
{
    public const byte KindMask = 0x0F;
    public const byte Offset = 0x20;   // veri ogesi bir adres (off_)
    public const byte Tail = 0x40;     // ogenin devami
    public const byte Head = 0x80;     // ogenin ilk bayti
}

public enum XrefType : byte { Call = (byte)'p', Jump = (byte)'j', Offset = (byte)'o', Read = (byte)'r', Write = (byte)'w' }

public readonly record struct Xref(ulong From, ulong To, XrefType Type)
{
    public bool IsCode => Type is XrefType.Call or XrefType.Jump;
}

public sealed class Segment
{
    public string Name = "";
    public ulong Start, End;
    public byte[] Data = Array.Empty<byte>();
    public int InitSize;                 // dosyadan gelen (baslatilmis) kisim
    public byte[] F = Array.Empty<byte>();
    public int[] Owner = Array.Empty<int>(); // kod segmentlerinde: bayt -> fonksiyon indeksi
    public bool R, W, X;
    public string Class = "DATA";        // CODE / DATA / BSS / CONST / XTRN
    public string SegType = "Pure data"; // IDA'daki "Segment type"
    public long FileOffset = -1;
    public int Index;
    public List<string> Info = new();    // segment basligindaki ek yorumlar
    public bool IsExtern;                // .idata (import) segmenti

    public long Size => (long)(End - Start);
    public bool Contains(ulong ea) => ea >= Start && ea < End;
    public bool IsInit(long off) => off < InitSize;
    public string AsmName => Name.StartsWith('.') ? "_" + Name[1..] : Name;
}

public sealed class Function
{
    public ulong Start, End;
    public List<(ulong Start, ulong End)> Chunks = new();
    public List<ulong> Instrs = new();
    public bool BpBased, NoReturn, IsThunk, IsLibrary, HasRet;
    public int FrRegs;
    public int BpDelta = int.MinValue;
    public int Purge;
    public ulong ThunkTarget;
    public int Index;
    public SortedDictionary<int, int> Vars = new();        // L (girise gore) -> boyut
    public Dictionary<ulong, int> SpAt = new();              // komut -> sp farki
    public List<ulong> Blocks = new();                       // graph icin (lazy)

    public int LocalsSize
    {
        get
        {
            int m = 0;
            foreach (var l in Vars.Keys) { int o = l + FrRegs; if (o < 0) m = Math.Max(m, -o); }
            return m;
        }
    }

    public int ArgsSize(int ptr)
    {
        int m = 0;
        foreach (var kv in Vars) if (kv.Key >= ptr) m = Math.Max(m, kv.Key - ptr + kv.Value);
        return m;
    }
}

public sealed class ImportInfo
{
    public ulong Ea;
    public string Dll = "";
    public string Name = "";
    public int Ordinal = -1;
    public bool Delay;
}

public sealed class ExportInfo
{
    public ulong Ea;
    public string Name = "";
    public int Ordinal;
    public string? Forwarder;
}

public sealed class StrLit
{
    public ulong Ea;
    public int Len;          // bayt (sonlandirici dahil)
    public string Type = "C";
    public string Value = "";
}

public sealed class UserOp
{
    public string Op { get; set; } = "";
    public ulong Ea { get; set; }
    public int Arg { get; set; }
}

public sealed class Bookmark
{
    public ulong Ea { get; set; }
    public string Text { get; set; } = "";
}

public sealed class Db
{
    // ---- dosya ----
    public string FilePath = "";
    public byte[] FileBytes = Array.Empty<byte>();
    public string Format = "";
    public string LoaderId = "";
    public int Bitness = 64;
    public ulong ImageBase;
    public ulong Entry = ulong.MaxValue;
    public bool IsDotNet, IsSigned;
    public string Subsystem = "", Timestamp = "", FileType = "", OsType = "", AppType = "", PdbPath = "";
    public string Machine = "";
    public Guid PdbGuid = Guid.Empty;
    public uint PdbAge;
    public List<uint> PeSections = new();        // PE section RVA'lari (PDB segment numaralari icin)
    public string? SymbolSource;                  // yuklenen PDB yolu
    public bool CanDisasm = true;

    // ---- icerik ----
    public List<Segment> Segs = new();
    public List<ImportInfo> Imports = new();
    public Dictionary<ulong, ImportInfo> ImportAt = new();
    public List<ExportInfo> Exports = new();
    public List<(ulong Ea, string Name, int Ordinal)> Entries = new();
    public Dictionary<ulong, string> LoaderNames = new();
    public Dictionary<ulong, string> UserNames = new();
    public Dictionary<ulong, string> Comments = new();
    public Dictionary<ulong, string> RepComments = new();
    public Dictionary<ulong, string> AutoComments = new();
    public HashSet<ulong> DecimalOps = new();
    public Dictionary<ulong, byte> Patches = new();          // ea -> orijinal bayt
    public HashSet<ulong> Relocs = new();
    public HashSet<ulong> PublicNames = new();
    public Dictionary<ulong, ulong> PdataEnds = new();       // fonksiyon baslangici -> bitis
    public HashSet<ulong> RvaItems = new();                  // dd rva loc_X
    public Dictionary<ulong, ulong> RelItems = new();        // dd loc_X - tablo
    public Dictionary<ulong, string> StrNames = new();
    public Dictionary<(ulong Func, int L), string> StackNames = new();
    public Dictionary<ulong, string> AutoLabels = new();     // jpt_ gibi analiz isimleri
    private readonly HashSet<string> _strNameSet = new();

    public Dictionary<ulong, Function> Funcs = new();
    public List<Function> FuncList = new();
    public List<(ulong S, ulong E, Function F)> ChunkIdx = new();

    public Dictionary<ulong, List<Xref>> XTo = new();
    public Dictionary<ulong, List<Xref>> XFrom = new();

    public List<StrLit> Strings = new();
    public List<UserOp> Ops = new();
    public List<Bookmark> Marks = new();
    public Dictionary<string, List<ulong>> Folders = new();

    public bool Dirty;
    private Dictionary<string, ulong>? _nameIdx;

    public int Ptr => Bitness / 8;
    public int AddrDigits => Bitness == 64 ? 16 : 8;

    // ================= Adres / segment =================

    private int _lastSeg;
    public Segment? SegOf(ulong ea)
    {
        var segs = Segs;
        if (_lastSeg < segs.Count && segs[_lastSeg].Contains(ea)) return segs[_lastSeg];
        int lo = 0, hi = segs.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            var s = segs[mid];
            if (ea < s.Start) hi = mid - 1;
            else if (ea >= s.End) lo = mid + 1;
            else { _lastSeg = mid; return s; }
        }
        return null;
    }

    public bool IsMapped(ulong ea) => SegOf(ea) != null;

    public bool IsCodeSeg(ulong ea) => SegOf(ea) is { X: true };

    public bool TryByte(ulong ea, out byte b)
    {
        b = 0;
        var s = SegOf(ea);
        if (s == null) return false;
        long o = (long)(ea - s.Start);
        if (!s.IsInit(o)) return false;
        b = s.Data[o];
        return true;
    }

    public bool TryRead(ulong ea, int size, out ulong v)
    {
        v = 0;
        var s = SegOf(ea);
        if (s == null) return false;
        long o = (long)(ea - s.Start);
        if (o + size > s.InitSize) return false;
        for (int i = size - 1; i >= 0; i--) v = (v << 8) | s.Data[o + i];
        return true;
    }

    public bool TryReadPtr(ulong ea, out ulong v) => TryRead(ea, Ptr, out v);

    public long FileOffsetOf(ulong ea)
    {
        var s = SegOf(ea);
        if (s == null || s.FileOffset < 0) return -1;
        long o = (long)(ea - s.Start);
        return o < s.InitSize ? s.FileOffset + o : -1;
    }

    public ulong? EaOfFileOffset(long off)
    {
        foreach (var s in Segs)
            if (s.FileOffset >= 0 && off >= s.FileOffset && off < s.FileOffset + s.InitSize)
                return s.Start + (ulong)(off - s.FileOffset);
        return null;
    }

    // ================= Ogeler =================

    public byte Flag(ulong ea)
    {
        var s = SegOf(ea);
        return s == null ? (byte)0 : s.F[ea - s.Start];
    }

    public ItemKind KindAt(ulong ea) => (ItemKind)(Flag(ea) & FF.KindMask);

    public bool IsHead(ulong ea) => (Flag(ea) & FF.Head) != 0;

    public bool IsCode(ulong ea) => (Flag(ea) & (FF.Head | FF.KindMask)) == (FF.Head | (byte)ItemKind.Code);

    public ulong HeadOf(ulong ea)
    {
        var s = SegOf(ea);
        if (s == null) return ea;
        long o = (long)(ea - s.Start);
        while (o > 0 && (s.F[o] & FF.Tail) != 0) o--;
        return s.Start + (ulong)o;
    }

    public static int ItemSize(Segment s, long off)
    {
        if ((s.F[off] & FF.Head) == 0) return 1;
        long n = 1;
        while (off + n < s.Size && (s.F[off + n] & FF.Tail) != 0) n++;
        return (int)n;
    }

    public int ItemSize(ulong ea)
    {
        var s = SegOf(ea);
        return s == null ? 1 : ItemSize(s, (long)(ea - s.Start));
    }

    public ulong NextHead(ulong ea)
    {
        var s = SegOf(ea);
        if (s == null) return ea + 1;
        return ea + (ulong)ItemSize(s, (long)(ea - s.Start));
    }

    public bool RangeFree(Segment s, long off, int len)
    {
        if (off < 0 || off + len > s.Size) return false;
        for (int i = 0; i < len; i++) if (s.F[off + i] != 0) return false;
        return true;
    }

    public void SetItem(Segment s, long off, int len, ItemKind k, bool isOffset = false)
    {
        s.F[off] = (byte)(FF.Head | (byte)k | (isOffset ? FF.Offset : 0));
        for (int i = 1; i < len && off + i < s.Size; i++) s.F[off + i] = (byte)(FF.Tail | (byte)k);
    }

    public void ClearItem(Segment s, long off)
    {
        int n = ItemSize(s, off);
        for (int i = 0; i < n; i++)
        {
            s.F[off + i] = 0;
            if (s.Owner.Length > 0) s.Owner[off + i] = -1;
        }
    }

    // ================= Xref =================

    public void AddXref(ulong from, ulong to, XrefType t)
    {
        if (!XTo.TryGetValue(to, out var lt)) XTo[to] = lt = new List<Xref>(2);
        foreach (var x in lt) if (x.From == from && x.Type == t) return;
        var xr = new Xref(from, to, t);
        lt.Add(xr);
        if (!XFrom.TryGetValue(from, out var lf)) XFrom[from] = lf = new List<Xref>(2);
        lf.Add(xr);
    }

    public void RemoveXrefsFrom(ulong from)
    {
        if (!XFrom.TryGetValue(from, out var lf)) return;
        foreach (var x in lf)
            if (XTo.TryGetValue(x.To, out var lt))
            {
                lt.RemoveAll(y => y.From == from);
                if (lt.Count == 0) XTo.Remove(x.To);
            }
        XFrom.Remove(from);
    }

    public IReadOnlyList<Xref> XrefsTo(ulong ea) => XTo.TryGetValue(ea, out var l) ? l : Array.Empty<Xref>();
    public IReadOnlyList<Xref> XrefsFrom(ulong ea) => XFrom.TryGetValue(ea, out var l) ? l : Array.Empty<Xref>();

    // ================= Fonksiyonlar =================

    public Function? FuncAt(ulong ea)
    {
        var idx = ChunkIdx;
        int lo = 0, hi = idx.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            var c = idx[mid];
            if (ea < c.S) hi = mid - 1;
            else if (ea >= c.E) lo = mid + 1;
            else return c.F;
        }
        // henuz bolunmemis (analiz sirasinda) - sahiplik dizisinden
        var s = SegOf(ea);
        if (s != null && s.Owner.Length > 0)
        {
            int ow = s.Owner[ea - s.Start];
            if (ow >= 0 && ow < FuncList.Count) return FuncList[ow];
        }
        return null;
    }

    public void RebuildChunkIndex()
    {
        ChunkIdx.Clear();
        foreach (var f in FuncList)
            foreach (var c in f.Chunks) ChunkIdx.Add((c.Start, c.End, f));
        ChunkIdx.Sort((a, b) => a.S.CompareTo(b.S));
        // cakisanlari ayikla
        for (int i = 1; i < ChunkIdx.Count; i++)
            if (ChunkIdx[i].S < ChunkIdx[i - 1].E)
                ChunkIdx[i] = (ChunkIdx[i - 1].E, Math.Max(ChunkIdx[i].E, ChunkIdx[i - 1].E), ChunkIdx[i].F);
        ChunkIdx.RemoveAll(c => c.E <= c.S);
    }

    // ================= Isimler =================

    public static string Hx(ulong v) => v.ToString("X");

    // IDA sayi bicimi: 0-9 ondalik, digerleri 0Ah gibi
    public static string HexNum(ulong v)
    {
        if (v < 10) return v.ToString();
        string h = v.ToString("X");
        return (char.IsLetter(h[0]) ? "0" : "") + h + "h";
    }

    public static string HexNumSigned(long v) => v < 0 ? "-" + HexNum((ulong)(-v)) : HexNum((ulong)v);

    public string AddrStr(ulong ea) => ea.ToString(Bitness == 64 ? "X16" : "X8");

    public string? NameAt(ulong ea)
    {
        if (UserNames.TryGetValue(ea, out var n)) return n;
        if (LoaderNames.TryGetValue(ea, out n)) return n;
        if (AutoLabels.TryGetValue(ea, out n)) return n;
        return AutoName(ea, false);
    }

    public bool IsDummyName(ulong ea) => !UserNames.ContainsKey(ea) && !LoaderNames.ContainsKey(ea)
                                         && !StrNames.ContainsKey(ea);

    public string? AutoName(ulong ea, bool force)
    {
        var s = SegOf(ea);
        if (s == null) return null;
        long o = (long)(ea - s.Start);
        byte fl = s.F[o];
        if ((fl & FF.Tail) != 0) return null;

        if (Funcs.TryGetValue(ea, out var f))
        {
            if (f.IsThunk && f.ThunkTarget != 0 && f.ThunkTarget != ea)
            {
                var tn = NameAt(f.ThunkTarget);
                if (tn != null && !tn.StartsWith("j_") && !tn.StartsWith("sub_"))
                    return (LoaderId == "elf" ? "_" : "j_") + tn;
            }
            return "sub_" + Hx(ea);
        }

        if (!force && !XTo.ContainsKey(ea)) return null;

        var k = (ItemKind)(fl & FF.KindMask);
        bool isOff = (fl & FF.Offset) != 0;
        string h = Hx(ea);
        switch (k)
        {
            case ItemKind.Code:
                byte b = s.IsInit(o) ? s.Data[o] : (byte)0;
                bool ret = b == 0xC3 || b == 0xC2 || (b == 0xF3 && o + 1 < s.InitSize && s.Data[o + 1] == 0xC3);
                return (ret ? "locret_" : "loc_") + h;
            case ItemKind.Byte: return "byte_" + h;
            case ItemKind.Word: return "word_" + h;
            case ItemKind.Dword: return (isOff ? "off_" : "dword_") + h;
            case ItemKind.Qword: return (isOff ? "off_" : "qword_") + h;
            case ItemKind.Oword: return "xmmword_" + h;
            case ItemKind.Float: return "flt_" + h;
            case ItemKind.Double: return "dbl_" + h;
            case ItemKind.Ascii:
            case ItemKind.Utf16:
                return StrNames.TryGetValue(ea, out var sn) ? sn : "a" + h;
            case ItemKind.Align: return "algn_" + h;
            case ItemKind.Extern: return "__imp_" + h;
            default: return "unk_" + h;
        }
    }

    // Operand/xref icin isim: bas + ofset
    public string? RefName(ulong ea)
    {
        var s = SegOf(ea);
        if (s == null) return null;
        ulong head = HeadOf(ea);
        string? n = NameAt(head) ?? AutoName(head, true);
        if (n == null) return null;
        return head == ea ? n : n + "+" + HexNum(ea - head);
    }

    public string FuncName(Function f) => NameAt(f.Start) ?? "sub_" + Hx(f.Start);

    // Xref yorumlarindaki konum: sub_401000+1A veya .text:00401000
    public string LocStr(ulong ea)
    {
        var f = FuncAt(ea);
        if (f != null)
        {
            string fn = FuncName(f);
            if (ea == f.Start) return fn;
            return ea > f.Start ? fn + "+" + Hx(ea - f.Start) : fn + "-" + Hx(f.Start - ea);
        }
        var s = SegOf(ea);
        string? n = UserNames.GetValueOrDefault(ea) ?? LoaderNames.GetValueOrDefault(ea);
        if (n != null) return n;
        return (s?.Name ?? "") + ":" + AddrStr(ea);
    }

    public Dictionary<string, ulong> NameIndex()
    {
        if (_nameIdx != null) return _nameIdx;
        var d = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var kv in LoaderNames) d[kv.Value] = kv.Key;
        foreach (var kv in StrNames) d.TryAdd(kv.Value, kv.Key);
        foreach (var kv in UserNames) d[kv.Value] = kv.Key;
        return _nameIdx = d;
    }

    public void InvalidateNames() => _nameIdx = null;

    // ad veya adres -> ea
    public ulong? Resolve(string text)
    {
        text = text.Trim();
        if (text.Length == 0) return null;
        if (NameIndex().TryGetValue(text, out var ea)) return ea;

        // name+ofs
        int plus = text.LastIndexOf('+');
        if (plus > 0)
        {
            var b = Resolve(text[..plus]);
            var o = ParseNum(text[(plus + 1)..]);
            if (b != null && o != null) return b + o;
        }

        // otomatik isimler: sub_XXXX, loc_XXXX ...
        int us = text.IndexOf('_');
        if (us > 0 && us < text.Length - 1)
        {
            string pre = text[..us];
            if (pre is "sub" or "loc" or "locret" or "byte" or "word" or "dword" or "qword" or "off" or "unk"
                or "xmmword" or "flt" or "dbl" or "algn" or "j" or "a" or "stru" or "asc")
                if (ulong.TryParse(text[(us + 1)..], System.Globalization.NumberStyles.HexNumber, null, out var v))
                    return v;
        }
        var n = ParseNum(text);
        if (n != null)
        {
            // kisa yazilmis RVA'yi image base'e ekle
            if (!IsMapped(n.Value) && IsMapped(n.Value + ImageBase)) return n.Value + ImageBase;
            return n;
        }
        return null;
    }

    public static ulong? ParseNum(string t)
    {
        t = t.Trim().Replace("`", "");
        if (t.Length == 0) return null;
        bool neg = t.StartsWith('-');
        if (neg) t = t[1..];
        ulong v;
        bool ok;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            ok = ulong.TryParse(t[2..], System.Globalization.NumberStyles.HexNumber, null, out v);
        else if (t.EndsWith('h') || t.EndsWith('H'))
            ok = ulong.TryParse(t[..^1], System.Globalization.NumberStyles.HexNumber, null, out v);
        else if (t.StartsWith('#'))
            ok = ulong.TryParse(t[1..], out v);
        else
            ok = ulong.TryParse(t, System.Globalization.NumberStyles.HexNumber, null, out v);
        if (!ok) return null;
        return neg ? (ulong)(-(long)v) : v;
    }

    public bool IsValidName(string n)
    {
        if (string.IsNullOrEmpty(n) || n.Length > 512) return false;
        if (char.IsDigit(n[0])) return false;
        foreach (char c in n)
            if (!(char.IsLetterOrDigit(c) || c is '_' or '$' or '@' or '?' or '.' or ':' or '<' or '>' or '~'))
                return false;
        return true;
    }

    public string? SetUserName(ulong ea, string name)
    {
        name = name.Trim();
        if (name.Length == 0)
        {
            UserNames.Remove(ea);
            InvalidateNames();
            Dirty = true;
            return null;
        }
        if (!IsValidName(name)) return Loc.T("Geçersiz isim: ") + name;
        if (NameIndex().TryGetValue(name, out var other) && other != ea)
            return Loc.F("'{0}' ismi zaten {1} adresinde kullanılıyor.", name, AddrStr(other));
        UserNames[ea] = name;
        InvalidateNames();
        Dirty = true;
        return null;
    }

    // ================= String isimleri =================

    public string MakeStrName(ulong ea, string value)
    {
        if (StrNames.TryGetValue(ea, out var ex)) return ex;
        var sb = new StringBuilder("a");
        bool up = true;
        foreach (char c in value)
        {
            if (sb.Length >= 24) break;
            if (char.IsAsciiLetterOrDigit(c))
            {
                sb.Append(up ? char.ToUpperInvariant(c) : c);
                up = false;
            }
            else up = true;
        }
        string bas = sb.Length > 1 ? sb.ToString() : "asc_" + Hx(ea);
        string n = bas;
        for (int i = 0; _strNameSet.Contains(n) || LoaderNames.ContainsValue(n); i++) n = bas + "_" + i;
        _strNameSet.Add(n);
        StrNames[ea] = n;
        return n;
    }

    public void ClearStrName(ulong ea)
    {
        if (StrNames.Remove(ea, out var n)) _strNameSet.Remove(n);
    }

    // ================= String okuma =================

    public string ReadAscii(ulong ea, int max = 4096)
    {
        var sb = new StringBuilder();
        var s = SegOf(ea);
        if (s == null) return "";
        long o = (long)(ea - s.Start);
        while (o < s.InitSize && sb.Length < max)
        {
            byte b = s.Data[o++];
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    public string ReadUtf16(ulong ea, int max = 4096)
    {
        var sb = new StringBuilder();
        var s = SegOf(ea);
        if (s == null) return "";
        long o = (long)(ea - s.Start);
        while (o + 1 < s.InitSize && sb.Length < max)
        {
            char c = (char)(s.Data[o] | (s.Data[o + 1] << 8));
            o += 2;
            if (c == 0) break;
            sb.Append(c);
        }
        return sb.ToString();
    }

    public string? StringAt(ulong ea)
    {
        var k = KindAt(ea);
        if (!IsHead(ea)) return null;
        return k switch
        {
            ItemKind.Ascii => ReadAscii(ea),
            ItemKind.Utf16 => ReadUtf16(ea),
            _ => null,
        };
    }

    public static string Escape(string v, int max = 120)
    {
        var sb = new StringBuilder();
        foreach (char c in v)
        {
            if (sb.Length > max) { sb.Append("..."); break; }
            switch (c)
            {
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '"': sb.Append("\\\""); break;
                default:
                    if (c < 0x20) sb.Append("\\x").Append(((int)c).ToString("X2"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    // ================= Yama =================

    public bool PatchByte(ulong ea, byte v)
    {
        var s = SegOf(ea);
        if (s == null) return false;
        long o = (long)(ea - s.Start);
        if (!s.IsInit(o)) return false;
        if (!Patches.ContainsKey(ea)) Patches[ea] = s.Data[o];
        else if (Patches[ea] == v) Patches.Remove(ea);
        s.Data[o] = v;
        Dirty = true;
        return true;
    }
}
