using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Iced.Intel;

namespace tlk_hex.Core;

public enum LT : byte
{
    Blank, Cmt, SegDir, Assume, Org, FuncSep, Attr, Public, Proc, XrefCont, VarDecl, Label, Main,
    RunByte, Separator, Endp, SegEnds, End, ChunkStart, ChunkEnd, Raw,
}

public struct Spec
{
    public LT T;
    public int I;
    public string? S;
    public Spec(LT t, int i = 0, string? s = null) { T = t; I = i; S = s; }
}

public sealed class Line
{
    public ulong Ea;
    public LT Type;
    public List<Tok> Toks = new(16);
    public int BodyCol;               // govdenin basladigi karakter
    public bool HasBranch, IsCond;
    public ulong BranchTarget;
    private string? _plain;

    public string Plain
    {
        get
        {
            if (_plain != null) return _plain;
            var sb = new StringBuilder();
            foreach (var t in Toks) sb.Append(t.Text);
            return _plain = sb.ToString();
        }
    }
}

public sealed class Listing
{
    private readonly Db _db;
    private readonly Disasm _dis;

    private ulong[] _ea = Array.Empty<ulong>();
    private int[] _len = Array.Empty<int>();
    private byte[] _type = Array.Empty<byte>();   // 0 oge, 1 baslatilmis bilinmeyen dizi, 2 baslatilmamis dizi, 3 tek bayt
    private short[] _seg = Array.Empty<short>();
    private long[] _lineStart = Array.Empty<long>();
    private int _count;
    private readonly List<Spec> _specs = new(32);
    private List<Spec> _fileHeader = new();
    private readonly List<Tok> _tmp = new(32);

    public long TotalLines { get; private set; }
    public int ItemCount => _count;
    public bool ShowPrefix = true;
    public int OpBytes = 0;
    public int MaxXrefs = 8;
    public const int CmtCol = 40;

    public Listing(Db db, Disasm dis)
    {
        _db = db;
        _dis = dis;
    }

    // Arka plan aramasi/disa aktarim icin: ayni indeks, ayri cozucu
    public Listing CloneForWorker()
    {
        var l = new Listing(_db, new Disasm(_db))
        {
            _ea = _ea, _len = _len, _type = _type, _seg = _seg, _lineStart = _lineStart, _count = _count,
            _fileHeader = _fileHeader, TotalLines = TotalLines, ShowPrefix = ShowPrefix, OpBytes = OpBytes, MaxXrefs = MaxXrefs,
        };
        return l;
    }

    // ================= Indeks =================

    public void Build()
    {
        BuildFileHeader();
        var eas = new List<ulong>(1 << 16);
        var lens = new List<int>(1 << 16);
        var types = new List<byte>(1 << 16);
        var segs = new List<short>(1 << 16);
        foreach (var s in _db.Segs)
        {
            long o = 0;
            short si = (short)s.Index;
            while (o < s.Size)
            {
                byte fl = s.F[o];
                ulong ea = s.Start + (ulong)o;
                if ((fl & FF.Head) != 0)
                {
                    int n = Db.ItemSize(s, o);
                    eas.Add(ea); lens.Add(n); types.Add(0); segs.Add(si);
                    o += n;
                    continue;
                }
                if ((fl & FF.Tail) != 0 || HasLabel(ea))
                {
                    eas.Add(ea); lens.Add(1); types.Add(3); segs.Add(si);
                    o++;
                    continue;
                }
                bool init = s.IsInit(o);
                long st = o;
                o++;
                while (o < s.Size && s.F[o] == 0 && s.IsInit(o) == init && !HasLabel(s.Start + (ulong)o)) o++;
                eas.Add(ea); lens.Add((int)(o - st)); types.Add(init ? (byte)1 : (byte)2); segs.Add(si);
            }
        }
        _ea = eas.ToArray();
        _len = lens.ToArray();
        _type = types.ToArray();
        _seg = segs.ToArray();
        _count = _ea.Length;
        _lineStart = new long[_count + 1];
        long total = 0;
        for (int i = 0; i < _count; i++)
        {
            _lineStart[i] = total;
            Layout(i);
            total += SpecLines();
        }
        _lineStart[_count] = total;
        TotalLines = total;
    }

    private bool HasLabel(ulong ea) => _db.XTo.ContainsKey(ea) || _db.UserNames.ContainsKey(ea)
                                       || _db.LoaderNames.ContainsKey(ea) || _db.Comments.ContainsKey(ea);

    private long SpecLines()
    {
        long n = 0;
        foreach (var s in _specs) n += s.T == LT.RunByte ? s.I : 1;
        return n;
    }

    public int ItemIndexOf(ulong ea)
    {
        int lo = 0, hi = _count - 1, ans = 0;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_ea[mid] <= ea) { ans = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return ans;
    }

    public ulong ItemEa(int i) => _ea[i];
    public int ItemLen(int i) => _len[i];

    public int ItemOfLine(long line)
    {
        int lo = 0, hi = _count - 1, ans = 0;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_lineStart[mid] <= line) { ans = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return ans;
    }

    // Bir adresin ekrandaki satiri (isim satiri varsa o)
    public long LineOfEa(ulong ea, bool preferName = true)
    {
        if (_count == 0) return 0;
        int i = ItemIndexOf(ea);
        Layout(i);
        long line = _lineStart[i];
        ulong itemEa = _ea[i];
        foreach (var s in _specs)
        {
            if (preferName && ea == itemEa && s.T is LT.Proc or LT.Label) return line;
            if (s.T == LT.Main) return line;
            if (s.T == LT.RunByte)
            {
                long off = (long)(ea - itemEa);
                return line + Math.Clamp(off, 0, s.I - 1);
            }
            line++;
        }
        return _lineStart[i];
    }

    public ulong EaOfLine(long line)
    {
        if (_count == 0) return 0;
        line = Math.Clamp(line, 0, Math.Max(0, TotalLines - 1));
        int i = ItemOfLine(line);
        long sub = line - _lineStart[i];
        Layout(i);
        foreach (var s in _specs)
        {
            long n = s.T == LT.RunByte ? s.I : 1;
            if (sub < n) return s.T == LT.RunByte ? _ea[i] + (ulong)sub : _ea[i];
            sub -= n;
        }
        return _ea[i];
    }

    // ================= Duzen =================

    private void BuildFileHeader()
    {
        var h = new List<Spec>();
        void C(string s) => h.Add(new Spec(LT.Cmt, 0, s));
        var (sha, md5, crc) = Loaders.Hashes(_db.FileBytes);
        C(";");
        C("; +-------------------------------------------------------------------------+");
        C("; |    Bu dosya tlk-hex (interaktif disassembler) tarafından üretilmiştir    |");
        C("; +-------------------------------------------------------------------------+");
        C(";");
        C("; Input SHA256 : " + sha);
        C("; Input MD5    : " + md5);
        C("; Input CRC32  : " + crc);
        h.Add(new Spec(LT.Blank));
        C("; File Name   : " + _db.FilePath);
        C("; Format      : " + _db.Format);
        C("; Imagebase   : " + Db.Hx(_db.ImageBase));
        if (_db.Timestamp.Length > 0) C("; Timestamp   : " + _db.Timestamp);
        if (_db.PdbPath.Length > 0) C("; PDB File Name : " + _db.PdbPath);
        if (_db.IsDotNet) C("; .NET assembly (CLR basligi var)");
        C(";");
        C("; OS type         :  " + _db.OsType);
        C("; Application type:  " + _db.AppType);
        h.Add(new Spec(LT.Blank));
        h.Add(new Spec(LT.Raw, 0, ".686p"));
        h.Add(new Spec(LT.Raw, 0, ".mmx"));
        h.Add(new Spec(LT.Raw, 0, ".model flat"));
        h.Add(new Spec(LT.Blank));
        _fileHeader = h;
    }

    private static string Perms(Segment s)
    {
        var p = new List<string>();
        if (s.R) p.Add("Read");
        if (s.W) p.Add("Write");
        if (s.X) p.Add("Execute");
        return p.Count == 0 ? "No access" : string.Join("/", p);
    }

    private bool IsFirstCodeSeg(Segment s) => _db.Segs.FirstOrDefault(x => x.X) == s;

    private int ShownXrefs(ulong ea, out bool more)
    {
        int nx = _db.XTo.TryGetValue(ea, out var l) ? l.Count : 0;
        more = nx > MaxXrefs;
        return Math.Min(nx, MaxXrefs);
    }

    private bool IsLive(Function f) => f.Chunks.Count > 0 && _db.Funcs.TryGetValue(f.Start, out var g) && g == f;

    // _specs'i i. oge icin doldurur
    private void Layout(int i)
    {
        var sp = _specs;
        sp.Clear();
        ulong ea = _ea[i];
        int len = _len[i];
        byte type = _type[i];
        var s = _db.Segs[_seg[i]];
        bool isHead = type == 0;
        long off = (long)(ea - s.Start);
        var k = isHead ? (ItemKind)(s.F[off] & FF.KindMask) : ItemKind.Unknown;

        if (i == 0) sp.AddRange(_fileHeader);
        if (ea == s.Start)
        {
            sp.Add(new Spec(LT.Cmt, 0, "; ==========================================================================="));
            sp.Add(new Spec(LT.Blank));
            foreach (var inf in s.Info) sp.Add(new Spec(LT.Cmt, 0, inf));
            sp.Add(new Spec(LT.Cmt, 0, "; Segment type: " + s.SegType));
            if (s.IsExtern)
            {
                sp.Add(new Spec(LT.Cmt, 0, "; " + s.AsmName));
            }
            else
            {
                sp.Add(new Spec(LT.Cmt, 0, "; Segment permissions: " + Perms(s)));
                sp.Add(new Spec(LT.SegDir));
                sp.Add(new Spec(LT.Assume, 0));
                sp.Add(new Spec(LT.Org));
                if (IsFirstCodeSeg(s)) sp.Add(new Spec(LT.Assume, 1));
                sp.Add(new Spec(LT.Blank));
            }
        }

        if (isHead && k == ItemKind.Extern && _db.ImportAt.TryGetValue(ea, out var imp))
        {
            bool first = ea == s.Start || !_db.ImportAt.TryGetValue(ea - (ulong)_db.Ptr, out var prev) || prev.Dll != imp.Dll;
            if (first)
            {
                sp.Add(new Spec(LT.Cmt, 0, ";"));
                sp.Add(new Spec(LT.Cmt, 0, "; Imports from " + imp.Dll));
                sp.Add(new Spec(LT.Cmt, 0, ";"));
                sp.Add(new Spec(LT.Blank));
            }
        }

        Function? f = null;
        if (isHead && k == ItemKind.Code)
        {
            f = _db.FuncAt(ea);
            if (f != null && !IsLive(f)) f = null;
            if (f != null && ea != f.Start)
                for (int c = 1; c < f.Chunks.Count; c++)
                    if (f.Chunks[c].Start == ea)
                    {
                        sp.Add(new Spec(LT.Blank));
                        sp.Add(new Spec(LT.ChunkStart));
                        break;
                    }

            int nx = ShownXrefs(ea, out bool more);
            int cont = Math.Max(0, nx - 1) + (more ? 1 : 0);
            if (f != null && f.Start == ea)
            {
                sp.Add(new Spec(LT.Blank));
                sp.Add(new Spec(LT.FuncSep));
                sp.Add(new Spec(LT.Blank));
                string attrs = Attrs(f);
                if (attrs.Length > 0)
                {
                    sp.Add(new Spec(LT.Attr, 0, "; Attributes: " + attrs));
                    sp.Add(new Spec(LT.Blank));
                }
                if (_db.PublicNames.Contains(ea)) sp.Add(new Spec(LT.Public));
                sp.Add(new Spec(LT.Proc));
                for (int x = 0; x < cont; x++) sp.Add(new Spec(LT.XrefCont, x + 1));
                int nv = 0;
                foreach (var kv in f.Vars)
                    if (_dis.StackVarName(f, kv.Key) != null) nv++;
                if (nv > 0)
                {
                    sp.Add(new Spec(LT.Blank));
                    int vi = 0;
                    foreach (var kv in f.Vars)
                        if (_dis.StackVarName(f, kv.Key) != null) sp.Add(new Spec(LT.VarDecl, vi++));
                }
                sp.Add(new Spec(LT.Blank));
            }
            else if (_db.NameAt(ea) != null)
            {
                sp.Add(new Spec(LT.Blank));
                sp.Add(new Spec(LT.Label));
                for (int x = 0; x < cont; x++) sp.Add(new Spec(LT.XrefCont, x + 1));
            }
            sp.Add(new Spec(LT.Main));
        }
        else if (type == 1)
        {
            sp.Add(new Spec(LT.RunByte, len));
        }
        else
        {
            sp.Add(new Spec(LT.Main));
            if (type != 2)
            {
                int nx = ShownXrefs(ea, out bool more);
                bool cmtFirst = _db.Comments.ContainsKey(ea);
                int cont = (cmtFirst ? nx : Math.Max(0, nx - 1)) + (more ? 1 : 0);
                for (int x = 0; x < cont; x++) sp.Add(new Spec(LT.XrefCont, cmtFirst ? x : x + 1));
            }
        }

        // ---- son satirlar ----
        if (isHead && k == ItemKind.Code)
        {
            ulong next = ea + (ulong)len;
            bool brk = FlowBreak(ea);
            if (f != null)
            {
                bool endMain = next == f.End && ea >= f.Chunks[0].Start && ea < f.Chunks[0].End;
                bool endChunk = false;
                for (int c = 1; c < f.Chunks.Count; c++) if (f.Chunks[c].End == next) endChunk = true;
                if (endMain)
                {
                    sp.Add(new Spec(LT.Endp));
                    sp.Add(new Spec(LT.Blank));
                }
                else if (endChunk)
                {
                    sp.Add(new Spec(LT.ChunkEnd));
                    sp.Add(new Spec(LT.Separator));
                }
                else if (brk) sp.Add(new Spec(LT.Separator));
            }
            else if (brk) sp.Add(new Spec(LT.Separator));
        }

        bool lastInSeg = i + 1 >= _count || _seg[i + 1] != _seg[i];
        if (lastInSeg)
        {
            sp.Add(new Spec(LT.SegEnds));
            sp.Add(new Spec(LT.Blank));
            if (i == _count - 1) sp.Add(new Spec(LT.End));
        }
    }

    private string Attrs(Function f)
    {
        var a = new List<string>();
        if (f.IsLibrary) a.Add("library function");
        if (f.IsThunk) a.Add("thunk");
        if (f.NoReturn) a.Add("noreturn");
        if (f.BpBased) a.Add("bp-based frame");
        return string.Join(" ", a);
    }

    private bool FlowBreak(ulong ea)
    {
        if (!_dis.TryDecode(ea, out var ins)) return false;
        return ins.FlowControl switch
        {
            FlowControl.UnconditionalBranch or FlowControl.IndirectBranch or FlowControl.Return
                or FlowControl.Exception => true,
            FlowControl.Interrupt => ins.Mnemonic == Mnemonic.Int3,
            FlowControl.Call or FlowControl.IndirectCall => CallNoRet(ins),
            _ => false,
        };
    }

    private bool CallNoRet(in Instruction ins)
    {
        if (ins.FlowControl == FlowControl.Call &&
            ins.Op0Kind is OpKind.NearBranch32 or OpKind.NearBranch64 or OpKind.NearBranch16)
            return _db.Funcs.TryGetValue(ins.NearBranchTarget, out var f) && f.NoReturn;
        return false;
    }

    // ================= Satir uretimi =================

    public Line GetLine(long line, bool graph = false)
    {
        var ln = new Line();
        if (_count == 0) return ln;
        line = Math.Clamp(line, 0, TotalLines - 1);
        int i = ItemOfLine(line);
        long sub = line - _lineStart[i];
        Layout(i);
        for (int si = 0; si < _specs.Count; si++)
        {
            var s = _specs[si];
            long n = s.T == LT.RunByte ? s.I : 1;
            if (sub < n)
            {
                Render(i, s, (int)sub, ln, graph);
                return ln;
            }
            sub -= n;
        }
        return ln;
    }

    // Graph blogu icin: bir ogenin gosterilecek satirlari
    public List<Line> ItemLinesForGraph(ulong ea)
    {
        var res = new List<Line>();
        int i = ItemIndexOf(ea);
        if (_ea[i] != ea) return res;
        Layout(i);
        var specs = _specs.ToList();
        foreach (var s in specs)
        {
            if (s.T is LT.Attr or LT.Proc or LT.VarDecl or LT.Label or LT.Main)
            {
                var ln = new Line();
                Render(i, s, 0, ln, true);
                res.Add(ln);
            }
        }
        return res;
    }

    private Tk PrefixKind(ulong ea, Segment s, int type)
    {
        if (type != 0) return Tk.PrefixUnk;
        var k = (ItemKind)(s.F[ea - s.Start] & FF.KindMask);
        if (k == ItemKind.Extern || s.IsExtern) return Tk.PrefixExt;
        if (k == ItemKind.Code)
        {
            var f = _db.FuncAt(ea);
            if (f == null) return Tk.PrefixNoFunc;
            return f.IsLibrary || f.IsThunk ? Tk.PrefixLib : Tk.Prefix;
        }
        return Tk.PrefixData;
    }

    private void Render(int i, Spec spec, int sub, Line ln, bool graph)
    {
        ulong ea = _ea[i];
        var s = _db.Segs[_seg[i]];
        byte type = _type[i];
        ulong lineEa = spec.T == LT.RunByte ? ea + (ulong)sub : ea;
        ln.Ea = lineEa;
        ln.Type = spec.T;
        var t = ln.Toks;

        if (!graph && ShowPrefix)
        {
            t.Add(new Tok(s.Name + ":" + _db.AddrStr(lineEa), PrefixKind(ea, s, type)));
            t.Add(new Tok(" ", Tk.Text));
        }
        if (!graph && OpBytes > 0)
        {
            string bytes = "";
            if (spec.T is LT.Main or LT.RunByte)
            {
                int n = spec.T == LT.RunByte ? 1 : _len[i];
                var sb = new StringBuilder();
                for (int b = 0; b < Math.Min(n, OpBytes); b++)
                {
                    if (_db.TryByte(lineEa + (ulong)b, out var bv)) sb.Append(bv.ToString("X2")).Append(' ');
                    else sb.Append("?? ");
                }
                if (n > OpBytes) sb.Append('+');
                bytes = sb.ToString();
            }
            t.Add(new Tok(bytes.PadRight(OpBytes * 3 + 2), Tk.Bytes));
        }
        int bodyStart = 0;
        foreach (var x in t) bodyStart += x.Text.Length;
        ln.BodyCol = bodyStart;
        int col = 0;
        int ind = graph ? 0 : 16;
        int cmtCol = graph ? 0 : CmtCol;

        void Add(string text, Tk k)
        {
            t.Add(new Tok(text, k));
            col += text.Length;
        }
        void PadTo(int c)
        {
            if (col < c) Add(new string(' ', c - col), Tk.Text);
            else if (col > 0) Add(" ", Tk.Text);
        }
        void Name16(string name, Tk k)
        {
            Add(name, k);
            if (!graph) PadTo(16); else Add(" ", Tk.Text);
        }
        void Comment(string text, Tk k)
        {
            if (graph) Add("  ", Tk.Text);
            else PadTo(cmtCol);
            Add(text, k);
        }

        switch (spec.T)
        {
            case LT.Blank:
                break;
            case LT.Cmt:
            case LT.Attr:
                Add(spec.S ?? "", Tk.AutoCmt);
                break;
            case LT.FuncSep:
                Add("; =============== S U B R O U T I N E =======================================", Tk.AutoCmt);
                break;
            case LT.Separator:
                Add("; ---------------------------------------------------------------------------", Tk.AutoCmt);
                break;
            case LT.Raw:
                PadTo(ind);
                Add(spec.S ?? "", Tk.Directive);
                break;
            case LT.SegDir:
                Name16(s.AsmName, Tk.Name);
                Add("segment", Tk.Directive);
                Add(" para public ", Tk.Directive);
                Add("'" + s.Class + "'", Tk.Str);
                Add(" use" + _db.Bitness, Tk.Directive);
                break;
            case LT.Assume:
                PadTo(ind);
                if (spec.I == 0)
                {
                    Add("assume ", Tk.Directive);
                    Add("cs:" + s.AsmName, Tk.Text);
                }
                else
                {
                    var ds = _db.Segs.FirstOrDefault(x => x.Class == "DATA") ?? s;
                    Add("assume ", Tk.Directive);
                    Add($"es:nothing, ss:nothing, ds:{ds.AsmName}, fs:nothing, gs:nothing", Tk.Text);
                }
                break;
            case LT.Org:
                PadTo(ind);
                Add(";org " + Db.HexNum(s.Start), Tk.AutoCmt);
                break;
            case LT.SegEnds:
                Name16(s.AsmName, Tk.Name);
                Add("ends", Tk.Directive);
                break;
            case LT.End:
                PadTo(ind);
                Add("end", Tk.Directive);
                if (_db.Entry != ulong.MaxValue)
                {
                    Add(" ", Tk.Text);
                    Add(_db.NameAt(_db.Entry) ?? "start", Tk.Name);
                }
                break;
            case LT.Public:
                PadTo(ind);
                Add("public ", Tk.Directive);
                Add(_db.NameAt(ea) ?? "", Tk.Name);
                break;
            case LT.Proc:
            {
                string fn = _db.NameAt(ea) ?? "sub_" + Db.Hx(ea);
                Name16(fn, _db.IsDummyName(ea) ? Tk.DummyName : Tk.LabelDef);
                Add("proc near", Tk.Directive);
                XrefFirst(ea, Comment);
                break;
            }
            case LT.Endp:
            {
                var f = _db.FuncAt(ea);
                string fn = f != null ? _db.FuncName(f) : "";
                Name16(fn, f != null && _db.IsDummyName(f.Start) ? Tk.DummyName : Tk.LabelDef);
                Add("endp", Tk.Directive);
                break;
            }
            case LT.ChunkStart:
            {
                var f = _db.FuncAt(ea);
                Add("; START OF FUNCTION CHUNK FOR " + (f != null ? _db.FuncName(f) : "?"), Tk.AutoCmt);
                break;
            }
            case LT.ChunkEnd:
            {
                var f = _db.FuncAt(ea);
                Add("; END OF FUNCTION CHUNK FOR " + (f != null ? _db.FuncName(f) : "?"), Tk.AutoCmt);
                break;
            }
            case LT.Label:
            {
                string n = _db.NameAt(ea) ?? "loc_" + Db.Hx(ea);
                Add(n + ":", _db.IsDummyName(ea) ? Tk.DummyName : Tk.LabelDef);
                XrefFirst(ea, Comment);
                break;
            }
            case LT.XrefCont:
            {
                var xs = SortedXrefs(ea);
                if (spec.I < xs.Count && spec.I < MaxXrefs)
                    Comment("; " + XrefStr(xs[spec.I], ea), Tk.AutoCmt);
                else Comment("; ...", Tk.AutoCmt);
                break;
            }
            case LT.VarDecl:
            {
                var f = _db.FuncAt(ea);
                if (f == null) break;
                int vi = 0;
                foreach (var kv in f.Vars)
                {
                    string? vn = _dis.StackVarName(f, kv.Key);
                    if (vn == null) continue;
                    if (vi++ != spec.I) continue;
                    int o = kv.Key + f.FrRegs;
                    Add(vn, Tk.LocalVar);
                    if (!graph) PadTo(16);
                    Add("= ", Tk.Punct);
                    string kw = Disasm.SizeKw(kv.Value);
                    Add((kw.Length > 0 ? kw : "byte") + " ptr ", Tk.Kw);
                    Add((o >= 0 ? " " : "") + Db.HexNumSigned(o), Tk.Num);
                    break;
                }
                break;
            }
            case LT.Main:
                RenderMain(i, ea, s, type, ln, Add, PadTo, Name16, Comment, graph, ind);
                break;
            case LT.RunByte:
            {
                PadTo(ind);
                Add("db ", Tk.Directive);
                if (_db.TryByte(lineEa, out var b))
                {
                    Add(Db.HexNum(b).PadLeft(4), Tk.Num);
                    if (b >= 0x20 && b < 0x7F) Comment("; " + (char)b, Tk.AutoCmt);
                }
                else Add("   ?", Tk.Num);
                break;
            }
        }
    }

    private void RenderMain(int i, ulong ea, Segment s, byte type, Line ln, Action<string, Tk> Add, Action<int> PadTo,
        Action<string, Tk> Name16, Action<string, Tk> Comment, bool graph, int ind)
    {
        long off = (long)(ea - s.Start);
        int len = _len[i];
        if (type == 2)
        {
            string? n2 = _db.NameAt(ea);
            if (n2 != null) Name16(n2, Tk.Name); else PadTo(ind);
            Add("db ", Tk.Directive);
            if (len == 1) { Add("   ?", Tk.Num); Comment(";", Tk.AutoCmt); }
            else { Add(Db.HexNum((ulong)len), Tk.Num); Add(" dup(", Tk.Directive); Add("?", Tk.Num); Add(")", Tk.Directive); }
            return;
        }
        if (type == 3)
        {
            string? n3 = _db.NameAt(ea) ?? _db.AutoName(ea, true);
            if (n3 != null) Name16(n3, _db.IsDummyName(ea) ? Tk.DummyName : Tk.LabelDef); else PadTo(ind);
            Add("db ", Tk.Directive);
            if (_db.TryByte(ea, out var b)) Add(Db.HexNum(b).PadLeft(4), Tk.Num); else Add("   ?", Tk.Num);
            DataComment(ea, Comment, b >= 0x20 && b < 0x7F ? "; " + (char)b : null);
            return;
        }

        var k = (ItemKind)(s.F[off] & FF.KindMask);
        bool isOff = (s.F[off] & FF.Offset) != 0;
        bool init = s.IsInit(off);

        if (k == ItemKind.Code)
        {
            if (!graph) PadTo(ind);
            if (!_dis.TryDecode(ea, out var ins))
            {
                Add("db ", Tk.Directive);
                Add(_db.TryByte(ea, out var bb) ? Db.HexNum(bb) : "?", Tk.Error);
                return;
            }
            var f = _db.FuncAt(ea);
            _tmp.Clear();
            _dis.FormatInsn(ins, f, _tmp);
            foreach (var tk in _tmp) Add(tk.Text, tk.Kind);
            if (ins.FlowControl is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch
                && ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
            {
                ln.HasBranch = true;
                ln.IsCond = ins.FlowControl == FlowControl.ConditionalBranch;
                ln.BranchTarget = ins.NearBranchTarget;
            }
            string? c = CodeComment(ea, out Tk ck);
            if (c != null) Comment(c, ck);
            return;
        }

        if (k == ItemKind.Extern)
        {
            PadTo(ind);
            Add("extrn ", Tk.Directive);
            Add(_db.NameAt(ea) ?? "?", Tk.ImportName);
            Add(":", Tk.Punct);
            Add(_db.Ptr == 8 ? "qword" : "dword", Tk.Kw);
            DataComment(ea, Comment, null);
            return;
        }

        if (k == ItemKind.Align)
        {
            PadTo(ind);
            ulong end = ea + (ulong)len;
            ulong a = 0;
            if (end % 16 == 0 && len < 16) a = 16;
            else
                for (ulong x = 2; x <= 0x1000; x <<= 1)
                    if (x > (ulong)len && end % x == 0) { a = x; break; }
            if (a != 0)
            {
                Add("align ", Tk.Directive);
                Add(Db.HexNum(a), Tk.Num);
            }
            else
            {
                Add("db ", Tk.Directive);
                Add(Db.HexNum((ulong)len), Tk.Num);
                Add(" dup(", Tk.Directive);
                Add(_db.TryByte(ea, out var bb) ? Db.HexNum(bb) : "?", Tk.Num);
                Add(")", Tk.Directive);
            }
            return;
        }

        // ---- veri ----
        string? name = _db.NameAt(ea);
        if (name != null) Name16(name, _db.IsDummyName(ea) ? Tk.DummyName : Tk.LabelDef);
        else if (!graph) PadTo(ind);

        switch (k)
        {
            case ItemKind.Ascii:
            case ItemKind.Utf16:
                if (k == ItemKind.Utf16)
                {
                    Add("text ", Tk.Directive);
                    Add("\"UTF-16LE\"", Tk.Str);
                    Add(", ", Tk.Punct);
                    StrBody(_db.ReadUtf16(ea, 2048), Add);
                }
                else
                {
                    Add("db ", Tk.Directive);
                    StrBody(_db.ReadAscii(ea, 2048), Add);
                }
                break;
            default:
            {
                string dir = k switch
                {
                    ItemKind.Byte => "db", ItemKind.Word => "dw", ItemKind.Dword or ItemKind.Float => "dd",
                    ItemKind.Qword or ItemKind.Double => "dq", ItemKind.Oword => "xmmword", _ => "db",
                };
                Add(dir.PadRight(dir.Length < 4 ? 3 : dir.Length + 1), Tk.Directive);
                if (!init) { Add("?", Tk.Num); break; }
                int size = Disasm.KindSize(k, _db.Ptr);
                if (k == ItemKind.Oword)
                {
                    var sb = new StringBuilder();
                    for (int b = 15; b >= 0; b--) sb.Append(_db.TryByte(ea + (ulong)b, out var bv) ? bv.ToString("X2") : "00");
                    string h = sb.ToString().TrimStart('0');
                    if (h.Length == 0) h = "0";
                    Add(h.Length == 1 && char.IsDigit(h[0]) ? h : (char.IsLetter(h[0]) ? "0" : "") + h + "h", Tk.Num);
                    break;
                }
                _db.TryRead(ea, size, out var v);
                if (_db.RvaItems.Contains(ea))
                {
                    Add("rva ", Tk.Kw);
                    ulong tgt = _db.ImageBase + v;
                    Add(_db.RefName(tgt) ?? Db.HexNum(v), Tk.DummyName);
                }
                else if (_db.RelItems.TryGetValue(ea, out var rb))
                {
                    ulong tgt = (ulong)((long)rb + (int)(uint)v);
                    Add(_db.RefName(tgt) ?? "?", Tk.DummyName);
                    Add(" - ", Tk.Punct);
                    Add(_db.RefName(rb) ?? Db.HexNum(rb), Tk.DummyName);
                }
                else if (isOff && _db.IsMapped(v))
                {
                    Add("offset ", Tk.Kw);
                    Add(_db.RefName(v) ?? Db.HexNum(v), _dis.NameKind(_db.HeadOf(v), false));
                }
                else if (k == ItemKind.Float)
                    Add(BitConverter.Int32BitsToSingle((int)v).ToString("R", CultureInfo.InvariantCulture), Tk.Num);
                else if (k == ItemKind.Double)
                    Add(BitConverter.Int64BitsToDouble((long)v).ToString("R", CultureInfo.InvariantCulture), Tk.Num);
                else
                    Add(Db.HexNum(v), Tk.Num);
                break;
            }
        }
        DataComment(ea, Comment, null);
    }

    private static void StrBody(string v, Action<string, Tk> Add)
    {
        var sb = new StringBuilder();
        bool first = true;
        void Flush()
        {
            if (sb.Length == 0) return;
            if (!first) Add(",", Tk.Punct);
            Add("'" + sb + "'", Tk.Str);
            sb.Clear();
            first = false;
        }
        int shown = 0;
        foreach (char c in v)
        {
            if (++shown > 1024) break;
            if (c >= 0x20 && c != '\'' && c < 0x7F) sb.Append(c);
            else
            {
                Flush();
                if (!first) Add(",", Tk.Punct);
                Add(Db.HexNum(c), Tk.Num);
                first = false;
            }
        }
        Flush();
        if (!first) Add(",", Tk.Punct);
        Add("0", Tk.Num);
    }

    private void DataComment(ulong ea, Action<string, Tk> Comment, string? fallback)
    {
        if (_db.Comments.TryGetValue(ea, out var uc)) { Comment("; " + OneLine(uc), Tk.Cmt); return; }
        if (_db.RepComments.TryGetValue(ea, out var rc)) { Comment("; " + OneLine(rc), Tk.RepCmt); return; }
        var xs = SortedXrefs(ea);
        if (xs.Count > 0) { Comment(XrefHead(xs[0], ea), Tk.AutoCmt); return; }
        if (_db.AutoComments.TryGetValue(ea, out var ac)) { Comment("; " + ac, Tk.AutoCmt); return; }
        if (fallback != null) Comment(fallback, Tk.AutoCmt);
    }

    private void XrefFirst(ulong ea, Action<string, Tk> Comment)
    {
        var xs = SortedXrefs(ea);
        if (xs.Count > 0) Comment(XrefHead(xs[0], ea), Tk.AutoCmt);
        else if (_db.AutoComments.TryGetValue(ea, out var ac)) Comment("; " + ac, Tk.AutoCmt);
    }

    private static string OneLine(string s) => s.Replace("\r", "").Replace("\n", " ");

    private string? CodeComment(ulong ea, out Tk kind)
    {
        kind = Tk.Cmt;
        if (_db.Comments.TryGetValue(ea, out var uc)) return "; " + OneLine(uc);
        kind = Tk.RepCmt;
        if (_db.RepComments.TryGetValue(ea, out var rc)) return "; " + OneLine(rc);
        kind = Tk.AutoCmt;
        var parts = new List<string>();
        if (_db.AutoComments.TryGetValue(ea, out var ac)) parts.Add(ac);
        foreach (var x in _db.XrefsFrom(ea))
        {
            if (x.Type is XrefType.Call or XrefType.Jump && _db.Funcs.ContainsKey(x.To)) continue;
            ulong h = _db.HeadOf(x.To);
            if (_db.RepComments.TryGetValue(h, out var trc)) { parts.Add(OneLine(trc)); break; }
            var str = _db.StringAt(h);
            if (str != null && h == x.To) { parts.Add("\"" + Db.Escape(str, 100) + "\""); break; }
        }
        return parts.Count > 0 ? "; " + string.Join(" ", parts) : null;
    }

    private List<Xref> SortedXrefs(ulong ea)
    {
        if (!_db.XTo.TryGetValue(ea, out var l)) return new List<Xref>();
        var c = l.ToList();
        c.Sort((a, b) => a.From.CompareTo(b.From));
        return c;
    }

    private string XrefHead(Xref x, ulong to) => (x.IsCode ? "; CODE XREF: " : "; DATA XREF: ") + XrefStr(x, to);

    public string XrefStr(Xref x, ulong to)
    {
        string arrow = x.From < to ? "↑" : "↓";
        return _db.LocStr(x.From) + arrow + (char)x.Type;
    }

    // ================= Arama / disa aktarim =================

    public long FindText(string q, long from, bool down, bool matchCase, bool regex, CancellationToken ct = default)
    {
        Regex? rx = null;
        if (regex)
        {
            try { rx = new Regex(q, matchCase ? RegexOptions.None : RegexOptions.IgnoreCase); }
            catch { return -1; }
        }
        var cmp = matchCase ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        long step = down ? 1 : -1;
        for (long l = from; l >= 0 && l < TotalLines; l += step)
        {
            if ((l & 0xFFF) == 0 && ct.IsCancellationRequested) return -1;
            var line = GetLine(l);
            string p = line.Plain;
            if (rx != null ? rx.IsMatch(p) : p.Contains(q, cmp)) return l;
        }
        return -1;
    }

    public void Export(TextWriter w, bool withPrefix, CancellationToken ct = default)
    {
        bool old = ShowPrefix;
        int ob = OpBytes;
        ShowPrefix = withPrefix;
        OpBytes = 0;
        try
        {
            for (long l = 0; l < TotalLines; l++)
            {
                if ((l & 0xFFF) == 0 && ct.IsCancellationRequested) break;
                w.WriteLine(GetLine(l).Plain.TrimEnd());
            }
        }
        finally
        {
            ShowPrefix = old;
            OpBytes = ob;
        }
    }
}
