using Iced.Intel;

namespace tlk_hex.Core;

// Ekrandaki parca turleri (renklendirme)
public enum Tk : byte
{
    Text, Prefix, PrefixNoFunc, PrefixData, PrefixUnk, PrefixExt, PrefixLib,
    Mnem, Reg, Num, Kw, Punct, Name, DummyName, ImportName, LocalVar, Str,
    Cmt, AutoCmt, RepCmt, Directive, Bytes, Error, LabelDef, Keyword2, Macro,
}

public readonly record struct Tok(string Text, Tk Kind);

// Bayt dizisinden okuma konumu degistirilebilen okuyucu
public sealed class SegReader : CodeReader
{
    public byte[] Data = Array.Empty<byte>();
    public int Pos, End;
    public override int ReadByte() => Pos < End ? Data[Pos++] : -1;
}

public sealed class Disasm
{
    private readonly Db _db;
    private readonly SegReader _rd = new();
    private Decoder? _dec;
    private Segment? _decSeg;

    private readonly MasmFormatter _fmt;
    private readonly MasmFormatter _fmtDec;
    private readonly Resolver _res;

    public Disasm(Db db)
    {
        _db = db;
        _res = new Resolver(this);
        _fmt = new MasmFormatter(_res);
        _fmtDec = new MasmFormatter(_res);
        Setup(_fmt.Options);
        Setup(_fmtDec.Options);
        _fmtDec.Options.NumberBase = NumberBase.Decimal;
    }

    private static void Setup(FormatterOptions o)
    {
        o.MemorySizeOptions = MemorySizeOptions.Minimal;
        o.SpaceAfterOperandSeparator = true;
        o.RipRelativeAddresses = false;
        o.MasmSymbolDisplInBrackets = true;
        o.MasmDisplInBrackets = true;
        o.ShowBranchSize = false;
        o.HexSuffix = "h";
        o.HexPrefix = null;
        o.UppercaseHex = true;
        o.AddLeadingZeroToHexNumbers = true;
        o.SmallHexNumbersInDecimal = true;
        o.BranchLeadingZeros = false;
        o.LeadingZeros = false;
        o.DisplacementLeadingZeros = false;
        o.SignedMemoryDisplacements = true;
        o.ShowZeroDisplacements = false;
        o.CC_e = CC_e.z;
        o.CC_ne = CC_ne.nz;
        o.CC_ae = CC_ae.nb;
        o.CC_b = CC_b.b;
        o.CC_be = CC_be.be;
        o.CC_a = CC_a.a;
        o.CC_p = CC_p.p;
        o.CC_np = CC_np.np;
        o.CC_l = CC_l.l;
        o.CC_ge = CC_ge.ge;
        o.CC_le = CC_le.le;
        o.CC_g = CC_g.g;
    }

    public Db Db => _db;

    // ================= Cozme =================

    public bool TryDecode(ulong ea, out Instruction ins)
    {
        ins = default;
        var s = _db.SegOf(ea);
        if (s == null) return false;
        long o = (long)(ea - s.Start);
        if (o >= s.InitSize) return false;
        if (_decSeg != s || _dec == null)
        {
            _rd.Data = s.Data;
            _rd.End = s.InitSize;
            _rd.Pos = (int)o;
            _dec = Decoder.Create(_db.Bitness, _rd, ea, DecoderOptions.None);
            _decSeg = s;
        }
        _rd.Pos = (int)o;
        _rd.End = s.InitSize;
        _dec.IP = ea;
        _dec.Decode(out ins);
        return !ins.IsInvalid && _dec.LastError == DecoderError.None;
    }

    public static bool IsStackReg(Register r) => r is Register.RSP or Register.ESP or Register.SP;
    public static bool IsFrameReg(Register r) => r is Register.RBP or Register.EBP or Register.BP;

    public ulong? MemTarget(in Instruction ins)
    {
        if (ins.IsIPRelativeMemoryOperand) return ins.IPRelativeMemoryAddress;
        if (ins.MemoryBase == Register.None)
            return _db.Bitness == 64 ? ins.MemoryDisplacement64 : ins.MemoryDisplacement32;
        return null;
    }

    public static int MemBytes(in Instruction ins)
    {
        try { return ins.MemorySize.GetSize(); } catch { return 0; }
    }

    public static string SizeKw(int n) => n switch
    {
        1 => "byte", 2 => "word", 4 => "dword", 6 => "fword", 8 => "qword", 10 => "tbyte",
        16 => "xmmword", 32 => "ymmword", 64 => "zmmword", _ => "",
    };

    public static int KindSize(ItemKind k, int ptr) => k switch
    {
        ItemKind.Byte => 1, ItemKind.Word => 2, ItemKind.Dword => 4, ItemKind.Float => 4,
        ItemKind.Qword => 8, ItemKind.Double => 8, ItemKind.Oword => 16, ItemKind.Extern => ptr, _ => 0,
    };

    // ================= Bicimleme =================

    private Function? _curFunc;
    private ulong _curEa;
    private readonly Dictionary<string, Tk> _symKinds = new();
    private readonly TokOut _out = new();

    public void FormatInsn(in Instruction ins, Function? f, List<Tok> toks, bool padMnem = true)
    {
        _curFunc = f;
        _curEa = ins.IP;
        _symKinds.Clear();
        var fmt = _db.DecimalOps.Contains(ins.IP) ? _fmtDec : _fmt;

        _out.Target = toks;
        _out.Map = _symKinds;
        int start = toks.Count;
        fmt.FormatMnemonic(ins, _out, FormatMnemonicOptions.None);
        // IDA: ret -> retn
        int mlen = 0;
        for (int i = start; i < toks.Count; i++)
        {
            if (toks[i].Kind == Tk.Mnem && toks[i].Text == "ret") toks[i] = new Tok("retn", Tk.Mnem);
            mlen += toks[i].Text.Length;
        }

        int n = fmt.GetOperandCount(ins);
        if (n == 0) return;
        if (padMnem) toks.Add(new Tok(mlen < 8 ? new string(' ', 8 - mlen) : " ", Tk.Text));
        else toks.Add(new Tok(" ", Tk.Text));

        for (int op = 0; op < n; op++)
        {
            if (op > 0) toks.Add(new Tok(", ", Tk.Punct));
            int iop = GetInstrOp(fmt, ins, op);
            if (iop >= 0 && ins.GetOpKind(iop) == OpKind.Memory && TryCustomMem(ins, toks))
                continue;
            int opStart = toks.Count;
            if (op == 0 && (ins.IsJmpShort || ins.IsJccShort || ins.IsJcxShort || ins.IsLoopcc || ins.IsLoop))
                toks.Add(new Tok("short ", Tk.Kw));
            fmt.FormatOperand(ins, _out, op);
            // IDA dogrudan hedefler icin "near ptr" yazmaz
            if (toks.Count - opStart >= 4 && toks[opStart].Text == "near" && toks[opStart + 2].Text == "ptr")
                toks.RemoveRange(opStart, 4);
            if (iop >= 0 && ins.GetOpKind(iop) == OpKind.Memory && f != null) DropVarSize(ins, f, toks, opStart);
        }
    }

    // IDA: degisken tipi bellek boyutuyla ayniysa "dword ptr" yazilmaz
    private void DropVarSize(in Instruction ins, Function f, List<Tok> toks, int start)
    {
        if (toks.Count - start < 5 || toks[start].Kind != Tk.Kw || toks[start + 2].Text != "ptr") return;
        bool hasVar = false;
        for (int i = start; i < toks.Count; i++) if (toks[i].Kind == Tk.LocalVar) hasVar = true;
        if (!hasVar) return;
        var b = ins.MemoryBase;
        long disp = _db.Bitness == 64 ? (long)ins.MemoryDisplacement64 : (int)ins.MemoryDisplacement32;
        int delta;
        if (IsStackReg(b)) { if (!f.SpAt.TryGetValue(ins.IP, out delta)) return; }
        else if (IsFrameReg(b) && f.BpDelta != int.MinValue) delta = f.BpDelta;
        else return;
        if (f.Vars.TryGetValue((int)(delta + disp), out var vsz) && vsz == MemBytes(ins))
            toks.RemoveRange(start, 4);
    }

    private static int GetInstrOp(MasmFormatter fmt, in Instruction ins, int op)
    {
        try { return fmt.GetInstructionOperand(ins, op); } catch { return -1; }
    }

    // [rip+X] / [abs] / ds:tablo[reg*4] -> IDA tarzi: cs:isim
    private bool TryCustomMem(in Instruction ins, List<Tok> toks)
    {
        bool rip = ins.IsIPRelativeMemoryOperand;
        if (!rip && ins.MemoryBase != Register.None) return false;
        ulong target = rip ? ins.IPRelativeMemoryAddress
            : _db.Bitness == 64 ? ins.MemoryDisplacement64 : ins.MemoryDisplacement32;
        if (!_db.IsMapped(target))
        {
            if (target != _db.ImageBase || _db.LoaderId != "pe" || ins.MemoryIndex != Register.None) return false;
            toks.Add(new Tok("__ImageBase", Tk.Name));
            return true;
        }
        string? name = _db.RefName(target);
        if (name == null) return false;

        ulong head = _db.HeadOf(target);
        var k = _db.KindAt(head);
        int msz = MemBytes(ins);
        int isz = KindSize(k, _db.Ptr);
        bool isImport = _db.ImportAt.ContainsKey(head);
        bool lea = ins.Mnemonic == Mnemonic.Lea;
        bool needSize = !lea && msz > 0 && (isz != msz || head != target) && SizeKw(msz).Length > 0;
        if (needSize)
        {
            toks.Add(new Tok(SizeKw(msz), Tk.Kw));
            toks.Add(new Tok(" ptr ", Tk.Kw));
        }

        if (ins.SegmentPrefix != Register.None && !lea)
        {
            toks.Add(new Tok(ins.SegmentPrefix.ToString().ToLowerInvariant(), Tk.Reg));
            toks.Add(new Tok(":", Tk.Punct));
        }
        else if (!lea)
        {
            bool callJmp = ins.Mnemonic is Mnemonic.Call or Mnemonic.Jmp;
            if (rip) { toks.Add(new Tok("cs", Tk.Reg)); toks.Add(new Tok(":", Tk.Punct)); }
            else if (callJmp || ins.MemoryIndex != Register.None) { toks.Add(new Tok("ds", Tk.Reg)); toks.Add(new Tok(":", Tk.Punct)); }
        }

        toks.Add(new Tok(name, NameKind(head, isImport)));

        if (ins.MemoryIndex != Register.None)
        {
            toks.Add(new Tok("[", Tk.Punct));
            toks.Add(new Tok(ins.MemoryIndex.ToString().ToLowerInvariant(), Tk.Reg));
            if (ins.MemoryIndexScale > 1)
            {
                toks.Add(new Tok("*", Tk.Punct));
                toks.Add(new Tok(ins.MemoryIndexScale.ToString(), Tk.Num));
            }
            toks.Add(new Tok("]", Tk.Punct));
        }
        return true;
    }

    public Tk NameKind(ulong head, bool isImport)
    {
        if (isImport || _db.ImportAt.ContainsKey(head)) return Tk.ImportName;
        if (_db.Funcs.TryGetValue(head, out var f) && f.IsThunk) return Tk.ImportName;
        return _db.IsDummyName(head) ? Tk.DummyName : Tk.Name;
    }

    // ================= Yigin degiskenleri =================

    public string? StackVarName(Function f, int l)
    {
        if (_db.StackNames.TryGetValue((f.Start, l), out var un)) return un;
        int ptr = _db.Ptr;
        if (l >= ptr) return "arg_" + Db.Hx((ulong)(l - ptr));
        int o = l + f.FrRegs;
        if (o < 0) return "var_" + Db.Hx((ulong)(-o));
        return null;
    }

    private sealed class TokOut : FormatterOutput
    {
        public List<Tok> Target = new();
        public Dictionary<string, Tk> Map = new();

        public override void Write(string text, FormatterTextKind kind)
        {
            Tk k = kind switch
            {
                FormatterTextKind.Mnemonic or FormatterTextKind.Prefix => Tk.Mnem,
                FormatterTextKind.Register => Tk.Reg,
                FormatterTextKind.Number or FormatterTextKind.LabelAddress or FormatterTextKind.FunctionAddress
                    or FormatterTextKind.SelectorValue => Tk.Num,
                FormatterTextKind.Keyword or FormatterTextKind.Directive or FormatterTextKind.Decorator => Tk.Kw,
                FormatterTextKind.Operator or FormatterTextKind.Punctuation => Tk.Punct,
                FormatterTextKind.Data or FormatterTextKind.Label or FormatterTextKind.Function => Tk.Name,
                _ => Tk.Text,
            };
            if (k == Tk.Name && Map.TryGetValue(text, out var mk)) k = mk;
            Target.Add(new Tok(text, k));
        }
    }

    private sealed class Resolver : ISymbolResolver
    {
        private readonly Disasm _d;
        public Resolver(Disasm d) => _d = d;

        public bool TryGetSymbol(in Instruction instruction, int operand, int instructionOperand, ulong address,
            int addressSize, out SymbolResult symbol)
        {
            symbol = default;
            var db = _d._db;
            if (instructionOperand < 0) return false;
            var kind = instruction.GetOpKind(instructionOperand);

            switch (kind)
            {
                case OpKind.NearBranch16:
                case OpKind.NearBranch32:
                case OpKind.NearBranch64:
                {
                    string? n = db.RefName(address);
                    if (n == null) return false;
                    ulong head = db.HeadOf(address);
                    var tk = _d.NameKind(head, false);
                    _d._symKinds[n] = tk;
                    symbol = new SymbolResult(address, n, db.Funcs.ContainsKey(address)
                        ? FormatterTextKind.Function : FormatterTextKind.Label);
                    return true;
                }
                case OpKind.Immediate8to16:
                case OpKind.Immediate8to32:
                case OpKind.Immediate8to64:
                case OpKind.Immediate16:
                case OpKind.Immediate32:
                case OpKind.Immediate32to64:
                case OpKind.Immediate64:
                {
                    if (!HasOffsetXref(db, instruction.IP, address)) return false;
                    string? n = db.RefName(address);
                    if (n == null) return false;
                    _d._symKinds[n] = _d.NameKind(db.HeadOf(address), false);
                    symbol = new SymbolResult(address, n, FormatterTextKind.Data);
                    return true;
                }
                case OpKind.Memory:
                {
                    var f = _d._curFunc;
                    var b = instruction.MemoryBase;
                    if (f != null && (IsStackReg(b) || IsFrameReg(b)))
                    {
                        long disp = addressSize == 8 ? (long)instruction.MemoryDisplacement64
                            : (int)instruction.MemoryDisplacement32;
                        int regDelta;
                        if (IsStackReg(b))
                        {
                            if (!f.SpAt.TryGetValue(instruction.IP, out regDelta)) return false;
                        }
                        else
                        {
                            if (!f.BpBased || f.BpDelta == int.MinValue) return false;
                            regDelta = f.BpDelta;
                        }
                        int l = (int)(regDelta + disp);
                        string? vn = _d.StackVarName(f, l);
                        if (vn == null) return false;
                        long kk = -(regDelta + f.FrRegs);
                        if (kk < 0) return false;
                        _d._symKinds[vn] = Tk.LocalVar;
                        if (kk == 0)
                            symbol = new SymbolResult(address, new TextInfo(vn, FormatterTextKind.Data));
                        else
                            symbol = new SymbolResult(address, new TextInfo(new[]
                            {
                                new TextPart(Db.HexNum((ulong)kk), FormatterTextKind.Number),
                                new TextPart("+", FormatterTextKind.Operator),
                                new TextPart(vn, FormatterTextKind.Data),
                            }));
                        return true;
                    }
                    // tablo / taban+adres
                    if (db.IsMapped(address) && HasAnyXref(db, instruction.IP, address))
                    {
                        string? n = db.RefName(address);
                        if (n == null) return false;
                        _d._symKinds[n] = _d.NameKind(db.HeadOf(address), false);
                        symbol = new SymbolResult(address, n, FormatterTextKind.Data);
                        return true;
                    }
                    return false;
                }
            }
            return false;
        }

        private static bool HasOffsetXref(Db db, ulong from, ulong to)
        {
            foreach (var x in db.XrefsFrom(from))
                if (x.To == to && x.Type == XrefType.Offset) return true;
            return false;
        }

        private static bool HasAnyXref(Db db, ulong from, ulong to)
        {
            foreach (var x in db.XrefsFrom(from))
                if (x.To == to) return true;
            return false;
        }
    }
}
