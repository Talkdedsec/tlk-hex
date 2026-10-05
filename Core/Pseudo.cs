using System.Text;
using Iced.Intel;

namespace tlk_hex.Core;

// Basit, goto tabanli pseudocode uretici (Hex-Rays benzeri gorunum, gercek decompiler degil)
public sealed class Pseudo
{
    private readonly Db _db;
    private readonly Disasm _dis;
    private readonly InstructionInfoFactory _iif = new();
    private Function _f = null!;
    private readonly Dictionary<Register, string> _argRegs = new();
    private readonly HashSet<Register> _written = new();
    private readonly Dictionary<string, string> _vars = new();   // isim -> tip/yorum
    private List<Line> _out = new();
    private int _indent = 1;

    private static readonly Register[] X64Args = { Register.RCX, Register.RDX, Register.R8, Register.R9 };

    public Pseudo(Db db, Disasm dis)
    {
        _db = db;
        _dis = dis;
    }

    public List<Line> Decompile(Function f)
    {
        _f = f;
        _argRegs.Clear();
        _written.Clear();
        _vars.Clear();
        var body = new List<Line>();
        _out = body;
        _indent = 1;

        var blocks = FlowGraph.Build(_db, _dis, f);
        DetectArgs(f);

        // etiketler
        var labels = new Dictionary<ulong, string>();
        int ln = 1;
        foreach (var b in blocks.OrderBy(b => b.Start))
            if (b.Start != f.Start && b.Pred.Count > 0 && NeedsLabel(b, blocks))
                labels[b.Start] = "LABEL_" + ln++;

        // giris blogu once, sonra adres sirasi
        var ordered = blocks.OrderBy(b => b.Start == f.Start ? 0 : 1).ThenBy(b => b.Start).ToList();
        for (int bi = 0; bi < ordered.Count; bi++)
        {
            var b = ordered[bi];
            if (labels.TryGetValue(b.Start, out var lab))
            {
                var l = NewLine(b.Start, 0);
                l.Toks.Add(new Tok(lab + ":", Tk.LabelDef));
                body.Add(l);
            }
            EmitBlock(b, labels, bi + 1 < ordered.Count ? ordered[bi + 1].Start : ulong.MaxValue);
        }

        // basliklar
        var res = new List<Line>();
        var hdr = NewLine(f.Start, 0);
        hdr.Toks.Add(new Tok("// tlk-hex basit decompiler: goto tabanlı çeviri, kesin değil", Tk.Cmt));
        res.Add(hdr);
        var sig = NewLine(f.Start, 0);
        string rt = _db.Bitness == 64 ? "__int64" : "int";
        string cc = _db.Bitness == 64 ? "__fastcall" : (f.Purge > 0 ? "__stdcall" : "__cdecl");
        sig.Toks.Add(new Tok(rt + " " + cc + " ", Tk.Kw));
        sig.Toks.Add(new Tok(_db.FuncName(f), Tk.Name));
        sig.Toks.Add(new Tok("(", Tk.Punct));
        var args = ArgList();
        for (int i = 0; i < args.Count; i++)
        {
            if (i > 0) sig.Toks.Add(new Tok(", ", Tk.Punct));
            sig.Toks.Add(new Tok(args[i].type + " ", Tk.Kw));
            sig.Toks.Add(new Tok(args[i].name, Tk.LocalVar));
        }
        sig.Toks.Add(new Tok(")", Tk.Punct));
        res.Add(sig);
        res.Add(Simple(f.Start, "{", Tk.Punct, 0));
        foreach (var kv in _vars.OrderBy(k => k.Key))
        {
            var l = NewLine(f.Start, 1);
            l.Toks.Add(new Tok(kv.Value.Split('|')[0] + " ", Tk.Kw));
            l.Toks.Add(new Tok(kv.Key, Tk.LocalVar));
            l.Toks.Add(new Tok(";", Tk.Punct));
            string c = kv.Value.Contains('|') ? kv.Value.Split('|')[1] : "";
            if (c.Length > 0) l.Toks.Add(new Tok(" // " + c, Tk.Cmt));
            res.Add(l);
        }
        if (_vars.Count > 0) res.Add(NewLine(f.Start, 0));
        res.AddRange(body);
        res.Add(Simple(f.End, "}", Tk.Punct, 0));
        return res;
    }

    private bool NeedsLabel(BBlock b, List<BBlock> blocks)
    {
        foreach (var p in b.Pred)
        {
            var pb = blocks[p];
            foreach (var s in pb.Succ)
                if (blocks[s.To] == b && s.Kind != EdgeKind.False)
                {
                    // dusme yoluyla gelen (hemen onceki blok) etiket istemez
                    if (s.Kind == EdgeKind.Uncond && pb.End == b.Start && !IsJmp(pb.Insns[^1])) continue;
                    return true;
                }
        }
        return false;
    }

    private bool IsJmp(ulong ea) => _dis.TryDecode(ea, out var i) && i.FlowControl is FlowControl.UnconditionalBranch
        or FlowControl.IndirectBranch;

    private List<(string type, string name)> ArgList()
    {
        var l = new List<(string, string)>();
        if (_db.Bitness == 64)
        {
            int n = 0;
            for (int i = 0; i < 4; i++) if (_argRegs.ContainsKey(X64Args[i])) n = i + 1;
            for (int i = 0; i < n; i++) l.Add(("__int64", "a" + (i + 1)));
            foreach (var kv in _f.Vars)
                if (kv.Key >= _db.Ptr + 0x20)
                    l.Add(("__int64", _dis.StackVarName(_f, kv.Key)!));
        }
        else
        {
            foreach (var kv in _f.Vars)
                if (kv.Key >= _db.Ptr) l.Add(("int", _dis.StackVarName(_f, kv.Key)!));
        }
        return l;
    }

    private void DetectArgs(Function f)
    {
        if (_db.Bitness != 64) return;
        var written = new HashSet<Register>();
        foreach (var ea in f.Instrs)
        {
            if (!_dis.TryDecode(ea, out var ins)) continue;
            if (ins.FlowControl is FlowControl.Call or FlowControl.IndirectCall) break;
            var info = _iif.GetInfo(ins);
            foreach (var u in info.GetUsedRegisters())
            {
                var full = u.Register.GetFullRegister();
                int ai = Array.IndexOf(X64Args, full);
                if (ai < 0) continue;
                bool read = u.Access is OpAccess.Read or OpAccess.ReadWrite or OpAccess.CondRead or OpAccess.ReadCondWrite;
                bool selfXor = ins.Mnemonic is Mnemonic.Xor or Mnemonic.Sub && ins.OpCount == 2 && ins.Op0Kind == OpKind.Register
                               && ins.Op1Kind == OpKind.Register && ins.Op0Register == ins.Op1Register;
                if (read && !selfXor && !written.Contains(full)) _argRegs.TryAdd(full, "a" + (ai + 1));
            }
            foreach (var u in info.GetUsedRegisters())
                if (u.Access is OpAccess.Write or OpAccess.ReadWrite)
                    written.Add(u.Register.GetFullRegister());
        }
    }

    private Line NewLine(ulong ea, int indent)
    {
        var l = new Line { Ea = ea };
        if (indent > 0) l.Toks.Add(new Tok(new string(' ', indent * 2), Tk.Text));
        return l;
    }

    private Line Simple(ulong ea, string text, Tk k, int indent)
    {
        var l = NewLine(ea, indent);
        l.Toks.Add(new Tok(text, k));
        return l;
    }

    // ================= Blok =================

    private Instruction? _flagIns;
    private readonly List<string> _pushes = new();
    private readonly List<(Register reg, string expr)> _argSet = new();

    private void EmitBlock(BBlock b, Dictionary<ulong, string> labels, ulong nextStart)
    {
        for (int i = 0; i < b.Insns.Count; i++)
        {
            ulong ea = b.Insns[i];
            if (!_dis.TryDecode(ea, out var ins)) continue;
            Stmt(ins, b, i, labels, nextStart);
        }
    }

    private void Emit(ulong ea, params (string text, Tk kind)[] parts)
    {
        var l = NewLine(ea, _indent);
        foreach (var p in parts) l.Toks.Add(new Tok(p.text, p.kind));
        _out.Add(l);
    }

    private void EmitAsm(in Instruction ins)
    {
        var toks = new List<Tok>();
        _dis.FormatInsn(ins, _f, toks, false);
        var l = NewLine(ins.IP, _indent);
        l.Toks.Add(new Tok("__asm { ", Tk.Kw));
        l.Toks.AddRange(toks);
        l.Toks.Add(new Tok(" }", Tk.Kw));
        _out.Add(l);
    }

    private void Stmt(in Instruction ins, BBlock b, int idx, Dictionary<ulong, string> labels, ulong nextStart)
    {
        var m = ins.Mnemonic;
        ulong ea = ins.IP;

        // yigin cercevesi gurultusu
        if (m is Mnemonic.Push or Mnemonic.Pop && ins.Op0Kind == OpKind.Register)
        {
            var r = ins.Op0Register.GetFullRegister();
            if (_db.Bitness == 32 && m == Mnemonic.Push && !Disasm.IsFrameReg(r)) { _pushes.Add(Op(ins, 0)); return; }
            if (m == Mnemonic.Pop || Disasm.IsFrameReg(r) || IsCalleeSaved(r)) return;
        }
        if (m == Mnemonic.Push) { _pushes.Add(Op(ins, 0)); return; }
        if (m is Mnemonic.Sub or Mnemonic.Add && ins.Op0Kind == OpKind.Register && Disasm.IsStackReg(ins.Op0Register)) return;
        if (m == Mnemonic.Mov && ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register &&
            (Disasm.IsFrameReg(ins.Op0Register) && Disasm.IsStackReg(ins.Op1Register) ||
             Disasm.IsStackReg(ins.Op0Register) && Disasm.IsFrameReg(ins.Op1Register))) return;
        if (m == Mnemonic.Lea && ins.Op0Kind == OpKind.Register && (Disasm.IsFrameReg(ins.Op0Register) || Disasm.IsStackReg(ins.Op0Register))) return;
        if (m is Mnemonic.Nop or Mnemonic.Int3 or Mnemonic.Leave or Mnemonic.Endbr64 or Mnemonic.Endbr32) return;

        switch (m)
        {
            case Mnemonic.Mov:
            case Mnemonic.Movaps:
            case Mnemonic.Movups:
            case Mnemonic.Movdqa:
            case Mnemonic.Movdqu:
            case Mnemonic.Movq:
            case Mnemonic.Movd:
            case Mnemonic.Movss:
            case Mnemonic.Movsd when ins.OpCount == 2:
                Assign(ins, Op(ins, 1));
                return;
            case Mnemonic.Movzx:
                Assign(ins, Cast(ins, true) + Op(ins, 1));
                return;
            case Mnemonic.Movsx:
            case Mnemonic.Movsxd:
                Assign(ins, Cast(ins, false) + Op(ins, 1));
                return;
            case Mnemonic.Lea:
                Assign(ins, Addr(ins));
                return;
            case Mnemonic.Xor when ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register && ins.Op0Register == ins.Op1Register:
            case Mnemonic.Sub when ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register && ins.Op0Register == ins.Op1Register:
                Assign(ins, "0");
                _flagIns = ins;
                return;
            case Mnemonic.Add: Compound(ins, "+="); return;
            case Mnemonic.Sub: Compound(ins, "-="); return;
            case Mnemonic.And: Compound(ins, "&="); return;
            case Mnemonic.Or: Compound(ins, "|="); return;
            case Mnemonic.Xor: Compound(ins, "^="); return;
            case Mnemonic.Shl:
            case Mnemonic.Sal: Compound(ins, "<<="); return;
            case Mnemonic.Shr:
            case Mnemonic.Sar: Compound(ins, ">>="); return;
            case Mnemonic.Imul:
                if (ins.OpCount == 2) { Compound(ins, "*="); return; }
                if (ins.OpCount == 3) { Assign(ins, Op(ins, 1) + " * " + Op(ins, 2)); _flagIns = ins; return; }
                break;
            case Mnemonic.Inc: Emit(ea, ("++" + Op(ins, 0), Tk.Text), (";", Tk.Punct)); Written(ins); _flagIns = ins; return;
            case Mnemonic.Dec: Emit(ea, ("--" + Op(ins, 0), Tk.Text), (";", Tk.Punct)); Written(ins); _flagIns = ins; return;
            case Mnemonic.Neg: Assign(ins, "-" + Op(ins, 0)); _flagIns = ins; return;
            case Mnemonic.Not: Assign(ins, "~" + Op(ins, 0)); return;
            case Mnemonic.Cmp:
            case Mnemonic.Test:
            case Mnemonic.Bt:
            case Mnemonic.Ucomiss:
            case Mnemonic.Ucomisd:
            case Mnemonic.Comiss:
            case Mnemonic.Comisd:
                _flagIns = ins;
                return;
            case Mnemonic.Call:
                CallStmt(ins, b, idx);
                return;
            case Mnemonic.Ret:
                Emit(ea, ("return ", Tk.Kw), (_db.Bitness == 64 ? Reg(Register.RAX, Register.RAX) : Reg(Register.EAX, Register.EAX), Tk.LocalVar), (";", Tk.Punct));
                return;
            case Mnemonic.Jmp:
                if (ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
                {
                    ulong t = ins.NearBranchTarget;
                    if (_db.Funcs.ContainsKey(t) && t != _f.Start)
                    {
                        Emit(ea, ("return ", Tk.Kw), (_db.RefName(t) ?? Db.HexNum(t), Tk.Name), ("(" + CallArgs() + ");", Tk.Punct));
                        return;
                    }
                    if (t == nextStart) return;
                    Emit(ea, ("goto ", Tk.Kw), (labels.GetValueOrDefault(t) ?? (_db.RefName(t) ?? Db.HexNum(t)), Tk.LabelDef), (";", Tk.Punct));
                    return;
                }
                if (_db.XrefsFrom(ea).Any(x => x.Type == XrefType.Jump && !_db.ImportAt.ContainsKey(x.To)))
                {
                    Emit(ea, ("switch ( ", Tk.Kw), ("...", Tk.Text), (" )", Tk.Kw), ("  // jump table", Tk.Cmt));
                    foreach (var x in _db.XrefsFrom(ea).Where(x => x.Type == XrefType.Jump).DistinctBy(x => x.To))
                        Emit(ea, ("  case: ", Tk.Kw), ("goto ", Tk.Kw), (labels.GetValueOrDefault(x.To) ?? _db.RefName(x.To) ?? "", Tk.LabelDef), (";", Tk.Punct));
                    return;
                }
                if (ins.Op0Kind == OpKind.Memory && _dis.MemTarget(ins) is ulong sl && _db.ImportAt.ContainsKey(sl))
                {
                    Emit(ea, ("return ", Tk.Kw), (_db.NameAt(sl) ?? "", Tk.ImportName), ("(" + CallArgs() + ");", Tk.Punct));
                    return;
                }
                Emit(ea, ("__asm { jmp " + Op(ins, 0) + " }", Tk.Kw));
                return;
        }

        if (ins.FlowControl == FlowControl.ConditionalBranch && ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            ulong t = ins.NearBranchTarget;
            string cond = Cond(ins.ConditionCode);
            Emit(ea, ("if ( ", Tk.Kw), (cond, Tk.Text), (" )", Tk.Kw));
            var l = NewLine(ea, _indent + 1);
            l.Toks.Add(new Tok("goto ", Tk.Kw));
            l.Toks.Add(new Tok(labels.GetValueOrDefault(t) ?? (_db.RefName(t) ?? Db.HexNum(t)), Tk.LabelDef));
            l.Toks.Add(new Tok(";", Tk.Punct));
            _out.Add(l);
            return;
        }

        if (ins.Mnemonic.ToString().StartsWith("Set"))
        {
            if (ins.ConditionCode != ConditionCode.None)
            {
                Assign(ins, Cond(ins.ConditionCode));
                return;
            }
        }
        if (ins.Mnemonic.ToString().StartsWith("Cmov") && ins.ConditionCode != ConditionCode.None)
        {
            Emit(ea, ("if ( ", Tk.Kw), (Cond(ins.ConditionCode), Tk.Text), (" )", Tk.Kw));
            _indent++;
            Assign(ins, Op(ins, 1));
            _indent--;
            return;
        }
        EmitAsm(ins);
    }

    private static bool IsCalleeSaved(Register r) => r is Register.RBX or Register.RSI or Register.RDI or Register.R12
        or Register.R13 or Register.R14 or Register.R15 or Register.EBX or Register.ESI or Register.EDI;

    private void Assign(in Instruction ins, string rhs)
    {
        if (ins.OpCount > 0 && ins.Op0Kind == OpKind.Register) _written.Add(ins.Op0Register.GetFullRegister());
        string lhs = Op(ins, 0);
        Emit(ins.IP, (lhs, Tk.LocalVar), (" = ", Tk.Punct), (rhs, Tk.Text), (";", Tk.Punct));
        Written(ins, rhs);
    }

    private void Compound(in Instruction ins, string op)
    {
        Emit(ins.IP, (Op(ins, 0), Tk.LocalVar), (" " + op + " ", Tk.Punct), (Op(ins, 1), Tk.Text), (";", Tk.Punct));
        Written(ins);
        _flagIns = ins;
    }

    private void Written(in Instruction ins, string? value = null)
    {
        if (ins.OpCount > 0 && ins.Op0Kind == OpKind.Register)
        {
            var full = ins.Op0Register.GetFullRegister();
            _written.Add(full);
            int ai = Array.IndexOf(X64Args, full);
            // arguman olarak atanan degeri (sabit/string/adres) dogrudan cagriya tasi
            if (ai >= 0 && _db.Bitness == 64) _argSet.Add((full, value ?? Op(ins, 0)));
        }
    }

    private void CallStmt(in Instruction ins, BBlock b, int idx)
    {
        string callee;
        Tk ck = Tk.Name;
        if (ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64)
        {
            callee = _db.RefName(ins.NearBranchTarget) ?? Db.HexNum(ins.NearBranchTarget);
            if (_db.Funcs.TryGetValue(ins.NearBranchTarget, out var cf) && cf.IsThunk) ck = Tk.ImportName;
        }
        else if (ins.Op0Kind == OpKind.Memory && _dis.MemTarget(ins) is ulong sl && _db.IsMapped(sl))
        {
            callee = _db.RefName(sl) ?? Db.HexNum(sl);
            if (_db.ImportAt.ContainsKey(sl)) ck = Tk.ImportName;
        }
        else callee = "(*" + Op(ins, 0) + ")";

        string args = CallArgs();
        string ret = _db.Bitness == 64 ? "rax" : "eax";
        bool used = ResultUsed(b, idx);
        if (used)
        {
            Declare(ret, _db.Bitness == 64 ? "__int64" : "int", "");
            Emit(ins.IP, (ret, Tk.LocalVar), (" = ", Tk.Punct), (callee, ck), ("(" + args + ");", Tk.Punct));
        }
        else Emit(ins.IP, (callee, ck), ("(" + args + ");", Tk.Punct));
        _written.Add(Register.RAX);
        _written.Add(Register.EAX);
    }

    private string CallArgs()
    {
        string s;
        if (_db.Bitness == 64)
        {
            var parts = new List<string>();
            int max = -1;
            foreach (var a in _argSet) max = Math.Max(max, Array.IndexOf(X64Args, a.reg));
            for (int i = 0; i <= max; i++)
            {
                var last = _argSet.LastOrDefault(a => a.reg == X64Args[i]);
                parts.Add(last.expr ?? Reg(X64Args[i], X64Args[i]));
            }
            s = string.Join(", ", parts);
        }
        else
        {
            var p = _pushes.ToList();
            p.Reverse();
            s = string.Join(", ", p);
        }
        _argSet.Clear();
        _pushes.Clear();
        return s;
    }

    private bool ResultUsed(BBlock b, int idx)
    {
        for (int i = idx + 1; i < b.Insns.Count; i++)
        {
            if (!_dis.TryDecode(b.Insns[i], out var n)) break;
            var info = _iif.GetInfo(n);
            foreach (var u in info.GetUsedRegisters())
            {
                if (u.Register.GetFullRegister() != Register.RAX) continue;
                if (u.Access is OpAccess.Read or OpAccess.ReadWrite or OpAccess.CondRead or OpAccess.ReadCondWrite) return true;
                if (u.Access == OpAccess.Write) return false;
            }
            if (n.FlowControl is FlowControl.Call or FlowControl.IndirectCall) return false;
        }
        return true;
    }

    private string Cond(ConditionCode cc)
    {
        string a = "?", b = "0";
        bool test = false, cmp = false;
        if (_flagIns is Instruction fi)
        {
            if (fi.Mnemonic == Mnemonic.Cmp || fi.Mnemonic.ToString().Contains("comis"))
            {
                a = Op(fi, 0); b = Op(fi, 1); cmp = true;
            }
            else if (fi.Mnemonic == Mnemonic.Test)
            {
                test = true;
                a = Op(fi, 0);
                b = Op(fi, 1);
                if (fi.Op0Kind == OpKind.Register && fi.Op1Kind == OpKind.Register && fi.Op0Register == fi.Op1Register)
                    b = "";
            }
            else if (fi.OpCount > 0) a = Op(fi, 0);
        }
        if (test)
        {
            string v = b.Length == 0 ? a : $"({a} & {b})";
            return cc switch
            {
                ConditionCode.e => b.Length == 0 ? "!" + a : v + " == 0",
                ConditionCode.ne => b.Length == 0 ? a : v + " != 0",
                ConditionCode.s or ConditionCode.l => v + " < 0",
                ConditionCode.ns or ConditionCode.ge => v + " >= 0",
                ConditionCode.le => v + " <= 0",
                ConditionCode.g => v + " > 0",
                _ => $"{v} /*{cc}*/",
            };
        }
        if (!cmp) { b = "0"; }
        return cc switch
        {
            ConditionCode.e => $"{a} == {b}",
            ConditionCode.ne => $"{a} != {b}",
            ConditionCode.l => $"(signed){a} < {b}",
            ConditionCode.ge => $"(signed){a} >= {b}",
            ConditionCode.le => $"(signed){a} <= {b}",
            ConditionCode.g => $"(signed){a} > {b}",
            ConditionCode.b => $"(unsigned){a} < {b}",
            ConditionCode.ae => $"(unsigned){a} >= {b}",
            ConditionCode.be => $"(unsigned){a} <= {b}",
            ConditionCode.a => $"(unsigned){a} > {b}",
            ConditionCode.s => $"{a} < 0",
            ConditionCode.ns => $"{a} >= 0",
            ConditionCode.o => $"__OFSUB__({a}, {b})",
            ConditionCode.no => $"!__OFSUB__({a}, {b})",
            ConditionCode.p => $"__SETP__({a}, {b})",
            ConditionCode.np => $"!__SETP__({a}, {b})",
            _ => "?",
        };
    }

    private string Cast(in Instruction ins, bool unsigned)
    {
        int sz = ins.Op1Kind == OpKind.Memory ? Disasm.MemBytes(ins) : ins.Op1Register.GetSize();
        return (unsigned, sz) switch
        {
            (true, 1) => "(unsigned __int8)",
            (true, 2) => "(unsigned __int16)",
            (false, 1) => "(char)",
            (false, 2) => "(__int16)",
            (false, 4) => "(int)",
            _ => "",
        };
    }

    private void Declare(string name, string type, string cmt)
    {
        if (!_vars.ContainsKey(name)) _vars[name] = type + (cmt.Length > 0 ? "|" + cmt : "");
    }

    private string Reg(Register r, Register full)
    {
        string n;
        if (_db.Bitness == 64 && !_written.Contains(full) && _argRegs.TryGetValue(full, out var an)) n = an;
        else
        {
            n = full.ToString().ToLowerInvariant();
            bool frame = Disasm.IsFrameReg(full) && _f.BpBased;
            if (!Disasm.IsStackReg(full) && !frame)
            {
                int fs = full.GetSize();
                Declare(n, fs switch { 8 => "__int64", 4 => "int", 16 => "__m128", 32 => "__m256", _ => "int" }, "register");
            }
        }
        int sz = r.GetSize();
        if (sz >= 4 || sz == full.GetSize()) return n;
        if (sz == 2) return $"LOWORD({n})";
        return r is Register.AH or Register.BH or Register.CH or Register.DH ? $"BYTE1({n})" : $"LOBYTE({n})";
    }

    // Operand -> ifade
    private string Op(in Instruction ins, int i)
    {
        var k = ins.GetOpKind(i);
        switch (k)
        {
            case OpKind.Register:
                return Reg(ins.GetOpRegister(i), ins.GetOpRegister(i).GetFullRegister());
            case OpKind.Memory:
                return Mem(ins, false);
            case OpKind.NearBranch16:
            case OpKind.NearBranch32:
            case OpKind.NearBranch64:
                return _db.RefName(ins.NearBranchTarget) ?? Db.HexNum(ins.NearBranchTarget);
            default:
                if (k.ToString().StartsWith("Immediate"))
                {
                    ulong v = ins.GetImmediate(i);
                    foreach (var x in _db.XrefsFrom(ins.IP))
                        if (x.To == v && x.Type == XrefType.Offset)
                        {
                            var s = _db.StringAt(v);
                            if (s != null) return "\"" + Db.Escape(s, 80) + "\"";
                            return (_db.IsCodeSeg(v) ? "" : "&") + (_db.RefName(v) ?? Db.HexNum(v));
                        }
                    return Num(v, ins);
                }
                return "?";
        }
    }

    private static string Num(ulong v, in Instruction ins)
    {
        long sv = ins.GetOpKind(1) is OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64 ? (long)v : (long)v;
        if (sv < 0 && sv > -0x10000) return "-" + C((ulong)(-sv));
        return C(v);
    }

    private static string C(ulong v) => v < 10 ? v.ToString() : "0x" + v.ToString("X");

    private string SizeCast(int n) => n switch
    {
        1 => "_BYTE", 2 => "_WORD", 4 => "_DWORD", 8 => "_QWORD", 16 => "_OWORD", 10 => "_TBYTE", _ => "_BYTE",
    };

    private string Mem(in Instruction ins, bool addrOf)
    {
        var b = ins.MemoryBase;
        long disp = _db.Bitness == 64 ? (long)ins.MemoryDisplacement64 : (int)ins.MemoryDisplacement32;
        // yigin degiskeni
        if ((Disasm.IsStackReg(b) || Disasm.IsFrameReg(b)) && ins.MemoryIndex == Register.None)
        {
            int delta = int.MinValue;
            if (Disasm.IsStackReg(b) && _f.SpAt.TryGetValue(ins.IP, out var sp)) delta = sp;
            else if (Disasm.IsFrameReg(b) && _f.BpBased && _f.BpDelta != int.MinValue) delta = _f.BpDelta;
            if (delta != int.MinValue)
            {
                int l = (int)(delta + disp);
                string? vn = _dis.StackVarName(_f, l);
                if (vn != null)
                {
                    int sz = Disasm.MemBytes(ins);
                    Declare(vn, sz switch { 1 => "char", 2 => "__int16", 4 => "int", 8 => "__int64", 16 => "__m128", _ => "_BYTE" },
                        $"[{b.ToString().ToLowerInvariant()}{(disp >= 0 ? "+" : "-")}{Math.Abs(disp):X}h]");
                    return addrOf ? "&" + vn : vn;
                }
            }
        }
        // global
        ulong? tgt = ins.IsIPRelativeMemoryOperand ? ins.IPRelativeMemoryAddress
            : b == Register.None && ins.MemoryIndex == Register.None ? (ulong)disp : null;
        if (tgt is ulong t && _db.IsMapped(t))
        {
            var s = _db.StringAt(t);
            if (addrOf && s != null) return "\"" + Db.Escape(s, 80) + "\"";
            string n = _db.RefName(t) ?? Db.HexNum(t);
            return addrOf ? "&" + n : n;
        }
        // genel ifade
        var sb = new StringBuilder();
        if (b != Register.None && !(b is Register.RIP or Register.EIP)) sb.Append(Reg(b, b.GetFullRegister()));
        if (ins.MemoryIndex != Register.None)
        {
            if (sb.Length > 0) sb.Append(" + ");
            if (ins.MemoryIndexScale > 1) sb.Append(ins.MemoryIndexScale).Append(" * ");
            sb.Append(Reg(ins.MemoryIndex, ins.MemoryIndex.GetFullRegister()));
        }
        if (disp != 0 || sb.Length == 0)
        {
            if (sb.Length > 0) sb.Append(disp < 0 ? " - " : " + ").Append(C((ulong)Math.Abs(disp)));
            else sb.Append(C((ulong)disp));
        }
        if (addrOf) return sb.ToString();
        int msz = Disasm.MemBytes(ins);
        return $"*({SizeCast(msz)} *)({sb})";
    }

    private string Addr(in Instruction ins) => Mem(ins, true);
}
