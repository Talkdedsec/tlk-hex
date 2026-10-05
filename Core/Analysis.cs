using Iced.Intel;

namespace tlk_hex.Core;

// Otomatik analiz: recursive descent, fonksiyonlar, xref'ler, veri/string ogeleri,
// switch tablolari, yigin degiskenleri. Kullanici islemleri (C/D/U/A/P/O) de burada.
public sealed class AutoAnalysis
{
    private readonly Db _db;
    private readonly Disasm _dis;
    private readonly Queue<ulong> _fq = new();
    private readonly HashSet<ulong> _queued = new();
    private readonly InstructionInfoFactory _iif = new();

    public Action<string>? Progress;
    public List<ulong> ExtraSeeds = new();   // PDB fonksiyonlari
    public int MinStrLen = 5;

    private static readonly HashSet<string> NoRetNames = new(StringComparer.Ordinal)
    {
        "ExitProcess", "exit", "_exit", "_Exit", "abort", "ExitThread", "FreeLibraryAndExitThread",
        "_CxxThrowException", "__std_terminate", "terminate", "_invalid_parameter_noinfo_noreturn",
        "__report_rangecheckfailure", "__report_gsfailure", "RtlExitUserProcess", "RtlExitUserThread",
        "longjmp", "_longjmp", "__stack_chk_fail", "quick_exit", "__assert_fail", "__cxa_throw",
        "__cxa_rethrow", "FatalExit", "FatalAppExitA", "FatalAppExitW", "_amsg_exit", "RaiseFailFastException",
        "__fastfail", "_assert", "_wassert", "__fortify_fail", "__chk_fail", "pthread_exit", "ExitWindows",
        "RtlRaiseStatus", "KeBugCheckEx", "KeBugCheck", "__security_check_cookie_fail", "_purecall",
        "__scrt_fastfail", "?terminate@@YAXXZ", "_ZSt9terminatev", "__cxa_bad_cast", "__cxa_bad_typeid",
        "__cxa_pure_virtual", "_Unwind_Resume", "__libc_start_main", "_Xlength_error", "_Xout_of_range",
        "?_Xlength_error@std@@YAXPEBD@Z", "?_Xout_of_range@std@@YAXPEBD@Z", "?_Xbad_alloc@std@@YAXXZ",
    };

    public AutoAnalysis(Db db, Disasm dis)
    {
        _db = db;
        _dis = dis;
    }

    // ================= Ana akis =================

    public void Run(Action<string> log)
    {
        MarkExterns();
        if (!_db.CanDisasm)
        {
            log($"  Bu işlemci ({_db.Machine}) için disassembler yok; sadece veri olarak yüklendi.");
            BuildStrings();
            return;
        }

        if (_db.Entry != ulong.MaxValue) QueueFunc(_db.Entry);
        foreach (var e in _db.Entries) QueueFunc(e.Ea);
        foreach (var p in _db.PdataEnds.Keys.OrderBy(x => x)) QueueFunc(p);
        foreach (var p in ExtraSeeds) QueueFunc(p);
        Drain();
        Progress?.Invoke("İşaretçiler taranıyor...");
        RelocPass();
        Drain();
        Progress?.Invoke("Fonksiyon girişleri taranıyor...");
        PrologueScan();
        Drain();
        FinalizeFunctions();
        AlignPass();
        BuildStrings();
        log($"  {_db.Funcs.Count:N0} fonksiyon, {_db.XFrom.Count:N0} xref kaynağı, {_db.Strings.Count:N0} string bulundu.");
    }

    private void MarkExterns()
    {
        foreach (var imp in _db.Imports)
        {
            var s = _db.SegOf(imp.Ea);
            if (s == null) continue;
            long o = (long)(imp.Ea - s.Start);
            if (!_db.RangeFree(s, o, _db.Ptr)) continue;
            if (!imp.Delay && _db.LoaderId == "pe")
                _db.SetItem(s, o, _db.Ptr, ItemKind.Extern);
            else
                _db.SetItem(s, o, _db.Ptr, _db.Ptr == 8 ? ItemKind.Qword : ItemKind.Dword, true);
        }
    }

    private void QueueFunc(ulong ea)
    {
        if (_queued.Add(ea)) _fq.Enqueue(ea);
    }

    private void Drain()
    {
        int n = 0;
        while (_fq.Count > 0)
        {
            var ea = _fq.Dequeue();
            MakeFunction(ea);
            if (++n % 2000 == 0) Progress?.Invoke($"AU: {_db.Funcs.Count:N0} fonksiyon, kuyruk {_fq.Count:N0}");
        }
    }

    // ================= Fonksiyon olusturma =================

    public Function? MakeFunction(ulong start)
    {
        if (_db.Funcs.TryGetValue(start, out var exist)) return exist;
        var s = _db.SegOf(start);
        if (s == null || !s.X) return null;
        long o0 = (long)(start - s.Start);
        if (o0 >= s.InitSize) return null;
        byte fl = s.F[o0];
        if ((fl & FF.Tail) != 0) return null;
        if (fl != 0 && (fl & FF.KindMask) != (byte)ItemKind.Code) return null;
        if (fl != 0 && s.Owner[o0] >= 0) return null;
        if (!_dis.TryDecode(start, out _)) return null;

        var f = new Function { Start = start, Index = _db.FuncList.Count };
        _db.Funcs[start] = f;
        _db.FuncList.Add(f);
        Trace(start, f);
        f.Instrs.Sort();
        return f;
    }

    // Akisi izleyerek kod olustur; f null ise fonksiyonsuz kod (C komutu)
    private void Trace(ulong start, Function? f)
    {
        int fi = f?.Index ?? -1;
        var work = new Stack<(ulong ea, int sp)>();
        work.Push((start, 0));
        var ring = new Instruction[8];

        while (work.Count > 0)
        {
            var (ea, sp) = work.Pop();
            int ringN = 0;
            while (true)
            {
                var seg = _db.SegOf(ea);
                if (seg == null || !seg.X) break;
                long o = (long)(ea - seg.Start);
                if (o >= seg.InitSize) break;
                byte b = seg.F[o];
                bool reclaim = false;
                if (b != 0)
                {
                    bool codeHead = (b & FF.Head) != 0 && (b & FF.KindMask) == (byte)ItemKind.Code;
                    if (f != null && codeHead && seg.Owner[o] < 0 && (ea == start || !_db.Funcs.ContainsKey(ea)))
                        reclaim = true;
                    else break;
                }
                if (ea != start && _db.Funcs.ContainsKey(ea)) break;
                if (!_dis.TryDecode(ea, out var ins)) break;
                int len = ins.Length;
                if (reclaim)
                {
                    if (Db.ItemSize(seg, o) != len) break;
                    _db.RemoveXrefsFrom(ea);
                }
                else if (!_db.RangeFree(seg, o, len)) break;

                _db.SetItem(seg, o, len, ItemKind.Code);
                if (f != null)
                {
                    for (int i = 0; i < len; i++) seg.Owner[o + i] = fi;
                    f.Instrs.Add(ea);
                    StackEffect(f, ins, ref sp);
                }

                bool stop = Flow(f, ins, sp, work, ring, ringN);
                DataRefs(ins);
                ring[ringN % ring.Length] = ins;
                ringN++;
                if (stop) break;
                ea = ins.NextIP;
            }
        }
    }

    private static bool IsNearBranch(in Instruction ins) =>
        ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64;

    private void PushTarget(ulong t, int sp, Stack<(ulong, int)> work)
    {
        var s = _db.SegOf(t);
        if (s == null || !s.X) return;
        work.Push((t, sp));
    }

    // Akis kontrolu; true = bu yol burada biter
    private bool Flow(Function? f, in Instruction ins, int sp, Stack<(ulong, int)> work, Instruction[] ring, int ringN)
    {
        ulong ea = ins.IP;
        switch (ins.FlowControl)
        {
            case FlowControl.Next:
                return ins.Mnemonic == Mnemonic.Hlt;

            case FlowControl.ConditionalBranch:
                if (IsNearBranch(ins))
                {
                    ulong t = ins.NearBranchTarget;
                    _db.AddXref(ea, t, XrefType.Jump);
                    PushTarget(t, sp, work);
                }
                return false;

            case FlowControl.UnconditionalBranch:
                if (IsNearBranch(ins))
                {
                    ulong t = ins.NearBranchTarget;
                    _db.AddXref(ea, t, XrefType.Jump);
                    if (f != null && t != f.Start && _db.Funcs.ContainsKey(t)) return true; // tail call
                    PushTarget(t, sp, work);
                }
                return true;

            case FlowControl.IndirectBranch:
            {
                var slot = _dis.MemTarget(ins);
                if (ins.Op0Kind == OpKind.Memory && slot is ulong sl && _db.IsMapped(sl))
                {
                    bool imp = _db.ImportAt.ContainsKey(sl);
                    _db.AddXref(ea, sl, imp ? XrefType.Jump : XrefType.Read);
                    if (!imp) TrySwitch(f, ins, sp, work, ring, ringN);
                }
                else TrySwitch(f, ins, sp, work, ring, ringN);
                return true;
            }

            case FlowControl.Call:
                if (IsNearBranch(ins))
                {
                    ulong t = ins.NearBranchTarget;
                    _db.AddXref(ea, t, XrefType.Call);
                    QueueFunc(t);
                    if (IsNoRetTarget(t)) return true;
                }
                return false;

            case FlowControl.IndirectCall:
            {
                var slot = _dis.MemTarget(ins);
                if (ins.Op0Kind == OpKind.Memory && slot is ulong sl && _db.IsMapped(sl))
                {
                    bool imp = _db.ImportAt.TryGetValue(sl, out var ii);
                    _db.AddXref(ea, sl, imp ? XrefType.Call : XrefType.Read);
                    if (imp && NoRetNames.Contains(ii!.Name)) return true;
                    if (!imp) MakeDataAt(sl, _db.Ptr, MemorySize.Unknown, false);
                }
                return false;
            }

            case FlowControl.Return:
                if (f != null)
                {
                    f.HasRet = true;
                    if (ins.OpCount == 1 && ins.Op0Kind == OpKind.Immediate16) f.Purge = ins.Immediate16;
                }
                return true;

            case FlowControl.Interrupt:
                if (ins.Mnemonic == Mnemonic.Int3) return true;
                if (ins.Mnemonic == Mnemonic.Int && ins.Op0Kind == OpKind.Immediate8 && ins.Immediate8 == 0x29) return true;
                return false;

            case FlowControl.Exception:
                return true;

            default:
                return false;
        }
    }

    private bool IsNoRetTarget(ulong t)
    {
        if (_db.Funcs.TryGetValue(t, out var f) && f.NoReturn) return true;
        string? n = _db.UserNames.GetValueOrDefault(t) ?? _db.LoaderNames.GetValueOrDefault(t);
        if (n != null && NoRetNames.Contains(n)) return true;
        // jmp [import] thunk mi?
        if (_dis.TryDecode(t, out var ins) && ins.Mnemonic == Mnemonic.Jmp && ins.Op0Kind == OpKind.Memory)
        {
            var sl = _dis.MemTarget(ins);
            if (sl is ulong s && _db.ImportAt.TryGetValue(s, out var ii) && NoRetNames.Contains(ii.Name)) return true;
        }
        return false;
    }

    // ================= Veri referanslari =================

    private bool HasRelocIn(ulong ea, int len)
    {
        if (_db.Relocs.Count == 0) return false;
        for (int i = 0; i < len; i++) if (_db.Relocs.Contains(ea + (ulong)i)) return true;
        return false;
    }

    private void DataRefs(in Instruction ins)
    {
        ulong ea = ins.IP;
        int len = ins.Length;
        var fc = ins.FlowControl;
        for (int i = 0; i < ins.OpCount; i++)
        {
            var k = ins.GetOpKind(i);
            if (k == OpKind.Memory)
            {
                if (fc is FlowControl.IndirectBranch or FlowControl.IndirectCall) continue;
                ulong? tgt = null;
                if (ins.IsIPRelativeMemoryOperand) tgt = ins.IPRelativeMemoryAddress;
                else if (ins.MemoryBase == Register.None && ins.SegmentPrefix is not (Register.FS or Register.GS))
                    tgt = _db.Bitness == 64 ? ins.MemoryDisplacement64 : ins.MemoryDisplacement32;
                else if (_db.Bitness == 32 && ins.MemoryBase != Register.None && HasRelocIn(ea, len))
                    tgt = ins.MemoryDisplacement32;
                if (tgt is ulong t && _db.IsMapped(t))
                {
                    XrefType xt;
                    if (ins.Mnemonic == Mnemonic.Lea) xt = XrefType.Offset;
                    else if (i == 0 && IsWrite(ins)) xt = XrefType.Write;
                    else xt = XrefType.Read;
                    _db.AddXref(ea, t, xt);
                    MakeDataAt(t, Disasm.MemBytes(ins), ins.MemorySize, xt == XrefType.Offset);
                }
            }
            else if (k is OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate32to64)
            {
                ulong v = ins.GetImmediate(i);
                if (_db.ImageBase < 0x10000) continue;      // PIE: sabitlerle karisir
                if (!_db.IsMapped(v)) continue;
                if (_db.Relocs.Count > 0 && !HasRelocIn(ea, len)) continue;
                if (fc is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch or FlowControl.Call) continue;
                _db.AddXref(ea, v, XrefType.Offset);
                if (_db.IsCodeSeg(v)) QueueFunc(v);
                else MakeDataAt(v, 0, MemorySize.Unknown, true);
            }
        }
    }

    private bool IsWrite(in Instruction ins)
    {
        try
        {
            var info = _iif.GetInfo(ins);
            var a = info.Op0Access;
            return a is OpAccess.Write or OpAccess.ReadWrite or OpAccess.CondWrite or OpAccess.ReadCondWrite;
        }
        catch { return false; }
    }

    private void MakeDataAt(ulong t, int msz, MemorySize ms, bool offsetRef)
    {
        var s = _db.SegOf(t);
        if (s == null) return;
        long o = (long)(t - s.Start);
        if (s.F[o] != 0) return;
        if (s.X)
        {
            if (offsetRef) QueueFunc(t);
            return;
        }
        if (s.IsInit(o) && (offsetRef || msz <= 2) && TryString(s, o, 4, out int slen, out bool wide))
        {
            SetString(s, o, slen, wide);
            return;
        }

        ItemKind k = ms switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => ItemKind.Byte,
            MemorySize.UInt16 or MemorySize.Int16 => ItemKind.Word,
            MemorySize.UInt32 or MemorySize.Int32 or MemorySize.DwordOffset => ItemKind.Dword,
            MemorySize.Float32 => ItemKind.Float,
            MemorySize.UInt64 or MemorySize.Int64 or MemorySize.QwordOffset => ItemKind.Qword,
            MemorySize.Float64 => ItemKind.Double,
            MemorySize.UInt128 or MemorySize.Packed128_Float32 or MemorySize.Packed128_Float64
                or MemorySize.Packed128_Int32 or MemorySize.Packed128_UInt64 or MemorySize.Packed128_Int64
                or MemorySize.Packed128_UInt32 or MemorySize.Packed128_UInt8 or MemorySize.Packed128_Int8
                or MemorySize.Packed128_UInt16 or MemorySize.Packed128_Int16 => ItemKind.Oword,
            _ => ItemKind.Unknown,
        };
        if (k == ItemKind.Unknown && msz == _db.Ptr) k = _db.Ptr == 8 ? ItemKind.Qword : ItemKind.Dword;
        if (k == ItemKind.Unknown) return;
        int size = Disasm.KindSize(k, _db.Ptr);
        if (!_db.RangeFree(s, o, size)) return;

        bool isOff = false;
        bool ptrSized = (k == ItemKind.Qword && _db.Ptr == 8) || (k == ItemKind.Dword && _db.Ptr == 4);
        if (ptrSized && s.IsInit(o) && _db.TryReadPtr(t, out var v) && _db.IsMapped(v) && _db.ImageBase >= 0x10000
            && (_db.Relocs.Count == 0 || _db.Relocs.Contains(t)))
        {
            isOff = true;
            _db.AddXref(t, v, XrefType.Offset);
            if (_db.IsCodeSeg(v)) QueueFunc(v);
        }
        _db.SetItem(s, o, size, k, isOff);
    }

    private static bool Printable(byte b) => (b >= 0x20 && b < 0x7F) || b is 9 or 10 or 13;

    private bool TryString(Segment s, long o, int minLen, out int size, out bool wide)
    {
        size = 0;
        wide = false;
        // UTF-16LE
        if (o + 3 < s.InitSize && s.Data[o + 1] == 0 && Printable(s.Data[o]))
        {
            long p = o;
            int n = 0;
            while (p + 1 < s.InitSize && s.Data[p + 1] == 0 && Printable(s.Data[p]) && n < 4096) { p += 2; n++; }
            if (n >= minLen && p + 1 < s.InitSize && s.Data[p] == 0 && s.Data[p + 1] == 0)
            {
                size = (n + 1) * 2;
                wide = true;
                if (_db.RangeFree(s, o, size)) return true;
            }
        }
        {
            long p = o;
            int n = 0;
            while (p < s.InitSize && Printable(s.Data[p]) && n < 4096) { p++; n++; }
            if (n >= minLen && p < s.InitSize && s.Data[p] == 0)
            {
                size = n + 1;
                wide = false;
                return _db.RangeFree(s, o, size);
            }
        }
        return false;
    }

    private void SetString(Segment s, long o, int size, bool wide)
    {
        ulong ea = s.Start + (ulong)o;
        _db.SetItem(s, o, size, wide ? ItemKind.Utf16 : ItemKind.Ascii);
        _db.MakeStrName(ea, wide ? _db.ReadUtf16(ea, 64) : _db.ReadAscii(ea, 64));
    }

    // ================= Yigin =================

    private void StackEffect(Function f, in Instruction ins, ref int sp)
    {
        int ptr = _db.Ptr;
        for (int i = 0; i < ins.OpCount; i++)
        {
            if (ins.GetOpKind(i) != OpKind.Memory) continue;
            var b = ins.MemoryBase;
            long disp = _db.Bitness == 64 ? (long)ins.MemoryDisplacement64 : (int)ins.MemoryDisplacement32;
            int l;
            if (Disasm.IsStackReg(b))
            {
                l = (int)(sp + disp);
                f.SpAt[ins.IP] = sp;
            }
            else if (Disasm.IsFrameReg(b) && f.BpBased && f.BpDelta != int.MinValue) l = (int)(f.BpDelta + disp);
            else break;
            if (ins.MemoryIndex != Register.None) break;
            int size = Math.Max(1, Disasm.MemBytes(ins));
            if (size > 64) size = ptr;
            if (l >= ptr || l + f.FrRegs < 0)
                f.Vars[l] = Math.Max(f.Vars.GetValueOrDefault(l), size);
            break;
        }

        switch (ins.Mnemonic)
        {
            case Mnemonic.Push:
            case Mnemonic.Pushf:
            case Mnemonic.Pushfd:
            case Mnemonic.Pushfq:
            case Mnemonic.Pusha:
            case Mnemonic.Pushad:
            case Mnemonic.Pop:
            case Mnemonic.Popf:
            case Mnemonic.Popfd:
            case Mnemonic.Popfq:
            case Mnemonic.Popa:
            case Mnemonic.Popad:
                sp += ins.StackPointerIncrement;
                break;
            case Mnemonic.Sub:
            case Mnemonic.Add:
                if (ins.Op0Kind == OpKind.Register && Disasm.IsStackReg(ins.Op0Register) && IsImm(ins.Op1Kind))
                {
                    int v = (int)(long)ins.GetImmediate(1);
                    sp += ins.Mnemonic == Mnemonic.Sub ? -v : v;
                }
                break;
            case Mnemonic.Lea:
                if (ins.Op0Kind == OpKind.Register)
                {
                    long disp = _db.Bitness == 64 ? (long)ins.MemoryDisplacement64 : (int)ins.MemoryDisplacement32;
                    if (Disasm.IsStackReg(ins.Op0Register))
                    {
                        if (Disasm.IsStackReg(ins.MemoryBase)) sp += (int)disp;
                        else if (Disasm.IsFrameReg(ins.MemoryBase) && f.BpDelta != int.MinValue) sp = (int)(f.BpDelta + disp);
                    }
                    else if (Disasm.IsFrameReg(ins.Op0Register) && Disasm.IsStackReg(ins.MemoryBase)
                             && ins.MemoryIndex == Register.None)
                    {
                        f.BpBased = true;
                        f.BpDelta = (int)(sp + disp);
                    }
                }
                break;
            case Mnemonic.Mov:
                if (ins.Op0Kind == OpKind.Register && ins.Op1Kind == OpKind.Register)
                {
                    if (Disasm.IsFrameReg(ins.Op0Register) && Disasm.IsStackReg(ins.Op1Register))
                    {
                        f.BpBased = true;
                        f.BpDelta = sp;
                        if (sp == -ptr) f.FrRegs = ptr;
                    }
                    else if (Disasm.IsStackReg(ins.Op0Register) && Disasm.IsFrameReg(ins.Op1Register)
                             && f.BpDelta != int.MinValue)
                        sp = f.BpDelta;
                }
                break;
            case Mnemonic.Leave:
                if (f.BpDelta != int.MinValue) sp = f.BpDelta + ptr;
                break;
            case Mnemonic.Enter:
                sp -= ptr;
                f.BpBased = true;
                f.BpDelta = sp;
                f.FrRegs = ptr;
                sp -= ins.Immediate16;
                break;
            case Mnemonic.Call:
                if (_db.Bitness == 32 && IsNearBranch(ins) && _db.Funcs.TryGetValue(ins.NearBranchTarget, out var cf))
                    sp += cf.Purge;
                break;
        }
    }

    private static bool IsImm(OpKind k) => k is OpKind.Immediate8 or OpKind.Immediate8to16 or OpKind.Immediate8to32
        or OpKind.Immediate8to64 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate32to64 or OpKind.Immediate64;

    // ================= Switch tablolari =================

    private void TrySwitch(Function? f, in Instruction jmp, int sp, Stack<(ulong, int)> work, Instruction[] ring, int ringN)
    {
        ulong jea = jmp.IP;
        var seg = _db.SegOf(jea);
        if (seg == null) return;
        int back = Math.Min(ringN, ring.Length);
        Instruction Prev(int k) => ring[(ringN - k) % ring.Length];

        ulong table;
        int esz;
        Func<ulong, ulong?> target;
        bool rva = false;
        ulong relBase = 0;

        if (jmp.Op0Kind == OpKind.Memory && jmp.MemoryIndex != Register.None && jmp.MemoryBase == Register.None
            && jmp.MemoryIndexScale == _db.Ptr)
        {
            // x86: jmp ds:off_X[eax*4]
            table = _db.Bitness == 64 ? jmp.MemoryDisplacement64 : jmp.MemoryDisplacement32;
            esz = _db.Ptr;
            target = e => _db.TryReadPtr(e, out var v) ? v : null;
        }
        else if (jmp.Op0Kind == OpKind.Register)
        {
            var jr = jmp.Op0Register.GetFullRegister();
            Register rb = Register.None;
            int addAt = -1;
            for (int k = 1; k <= back; k++)
            {
                var p = Prev(k);
                if (p.Mnemonic == Mnemonic.Add && p.Op0Kind == OpKind.Register && p.Op1Kind == OpKind.Register
                    && p.Op0Register.GetFullRegister() == jr)
                {
                    rb = p.Op1Register.GetFullRegister();
                    addAt = k;
                    break;
                }
            }
            if (rb == Register.None) return;
            ulong disp = 0;
            bool found = false;
            ulong baseVal = 0;
            bool baseFound = false;
            for (int k = addAt + 1; k <= back; k++)
            {
                var p = Prev(k);
                if (!found && (p.Mnemonic is Mnemonic.Mov or Mnemonic.Movsxd) && p.Op0Kind == OpKind.Register
                    && p.Op1Kind == OpKind.Memory && p.Op0Register.GetFullRegister() == jr
                    && p.MemoryBase.GetFullRegister() == rb && p.MemoryIndex != Register.None && p.MemoryIndexScale == 4)
                {
                    disp = p.MemoryDisplacement64;
                    if (_db.Bitness == 32) disp = p.MemoryDisplacement32;
                    found = true;
                }
                else if (p.Mnemonic == Mnemonic.Lea && p.Op0Kind == OpKind.Register
                         && p.Op0Register.GetFullRegister() == rb && p.IsIPRelativeMemoryOperand)
                {
                    baseVal = p.IPRelativeMemoryAddress;
                    baseFound = true;
                    break;
                }
            }
            if (!found || !baseFound) return;
            esz = 4;
            if (baseVal == _db.ImageBase && _db.LoaderId == "pe")
            {
                table = baseVal + disp;
                rva = true;
                target = e => _db.TryRead(e, 4, out var v) ? _db.ImageBase + v : null;
            }
            else
            {
                table = baseVal + disp;
                relBase = baseVal;
                target = e => _db.TryRead(e, 4, out var v) ? (ulong)((long)relBase + (int)(uint)v) : null;
            }
        }
        else return;

        // sinir: cmp reg, imm ; ja default
        int count = -1;
        for (int k = 1; k <= back; k++)
        {
            var p = Prev(k);
            if (p.Mnemonic == Mnemonic.Cmp && p.Op1Kind != OpKind.Register && p.Op1Kind != OpKind.Memory
                && p.Op0Kind == OpKind.Register)
            {
                count = (int)Math.Min(2048, (long)p.GetImmediate(1) + 1);
                break;
            }
        }
        int max = count > 0 ? count : 512;

        var tseg = _db.SegOf(table);
        if (tseg == null) return;
        _db.AddXref(jea, table, XrefType.Read);
        var cases = new Dictionary<ulong, List<int>>();
        int nOk = 0;
        for (int i = 0; i < max; i++)
        {
            ulong e = table + (ulong)(i * esz);
            var es = _db.SegOf(e);
            if (es == null) break;
            long eo = (long)(e - es.Start);
            if (i > 0 && count < 0 && _db.XTo.ContainsKey(e)) break;
            var t = target(e);
            if (t is not ulong tv || !seg.Contains(tv)) break;
            if (f != null && (tv < f.Start - Math.Min(f.Start, 0x100000UL) || tv > f.Start + 0x100000)) break;
            bool free = _db.RangeFree(es, eo, esz);
            if (!free && (es.F[eo] & FF.Head) == 0) break;
            if (free)
            {
                _db.SetItem(es, eo, esz, esz == 8 ? ItemKind.Qword : ItemKind.Dword, !rva && relBase == 0);
                if (rva) _db.RvaItems.Add(e);
                if (relBase != 0) _db.RelItems[e] = relBase;
            }
            _db.AddXref(e, tv, XrefType.Offset);
            _db.AddXref(jea, tv, XrefType.Jump);
            if (!cases.TryGetValue(tv, out var lst)) cases[tv] = lst = new List<int>();
            lst.Add(i);
            PushTarget(tv, sp, work);
            nOk++;
        }
        if (nOk == 0) return;
        _db.AutoComments[jea] = $"switch jump";
        _db.AutoComments.TryAdd(table, $"jump table for switch statement");
        _db.AutoLabels.TryAdd(table, "jpt_" + Db.Hx(jea));
        foreach (var kv in cases)
        {
            string c = kv.Value.Count == 1 ? $"case {kv.Value[0]}" : "cases " + string.Join(",", kv.Value.Take(12))
                                                                     + (kv.Value.Count > 12 ? ",..." : "");
            _db.AutoComments[kv.Key] = $"jumptable {_db.AddrStr(jea)} {c}";
        }
    }

    // ================= Ek gecisler =================

    private void RelocPass()
    {
        if (_db.Relocs.Count == 0 || _db.ImageBase < 0x10000) return;
        int ptr = _db.Ptr;
        foreach (var r in _db.Relocs.OrderBy(x => x))
        {
            var s = _db.SegOf(r);
            if (s == null) continue;
            long o = (long)(r - s.Start);
            if (!_db.RangeFree(s, o, ptr) || !s.IsInit(o)) continue;
            if (!_db.TryReadPtr(r, out var v) || !_db.IsMapped(v)) continue;
            _db.SetItem(s, o, ptr, ptr == 8 ? ItemKind.Qword : ItemKind.Dword, true);
            _db.AddXref(r, v, XrefType.Offset);
            if (_db.IsCodeSeg(v)) QueueFunc(v);
            else MakeDataAt(v, 0, MemorySize.Unknown, true);
        }
    }

    private void PrologueScan()
    {
        foreach (var s in _db.Segs)
        {
            if (!s.X) continue;
            long o = 0;
            while (o < s.InitSize)
            {
                if (s.F[o] != 0) { o += Db.ItemSize(s, o); continue; }
                byte b = s.Data[o];
                if (b is 0xCC or 0x90 or 0x00) { o++; continue; }
                bool boundary = o == 0 || s.F[o - 1] != 0 || s.Data[o - 1] is 0xCC or 0x90 or 0x00 or 0xC3;
                if (boundary && IsPrologue(s, o))
                {
                    ulong ea = s.Start + (ulong)o;
                    _queued.Add(ea);
                    if (MakeFunction(ea) != null)
                    {
                        Drain();
                        continue;
                    }
                }
                o++;
            }
        }
    }

    private bool IsPrologue(Segment s, long o)
    {
        byte B(int i) => o + i < s.InitSize ? s.Data[o + i] : (byte)0;
        if (_db.Bitness == 64)
        {
            if (B(0) == 0x48 && B(1) == 0x89 && B(3) == 0x24 && B(2) is 0x5C or 0x4C or 0x54 or 0x6C or 0x74 or 0x7C) return true;
            if (B(0) == 0x4C && B(1) == 0x89 && B(3) == 0x24 && B(2) is 0x44 or 0x4C) return true;
            if (B(0) == 0x48 && (B(1) is 0x83 or 0x81) && B(2) == 0xEC) return true;
            if (B(0) == 0x40 && B(1) is 0x53 or 0x55 or 0x56 or 0x57 && B(2) is 0x48 or 0x41) return true;
            if (B(0) == 0x41 && B(1) is >= 0x54 and <= 0x57 && B(2) is 0x48 or 0x41) return true;
            if (B(0) == 0x55 && B(1) == 0x48 && (B(2) == 0x8B && B(3) == 0xEC || B(2) == 0x89 && B(3) == 0xE5)) return true;
            if (B(0) is 0x53 or 0x56 or 0x57 && B(1) == 0x48 && B(2) is 0x83 or 0x81 && B(3) == 0xEC) return true;
            if (B(0) == 0x48 && B(1) == 0x8B && B(2) == 0xC4) return true;
            if (B(0) == 0x4C && B(1) == 0x8B && B(2) == 0xDC) return true;
            if (B(0) == 0xF3 && B(1) == 0x0F && B(2) == 0x1E && B(3) == 0xFA) return true;
            return false;
        }
        if (B(0) == 0x55 && B(1) == 0x8B && B(2) == 0xEC) return true;
        if (B(0) == 0x55 && B(1) == 0x89 && B(2) == 0xE5) return true;
        if (B(0) == 0x8B && B(1) == 0xFF && B(2) == 0x55 && B(3) == 0x8B) return true;
        if (B(0) == 0x6A && B(2) == 0x68) return true;
        if (B(0) == 0x83 && B(1) == 0xEC) return true;
        if (B(0) == 0x81 && B(1) == 0xEC) return true;
        if (B(0) == 0xF3 && B(1) == 0x0F && B(2) == 0x1E && B(3) == 0xFB) return true;
        if (B(0) == 0x53 && B(1) == 0x56 && B(2) == 0x57) return true;
        if (B(0) == 0x56 && B(1) == 0x8B && B(2) == 0xF1) return true;
        return false;
    }

    // Dolgu baytlari -> align
    // Sonradan eklenen fonksiyon baslangiclari (orn. indirilen PDB)
    public int AddFunctions(IEnumerable<ulong> eas)
    {
        int before = _db.Funcs.Count;
        foreach (var ea in eas)
            if (!_db.Funcs.ContainsKey(ea))
            {
                _queued.Remove(ea);
                QueueFunc(ea);
            }
        Drain();
        FinalizeFunctions();
        AlignPass();
        return _db.Funcs.Count - before;
    }

    public void AlignPass()
    {
        foreach (var s in _db.Segs)
        {
            long o = 0;
            while (o < s.InitSize)
            {
                if (s.F[o] != 0) { o += Db.ItemSize(s, o); continue; }
                long st = o;
                byte b = s.Data[o];
                if (b is not (0xCC or 0x90 or 0x00)) { o++; continue; }
                while (o < s.InitSize && s.F[o] == 0 && s.Data[o] == b && (o == st || !_db.XTo.ContainsKey(s.Start + (ulong)o)))
                    o++;
                if (_db.XTo.ContainsKey(s.Start + (ulong)st) || _db.LoaderNames.ContainsKey(s.Start + (ulong)st)) continue;
                long len = o - st;
                ulong end = s.Start + (ulong)o;
                // ancak arkasinda bir oge ya da segment/veri sonu varsa
                bool atEnd = o >= s.InitSize;
                if (!atEnd && s.F[o] == 0) continue;
                if (s.X && b is 0xCC or 0x90)
                {
                    // kod segmentinde fonksiyonlar arasi dolgu: align / db N dup(0CCh)
                    _db.SetItem(s, st, (int)len, ItemKind.Align);
                    continue;
                }
                for (ulong a = 0x1000; a >= 4; a >>= 1)
                {
                    if (end % a == 0 && (ulong)len < a)
                    {
                        _db.SetItem(s, st, (int)len, ItemKind.Align);
                        break;
                    }
                }
            }
        }
    }

    public void FinalizeFunctions()
    {
        foreach (var f in _db.FuncList)
        {
            if (f.Instrs.Count == 0) { f.Chunks.Clear(); continue; }
            f.Instrs.Sort();
            f.Chunks.Clear();
            ulong cs = f.Instrs[0], ce = cs;
            foreach (var ea in f.Instrs)
            {
                int len = _db.ItemSize(ea);
                if (ea != ce)
                {
                    f.Chunks.Add((cs, ce));
                    cs = ea;
                }
                ce = ea + (ulong)len;
            }
            f.Chunks.Add((cs, ce));
            var main = f.Chunks.FirstOrDefault(c => f.Start >= c.Start && f.Start < c.End);
            if (main.End == 0) main = f.Chunks[0];
            f.End = main.End;
            // ana parca once
            f.Chunks.Remove(main);
            f.Chunks.Insert(0, main);

            f.IsThunk = false;
            f.ThunkTarget = 0;
            if (f.Instrs.Count == 1 && _dis.TryDecode(f.Start, out var ins) && ins.Mnemonic == Mnemonic.Jmp)
            {
                if (IsNearBranch(ins)) { f.IsThunk = true; f.ThunkTarget = ins.NearBranchTarget; }
                else if (ins.Op0Kind == OpKind.Memory && _dis.MemTarget(ins) is ulong sl && _db.ImportAt.ContainsKey(sl))
                {
                    f.IsThunk = true;
                    f.ThunkTarget = sl;
                }
            }
            if (!f.HasRet && !f.IsThunk)
            {
                bool tail = false;
                foreach (var x in f.Instrs)
                    foreach (var xr in _db.XrefsFrom(x))
                        if (xr.Type == XrefType.Jump && _db.Funcs.ContainsKey(xr.To) && xr.To != f.Start) tail = true;
                f.NoReturn = !tail && f.Instrs.Count > 0;
            }
        }
        _db.RebuildChunkIndex();
    }

    public void BuildStrings()
    {
        var list = new List<StrLit>();
        foreach (var s in _db.Segs)
        {
            if (s.IsExtern) continue;
            long o = 0;
            while (o < s.InitSize)
            {
                byte fl = s.F[o];
                var k = (ItemKind)(fl & FF.KindMask);
                if ((fl & FF.Head) != 0 && k is ItemKind.Ascii or ItemKind.Utf16)
                {
                    int sz = Db.ItemSize(s, o);
                    ulong ea = s.Start + (ulong)o;
                    string v = k == ItemKind.Ascii ? _db.ReadAscii(ea, 1024) : _db.ReadUtf16(ea, 1024);
                    list.Add(new StrLit { Ea = ea, Len = sz, Type = k == ItemKind.Ascii ? "C" : "C16", Value = v });
                    o += sz;
                    continue;
                }
                if (k == ItemKind.Code || (fl != 0 && k != ItemKind.Unknown && k != ItemKind.Byte))
                {
                    o += Math.Max(1, Db.ItemSize(s, o));
                    continue;
                }
                // UTF-16
                if (o + 1 < s.InitSize && s.Data[o + 1] == 0 && Printable(s.Data[o]) && (o & 1) == 0)
                {
                    long p = o;
                    int n = 0;
                    while (p + 1 < s.InitSize && s.Data[p + 1] == 0 && Printable(s.Data[p]) && s.F[p] == 0) { p += 2; n++; }
                    if (n >= MinStrLen && p + 1 < s.InitSize && s.Data[p] == 0 && s.Data[p + 1] == 0)
                    {
                        ulong ea = s.Start + (ulong)o;
                        list.Add(new StrLit { Ea = ea, Len = (n + 1) * 2, Type = "C16", Value = _db.ReadUtf16(ea, 1024) });
                        o = p + 2;
                        continue;
                    }
                }
                if (Printable(s.Data[o]))
                {
                    long p = o;
                    while (p < s.InitSize && Printable(s.Data[p]) && s.F[p] == 0) p++;
                    int n = (int)(p - o);
                    if (n >= MinStrLen && p < s.InitSize && s.Data[p] == 0)
                    {
                        ulong ea = s.Start + (ulong)o;
                        list.Add(new StrLit { Ea = ea, Len = n + 1, Type = "C", Value = _db.ReadAscii(ea, 1024) });
                    }
                    o = Math.Max(p, o + 1);
                    continue;
                }
                o++;
            }
        }
        _db.Strings = list;
    }

    // ================= Kullanici islemleri =================

    public void Record(string op, ulong ea, int arg = 0)
    {
        _db.Ops.Add(new UserOp { Op = op, Ea = ea, Arg = arg });
        _db.Dirty = true;
    }

    public bool Apply(UserOp op) => op.Op switch
    {
        "U" => Undefine(op.Ea),
        "C" => MakeCode(op.Ea),
        "P" => CreateFunction(op.Ea),
        "DF" => DeleteFunction(op.Ea),
        "D" => MakeData(op.Ea, (ItemKind)op.Arg),
        "A" => MakeString(op.Ea, op.Arg == 1),
        "O" => ToggleOffset(op.Ea),
        _ => false,
    };

    public bool Undefine(ulong ea)
    {
        var s = _db.SegOf(ea);
        if (s == null) return false;
        ulong head = _db.HeadOf(ea);
        long o = (long)(head - s.Start);
        if (s.F[o] == 0) return false;
        var k = (ItemKind)(s.F[o] & FF.KindMask);
        int fi = k == ItemKind.Code && s.Owner.Length > 0 ? s.Owner[o] : -1;
        _db.RemoveXrefsFrom(head);
        _db.ClearItem(s, o);
        _db.ClearStrName(head);
        _db.RvaItems.Remove(head);
        _db.RelItems.Remove(head);
        _db.AutoLabels.Remove(head);
        if (fi >= 0)
        {
            var f = _db.FuncList[fi];
            f.Instrs.Remove(head);
            if (head == f.Start) RemoveFunc(f);
        }
        return true;
    }

    private void RemoveFunc(Function f)
    {
        foreach (var ea in f.Instrs)
        {
            var s = _db.SegOf(ea);
            if (s == null) continue;
            long o = (long)(ea - s.Start);
            int n = Db.ItemSize(s, o);
            for (int i = 0; i < n; i++) if (s.Owner[o + i] == f.Index) s.Owner[o + i] = -1;
        }
        f.Instrs.Clear();
        f.Chunks.Clear();
        f.Vars.Clear();
        f.SpAt.Clear();
        _db.Funcs.Remove(f.Start);
    }

    public bool MakeCode(ulong ea)
    {
        var s = _db.SegOf(ea);
        if (s == null || !s.IsInit((long)(ea - s.Start))) return false;
        if (_db.IsCode(ea)) return false;
        if (s.F[ea - s.Start] != 0) Undefine(ea);
        if (!_dis.TryDecode(ea, out _)) return false;
        var x = s.X;
        s.X = true; // kullanici istediyse veri segmentinde de kod
        if (s.Owner.Length == 0) { s.Owner = new int[s.Size]; Array.Fill(s.Owner, -1); }
        Trace(ea, null);
        s.X = x || s.X;
        // fonksiyon sinirlari icindeyse fonksiyonu yeniden olustur
        var host = _db.FuncList.FirstOrDefault(f => f.Instrs.Count > 0 && ea > f.Start && ea < f.End + 0x40
                                                     && _db.Funcs.ContainsKey(f.Start));
        if (host != null) Recreate(host.Start);
        Drain();
        return true;
    }

    private void Recreate(ulong start)
    {
        if (_db.Funcs.TryGetValue(start, out var f)) RemoveFunc(f);
        _queued.Remove(start);
        MakeFunction(start);
    }

    public bool CreateFunction(ulong ea)
    {
        if (_db.Funcs.ContainsKey(ea)) return false;
        var s = _db.SegOf(ea);
        if (s == null) return false;
        long o = (long)(ea - s.Start);
        if ((s.F[o] & FF.Tail) != 0) return false;
        if (s.F[o] != 0 && (s.F[o] & FF.KindMask) != (byte)ItemKind.Code) Undefine(ea);
        if (!s.X)
        {
            s.X = true;
            if (s.Owner.Length == 0) { s.Owner = new int[s.Size]; Array.Fill(s.Owner, -1); }
        }
        Function? host = null;
        if (s.Owner.Length > 0 && s.Owner[o] >= 0) host = _db.FuncList[s.Owner[o]];
        if (host != null) RemoveFunc(host);
        _queued.Remove(ea);
        var nf = MakeFunction(ea);
        if (host != null) Recreate(host.Start);
        Drain();
        return nf != null;
    }

    public bool DeleteFunction(ulong ea)
    {
        var f = _db.FuncAt(ea);
        if (f == null) return false;
        RemoveFunc(f);
        return true;
    }

    public static ItemKind NextDataKind(ItemKind k) => k switch
    {
        ItemKind.Byte => ItemKind.Word,
        ItemKind.Word => ItemKind.Dword,
        ItemKind.Dword => ItemKind.Qword,
        _ => ItemKind.Byte,
    };

    public bool MakeData(ulong ea, ItemKind k)
    {
        var s = _db.SegOf(ea);
        if (s == null) return false;
        ulong head = _db.HeadOf(ea);
        long o = (long)(head - s.Start);
        if (s.F[o] != 0) Undefine(head);
        int size = Disasm.KindSize(k, _db.Ptr);
        if (size == 0) size = 1;
        if (!_db.RangeFree(s, o, size))
        {
            k = ItemKind.Byte;
            size = 1;
        }
        _db.SetItem(s, o, size, k);
        return true;
    }

    public bool MakeString(ulong ea, bool wide)
    {
        var s = _db.SegOf(ea);
        if (s == null) return false;
        ulong head = _db.HeadOf(ea);
        long o = (long)(head - s.Start);
        if (s.F[o] != 0) Undefine(head);
        if (!s.IsInit(o)) return false;
        long p = o;
        int unit = wide ? 2 : 1;
        while (p + unit <= s.InitSize && s.F[p] == 0 && p - o < 8192)
        {
            int c = wide ? s.Data[p] | (s.Data[p + 1] << 8) : s.Data[p];
            p += unit;
            if (c == 0) break;
        }
        int len = (int)(p - o);
        if (len <= 0) return false;
        for (int i = 0; i < len; i++) if (s.F[o + i] != 0) { len = i; break; }
        if (len <= 0) return false;
        SetString(s, o, len, wide);
        return true;
    }

    public bool ToggleOffset(ulong ea)
    {
        var s = _db.SegOf(ea);
        if (s == null) return false;
        ulong head = _db.HeadOf(ea);
        long o = (long)(head - s.Start);
        var k = (ItemKind)(s.F[o] & FF.KindMask);
        if (k == ItemKind.Code)
        {
            if (!_dis.TryDecode(head, out var ins)) return false;
            bool had = _db.XrefsFrom(head).Any(x => x.Type == XrefType.Offset);
            if (had)
            {
                var keep = _db.XrefsFrom(head).Where(x => x.Type != XrefType.Offset).ToList();
                _db.RemoveXrefsFrom(head);
                foreach (var x in keep) _db.AddXref(x.From, x.To, x.Type);
                return true;
            }
            for (int i = 0; i < ins.OpCount; i++)
                if (IsImm(ins.GetOpKind(i)) && _db.IsMapped(ins.GetImmediate(i)))
                {
                    _db.AddXref(head, ins.GetImmediate(i), XrefType.Offset);
                    return true;
                }
            return false;
        }
        if (k is not (ItemKind.Dword or ItemKind.Qword)) return false;
        bool isOff = (s.F[o] & FF.Offset) != 0;
        if (isOff)
        {
            s.F[o] = (byte)(s.F[o] & ~FF.Offset);
            _db.RemoveXrefsFrom(head);
        }
        else if (_db.TryRead(head, k == ItemKind.Qword ? 8 : 4, out var v) && _db.IsMapped(v))
        {
            s.F[o] |= FF.Offset;
            _db.AddXref(head, v, XrefType.Offset);
        }
        else return false;
        return true;
    }
}
