using Iced.Intel;

namespace tlk_hex.Core;

public enum EdgeKind : byte { Uncond, True, False }

public sealed class BBlock
{
    public int Index;
    public ulong Start, End;
    public List<ulong> Insns = new();
    public List<(int To, EdgeKind Kind)> Succ = new();
    public List<int> Pred = new();
}

public static class FlowGraph
{
    public static List<BBlock> Build(Db db, Disasm dis, Function f)
    {
        var blocks = new List<BBlock>();
        if (f.Instrs.Count == 0) return blocks;
        var set = new HashSet<ulong>(f.Instrs);
        var leaders = new HashSet<ulong> { f.Start };
        var info = new Dictionary<ulong, (int Len, FlowControl Fc, ulong Target, bool Near)>();

        foreach (var ea in f.Instrs)
        {
            if (!dis.TryDecode(ea, out var ins)) continue;
            bool near = ins.Op0Kind is OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64;
            ulong tgt = near ? ins.NearBranchTarget : 0;
            info[ea] = (ins.Length, ins.FlowControl, tgt, near);
            switch (ins.FlowControl)
            {
                case FlowControl.ConditionalBranch:
                case FlowControl.UnconditionalBranch:
                    if (near && set.Contains(tgt)) leaders.Add(tgt);
                    leaders.Add(ins.NextIP);
                    break;
                case FlowControl.IndirectBranch:
                    foreach (var x in db.XrefsFrom(ea))
                        if (x.Type == XrefType.Jump && set.Contains(x.To)) leaders.Add(x.To);
                    leaders.Add(ins.NextIP);
                    break;
                case FlowControl.Return:
                case FlowControl.Exception:
                    leaders.Add(ins.NextIP);
                    break;
            }
            foreach (var x in db.XrefsTo(ea))
                if (x.Type == XrefType.Jump) leaders.Add(ea);
        }

        BBlock? cur = null;
        ulong prevEnd = 0;
        foreach (var ea in f.Instrs)
        {
            if (!info.TryGetValue(ea, out var inf)) continue;
            if (cur == null || leaders.Contains(ea) || ea != prevEnd)
            {
                cur = new BBlock { Index = blocks.Count, Start = ea };
                blocks.Add(cur);
            }
            cur.Insns.Add(ea);
            cur.End = ea + (ulong)inf.Len;
            prevEnd = cur.End;
            if (inf.Fc is FlowControl.ConditionalBranch or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch
                or FlowControl.Return or FlowControl.Exception)
                cur = null;
        }

        var byStart = blocks.ToDictionary(b => b.Start, b => b.Index);
        foreach (var b in blocks)
        {
            ulong last = b.Insns[^1];
            var inf = info[last];
            void Edge(ulong t, EdgeKind k)
            {
                if (byStart.TryGetValue(t, out var to) && !b.Succ.Any(s => s.To == to && s.Kind == k))
                {
                    b.Succ.Add((to, k));
                    blocks[to].Pred.Add(b.Index);
                }
            }
            switch (inf.Fc)
            {
                case FlowControl.ConditionalBranch:
                    if (inf.Near) Edge(inf.Target, EdgeKind.True);
                    Edge(b.End, EdgeKind.False);
                    break;
                case FlowControl.UnconditionalBranch:
                    if (inf.Near) Edge(inf.Target, EdgeKind.Uncond);
                    break;
                case FlowControl.IndirectBranch:
                    foreach (var x in db.XrefsFrom(last))
                        if (x.Type == XrefType.Jump) Edge(x.To, EdgeKind.Uncond);
                    break;
                case FlowControl.Return:
                case FlowControl.Exception:
                    break;
                default:
                    if (inf.Fc == FlowControl.Interrupt && dis.TryDecode(last, out var li) && li.Mnemonic == Mnemonic.Int3) break;
                    if (inf.Fc is FlowControl.Call && db.Funcs.TryGetValue(inf.Target, out var cf) && cf.NoReturn) break;
                    Edge(b.End, EdgeKind.Uncond);
                    break;
            }
        }
        // giris blogu basa
        int entry = byStart.TryGetValue(f.Start, out var e) ? e : 0;
        if (entry != 0)
        {
            var eb = blocks[entry];
            blocks.RemoveAt(entry);
            blocks.Insert(0, eb);
            var map = new int[blocks.Count];
            for (int i = 0; i < blocks.Count; i++) map[blocks[i].Index] = i;
            foreach (var b in blocks)
            {
                b.Index = map[b.Index];
                for (int i = 0; i < b.Succ.Count; i++) b.Succ[i] = (map[b.Succ[i].To], b.Succ[i].Kind);
                for (int i = 0; i < b.Pred.Count; i++) b.Pred[i] = map[b.Pred[i]];
            }
        }
        return blocks;
    }
}
