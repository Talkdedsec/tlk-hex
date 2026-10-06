using Iced.Intel;

namespace tlk_hex.Core;

// Iki binary'nin fonksiyonlarini yapisal olarak eslestirir (BinDiff benzeri).
// Dekompilasyon yok: normalize mnemonic dizisi + cagrilan import kumesi uzerinden.

public sealed class FuncSig
{
    public ulong Ea;
    public string Name = "";
    public int InsnCount;
    public ulong Hash;                               // mnemonic dizisi parmak izi
    public string[] Calls = Array.Empty<string>();   // cagrilan dummy-olmayan isimler (sirali, tekil)
    public bool Dummy;                               // otomatik isim (sub_/loc_)
    public bool Thunk;
}

public enum DiffKind { Identical, Changed, OnlyLeft, OnlyRight }

public sealed class DiffPair
{
    public FuncSig? Left;        // A (birincil) dosya
    public FuncSig? Right;       // B (karsilastirilan) dosya
    public DiffKind Kind;
    public double Similarity;    // 0..1
}

public sealed class DiffStats
{
    public int Identical, Changed, OnlyLeft, OnlyRight;
    public int Total => Identical + Changed + OnlyLeft + OnlyRight;
    public int Matched => Identical + Changed;
}

public static class BinDiff
{
    public static List<FuncSig> BuildSigs(Db db, Disasm dis)
    {
        var sigs = new List<FuncSig>(db.FuncList.Count);
        foreach (var f in db.FuncList)
        {
            ulong h = 1469598103934665603UL; // FNV-1a 64 offset
            int n = 0;
            var calls = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var ea in f.Instrs)
            {
                if (!dis.TryDecode(ea, out var ins)) continue;
                n++;
                ushort m = (ushort)ins.Mnemonic;
                h ^= m; h *= 1099511628211UL;
                if (ins.Mnemonic is Mnemonic.Call or Mnemonic.Jmp)
                {
                    foreach (var x in db.XrefsFrom(ea))
                    {
                        if (x.Type != XrefType.Call && x.Type != XrefType.Jump) continue;
                        if (x.To == ea) continue;
                        if (db.IsDummyName(x.To)) continue;      // sub_/loc_ atla (adres-bagimli)
                        var nm = db.NameAt(x.To);
                        if (string.IsNullOrEmpty(nm)) continue;
                        if (nm!.StartsWith("j_")) nm = nm[2..];
                        calls.Add(nm);
                    }
                }
            }
            sigs.Add(new FuncSig
            {
                Ea = f.Start,
                Name = db.FuncName(f),
                InsnCount = n,
                Hash = h,
                Calls = calls.ToArray(),
                Dummy = db.IsDummyName(f.Start),
                Thunk = f.IsThunk,
            });
        }
        return sigs;
    }

    public static List<DiffPair> Compare(IReadOnlyList<FuncSig> left, IReadOnlyList<FuncSig> right)
    {
        var pairs = new List<DiffPair>();
        var usedR = new HashSet<int>();

        // indeksler
        var byHash = new Dictionary<ulong, List<int>>();
        var byName = new Dictionary<string, List<int>>(StringComparer.Ordinal);
        for (int i = 0; i < right.Count; i++)
        {
            (byHash.TryGetValue(right[i].Hash, out var lh) ? lh : byHash[right[i].Hash] = new()).Add(i);
            if (!right[i].Dummy)
                (byName.TryGetValue(right[i].Name, out var ln) ? ln : byName[right[i].Name] = new()).Add(i);
        }

        var pendingL = new List<int>();

        // 1) birebir: ayni hash + ayni komut sayisi + ayni cagri kumesi
        for (int i = 0; i < left.Count; i++)
        {
            var a = left[i];
            int pick = -1;
            if (byHash.TryGetValue(a.Hash, out var cands))
            {
                int fallback = -1;
                foreach (var j in cands)
                {
                    if (usedR.Contains(j)) continue;
                    var b = right[j];
                    if (b.InsnCount != a.InsnCount || !CallsEqual(a.Calls, b.Calls)) continue;
                    if (b.Name == a.Name) { pick = j; break; }   // isim de ayni -> kesin
                    if (fallback < 0) fallback = j;
                }
                if (pick < 0) pick = fallback;
            }
            if (pick >= 0)
            {
                usedR.Add(pick);
                pairs.Add(new DiffPair { Left = a, Right = right[pick], Kind = DiffKind.Identical, Similarity = 1.0 });
            }
            else pendingL.Add(i);
        }

        // 2) isme gore: dummy olmayan adlar (ad korundu ama govde degisti)
        var still = new List<int>();
        foreach (var i in pendingL)
        {
            var a = left[i];
            int pick = -1;
            if (!a.Dummy && byName.TryGetValue(a.Name, out var cands))
                foreach (var j in cands)
                    if (!usedR.Contains(j)) { pick = j; break; }
            if (pick >= 0)
            {
                usedR.Add(pick);
                var b = right[pick];
                pairs.Add(new DiffPair { Left = a, Right = b, Kind = DiffKind.Changed, Similarity = Sim(a, b) });
            }
            else still.Add(i);
        }

        // 3) bulanik: kalanlari benzerlige gore acgozlu esle (esik 0.55)
        var remR = new List<int>();
        for (int j = 0; j < right.Count; j++) if (!usedR.Contains(j)) remR.Add(j);

        var candList = new List<(double s, int i, int j)>();
        foreach (var i in still)
        {
            var a = left[i];
            foreach (var j in remR)
            {
                double s = Sim(a, right[j]);
                if (s >= 0.55) candList.Add((s, i, j));
            }
        }
        candList.Sort((x, y) => y.s.CompareTo(x.s));
        var tookL = new HashSet<int>();
        var tookR = new HashSet<int>();
        foreach (var (s, i, j) in candList)
        {
            if (tookL.Contains(i) || tookR.Contains(j)) continue;
            tookL.Add(i); tookR.Add(j); usedR.Add(j);
            pairs.Add(new DiffPair { Left = left[i], Right = right[j], Kind = DiffKind.Changed, Similarity = s });
        }

        // 4) artanlar
        foreach (var i in still)
            if (!tookL.Contains(i))
                pairs.Add(new DiffPair { Left = left[i], Kind = DiffKind.OnlyLeft, Similarity = 0 });
        for (int j = 0; j < right.Count; j++)
            if (!usedR.Contains(j))
                pairs.Add(new DiffPair { Right = right[j], Kind = DiffKind.OnlyRight, Similarity = 0 });

        return pairs;
    }

    public static DiffStats Summarize(IEnumerable<DiffPair> pairs)
    {
        var s = new DiffStats();
        foreach (var p in pairs)
            switch (p.Kind)
            {
                case DiffKind.Identical: s.Identical++; break;
                case DiffKind.Changed: s.Changed++; break;
                case DiffKind.OnlyLeft: s.OnlyLeft++; break;
                case DiffKind.OnlyRight: s.OnlyRight++; break;
            }
        return s;
    }

    private static bool CallsEqual(string[] a, string[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    private static double Sim(FuncSig a, FuncSig b)
    {
        if (a.Hash == b.Hash && a.InsnCount == b.InsnCount) return 0.98;
        double call = Jaccard(a.Calls, b.Calls);
        int hi = Math.Max(a.InsnCount, b.InsnCount);
        double ic = hi == 0 ? 1.0 : (double)Math.Min(a.InsnCount, b.InsnCount) / hi;
        double s = 0.5 * call + 0.5 * ic;
        if (a.Hash == b.Hash) s = Math.Max(s, 0.9);
        return s;
    }

    private static double Jaccard(string[] a, string[] b)
    {
        if (a.Length == 0 && b.Length == 0) return 0.0;   // ortak cagri yok -> kanit yok
        var sa = new HashSet<string>(a, StringComparer.Ordinal);
        int inter = 0;
        foreach (var x in b) if (sa.Contains(x)) inter++;
        int uni = a.Length + b.Length - inter;
        return uni == 0 ? 0 : (double)inter / uni;
    }
}
