using System.Text;
using System.Text.RegularExpressions;
using Iced.Intel;

namespace tlk_hex.Core;

public sealed record Hit(ulong Ea, string Kind, string Text);

public sealed class SearchQuery
{
    public string Text = "";
    public string Scope = "all";      // all / names / strings / code / comments / bytes / imm
    public bool MatchCase;
    public bool Regex;
}

// Arama paneli icin motor: arka planda calisir, kendi cozucusunu kullanir
public static class SearchEngine
{
    public static Func<string, bool>? Matcher(SearchQuery q, out string? error)
    {
        error = null;
        if (q.Regex)
        {
            try
            {
                var rx = new Regex(q.Text, (q.MatchCase ? RegexOptions.None : RegexOptions.IgnoreCase) | RegexOptions.Compiled);
                return s => rx.IsMatch(s);
            }
            catch (Exception ex)
            {
                error = "Geçersiz regex: " + ex.Message;
                return null;
            }
        }
        var cmp = q.MatchCase ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        string t = q.Text;
        return s => s.Contains(t, cmp);
    }

    public static List<Hit> Run(SearchQuery q, Db db, Listing worker, List<(string Name, ulong Ea)> names,
        List<StrLit> strings, List<(ulong Ea, string Text)> comments, CancellationToken ct, out string? error, int max = 5000)
    {
        var res = new List<Hit>();
        error = null;
        if (q.Text.Length == 0) return res;
        string sc = q.Scope;
        bool all = sc == "all";

        if (sc is "bytes") { Bytes(q.Text, db, res, ct, max); return res; }
        if (sc is "imm")
        {
            var v = ParseValue(q.Text);
            if (v == null) { error = "Geçersiz sayı: " + q.Text; return res; }
            Immediates(v.Value, db, worker, res, ct, max);
            return res;
        }

        var m = Matcher(q, out error);
        if (m == null) return res;

        if (all || sc == "names")
            foreach (var (n, ea) in names)
            {
                if (ct.IsCancellationRequested || res.Count >= max) return res;
                if (m(n)) res.Add(new Hit(ea, "isim", n));
            }
        if (all || sc == "strings")
            foreach (var s in strings)
            {
                if (ct.IsCancellationRequested || res.Count >= max) return res;
                if (m(s.Value)) res.Add(new Hit(s.Ea, s.Type == "C16" ? "metin16" : "metin", Db.Escape(s.Value, 300)));
            }
        if (all || sc == "comments")
            foreach (var (ea, c) in comments)
            {
                if (ct.IsCancellationRequested || res.Count >= max) return res;
                if (m(c)) res.Add(new Hit(ea, "yorum", c.Replace("\n", " ")));
            }
        if (all || sc == "code")
        {
            for (long l = 0; l < worker.TotalLines && res.Count < max; l++)
            {
                if ((l & 0xFFF) == 0 && ct.IsCancellationRequested) return res;
                var ln = worker.GetLine(l);
                string p = ln.Plain;
                string body = ln.BodyCol < p.Length ? p[ln.BodyCol..].Trim() : "";
                if (body.Length == 0 || !m(body)) continue;
                if (all && (ln.Type is LT.Proc or LT.Label or LT.Endp or LT.XrefCont)) continue; // isimlerde zaten var
                res.Add(new Hit(ln.Ea, "kod", body));
            }
        }
        if (all && ParseValue(q.Text) is ulong num && q.Text.Any(char.IsDigit))
        {
            if (db.IsMapped(num)) res.Insert(0, new Hit(num, "adres", db.RefName(num) ?? db.AddrStr(num)));
            else if (db.IsMapped(num + db.ImageBase)) res.Insert(0, new Hit(num + db.ImageBase, "adres", "RVA " + Db.HexNum(num)));
        }
        return res;
    }

    public static ulong? ParseValue(string t)
    {
        t = t.Trim();
        if (t.Length == 0) return null;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || t.EndsWith('h') || t.EndsWith('H')) return Db.ParseNum(t);
        if (t.All(char.IsDigit)) return ulong.TryParse(t, out var d) ? d : null;
        if (t.StartsWith('-') && t[1..].All(char.IsDigit) && long.TryParse(t, out var neg)) return (ulong)neg;
        return t.All(Uri.IsHexDigit) ? Db.ParseNum(t) : null;
    }

    public static (byte[] Pat, bool[] Mask)? ParsePattern(string s)
    {
        var bytes = new List<byte>();
        var mask = new List<bool>();
        int i = 0;
        s = s.Trim();
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c) || c == ',') { i++; continue; }
            if (c == '"')
            {
                int j = s.IndexOf('"', i + 1);
                if (j < 0) j = s.Length;
                foreach (var b in Encoding.UTF8.GetBytes(s[(i + 1)..j])) { bytes.Add(b); mask.Add(true); }
                i = j + 1;
                continue;
            }
            if (c == '?')
            {
                bytes.Add(0);
                mask.Add(false);
                i += i + 1 < s.Length && s[i + 1] == '?' ? 2 : 1;
                continue;
            }
            if (i + 1 < s.Length && Uri.IsHexDigit(c) && Uri.IsHexDigit(s[i + 1]))
            {
                bytes.Add(Convert.ToByte(s.Substring(i, 2), 16));
                mask.Add(true);
                i += 2;
                continue;
            }
            return null;
        }
        return bytes.Count == 0 ? null : (bytes.ToArray(), mask.ToArray());
    }

    private static void Bytes(string text, Db db, List<Hit> res, CancellationToken ct, int max)
    {
        var pats = new List<(byte[] P, bool[] M, string Kind)>();
        if (ParsePattern(text) is { } pp) pats.Add((pp.Pat, pp.Mask, "bayt"));
        else
        {
            // duz metin: ASCII ve UTF-16 olarak ara
            var a = Encoding.UTF8.GetBytes(text);
            pats.Add((a, Enumerable.Repeat(true, a.Length).ToArray(), "bayt"));
            var u = Encoding.Unicode.GetBytes(text);
            pats.Add((u, Enumerable.Repeat(true, u.Length).ToArray(), "bayt16"));
        }
        foreach (var (pat, mask, kind) in pats)
            foreach (var s in db.Segs)
            {
                long n = s.InitSize - pat.Length;
                for (long o = 0; o <= n; o++)
                {
                    if ((o & 0xFFFF) == 0 && ct.IsCancellationRequested) return;
                    bool ok = true;
                    for (int k = 0; k < pat.Length; k++)
                        if (mask[k] && s.Data[o + k] != pat[k]) { ok = false; break; }
                    if (!ok) continue;
                    var sb = new StringBuilder();
                    for (int k = 0; k < Math.Min(16, s.InitSize - o); k++) sb.Append(s.Data[o + k].ToString("X2")).Append(' ');
                    res.Add(new Hit(s.Start + (ulong)o, kind, sb.ToString().Trim()));
                    if (res.Count >= max) return;
                }
            }
    }

    private static void Immediates(ulong val, Db db, Listing worker, List<Hit> res, CancellationToken ct, int max)
    {
        var dis = new Disasm(db);
        foreach (var s in db.Segs)
        {
            if (!s.X) continue;
            for (long o = 0; o < s.InitSize;)
            {
                if ((o & 0xFFFF) == 0 && ct.IsCancellationRequested) return;
                if ((s.F[o] & FF.Head) != 0 && (s.F[o] & FF.KindMask) == (byte)ItemKind.Code)
                {
                    ulong ea = s.Start + (ulong)o;
                    if (dis.TryDecode(ea, out var ins))
                    {
                        bool hit = false;
                        for (int i = 0; i < ins.OpCount && !hit; i++)
                        {
                            var k = ins.GetOpKind(i);
                            if (k.ToString().StartsWith("Immediate") &&
                                (ins.GetImmediate(i) == val || (ulong)(long)(int)ins.GetImmediate(i) == val)) hit = true;
                            if (k == OpKind.Memory && ins.MemoryDisplacement64 == val) hit = true;
                        }
                        if (hit)
                        {
                            var ln = worker.GetLine(worker.LineOfEa(ea, false));
                            string p = ln.Plain;
                            res.Add(new Hit(ea, "sabit", ln.BodyCol < p.Length ? p[ln.BodyCol..].Trim() : p));
                            if (res.Count >= max) return;
                        }
                    }
                    o += Db.ItemSize(s, o);
                }
                else o++;
            }
        }
    }
}
