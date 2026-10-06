using System.Text;
using System.Text.RegularExpressions;

namespace tlk_hex.Core;

// Hafif, kendi kendine yeten YARA alt-kumesi. Desteklenen bicim:
//   rule Ad {
//       meta: category = "Dropper" severity = "Yuksek"
//       strings:
//           $a = "metin"
//           $b = "genis" wide
//           $c = { 4D 5A ?? 00 }        // ?? tam bayt, 4? yarim bayt joker
//           $d = /regex/ nocase
//       condition: any of them          // any / all / <N> of them
//   }
public enum PatKind { Text, Hex, Regex }

public sealed class Pat
{
    public string Id = "";
    public PatKind Kind;
    public byte[] Bytes = Array.Empty<byte>();   // Text/Hex
    public byte[] Mask = Array.Empty<byte>();    // Hex (0xFF sabit)
    public Regex? Re;                            // Regex
    public bool Wide;                            // Text -> UTF-16LE
    public bool NoCase;
}

public sealed class YaraRule
{
    public string Name = "";
    public string Category = "Kural";
    public string Severity = "Orta";
    public List<Pat> Pats = new();
    public int MinHits = 1;      // "<N> of them"
    public bool All;             // "all of them"
}

public sealed class RuleMatch
{
    public YaraRule Rule = null!;
    public List<string> HitIds = new();
    public long FirstOffset = -1;
}

public static class RuleScan
{
    private const long NoOff = long.MinValue;   // eslesti ama ofset bilinmiyor

    // ---------------- ayristirma ----------------

    public static List<YaraRule> Parse(string text)
    {
        var rules = new List<YaraRule>();
        int i = 0;
        while (true)
        {
            int rk = text.IndexOf("rule", i, StringComparison.Ordinal);
            if (rk < 0) break;
            // "rule" kelime siniri
            if ((rk > 0 && (char.IsLetterOrDigit(text[rk - 1]) || text[rk - 1] == '_')))
            { i = rk + 4; continue; }
            int np = rk + 4;
            while (np < text.Length && char.IsWhiteSpace(text[np])) np++;
            int ns = np;
            while (np < text.Length && (char.IsLetterOrDigit(text[np]) || text[np] == '_')) np++;
            string name = text[ns..np];
            int open = text.IndexOf('{', np);
            if (name.Length == 0 || open < 0) { i = rk + 4; continue; }
            // eslesen kapanis (derinlik)
            int depth = 0, j = open, close = -1;
            for (; j < text.Length; j++)
            {
                if (text[j] == '{') depth++;
                else if (text[j] == '}') { if (--depth == 0) { close = j; break; } }
            }
            if (close < 0) break;
            var rule = ParseBody(name, text[(open + 1)..close]);
            if (rule.Pats.Count > 0) rules.Add(rule);
            i = close + 1;
        }
        return rules;
    }

    private static YaraRule ParseBody(string name, string body)
    {
        var rule = new YaraRule { Name = name };
        int metaAt = SectionIndex(body, "meta");
        int strAt = SectionIndex(body, "strings");
        int condAt = SectionIndex(body, "condition");

        string Section(int at)
        {
            if (at < 0) return "";
            int start = body.IndexOf(':', at);
            if (start < 0) return "";
            start++;
            int end = body.Length;
            foreach (var n in new[] { metaAt, strAt, condAt })
                if (n > at && n < end) end = n;
            return body[start..end];
        }

        // meta
        foreach (Match m in Regex.Matches(Section(metaAt), @"(\w+)\s*=\s*""([^""]*)"""))
        {
            string k = m.Groups[1].Value.ToLowerInvariant(), v = m.Groups[2].Value;
            if (k == "category") rule.Category = v;
            else if (k == "severity") rule.Severity = v;
        }

        // strings
        ParseStrings(Section(strAt), rule);

        // condition
        string cond = Section(condAt).Trim();
        if (Regex.IsMatch(cond, @"\ball\s+of\s+them\b", RegexOptions.IgnoreCase)) rule.All = true;
        else
        {
            var mn = Regex.Match(cond, @"\b(\d+)\s+of\s+them\b", RegexOptions.IgnoreCase);
            rule.MinHits = mn.Success ? Math.Max(1, int.Parse(mn.Groups[1].Value)) : 1;
        }
        return rule;
    }

    private static int SectionIndex(string body, string kw)
    {
        var m = Regex.Match(body, @"(?<![\w$])" + kw + @"\s*:");
        return m.Success ? m.Index : -1;
    }

    private static void ParseStrings(string s, YaraRule rule)
    {
        // Her "$id =" basini bul; deger ve degistiriciler bir sonraki "$id =" ya da
        // bolum sonuna kadar surer (tek satirda birden fazla desen de dogru ayristirilir).
        var heads = Regex.Matches(s, @"\$(\w+)\s*=\s*").Cast<Match>().ToList();
        for (int k = 0; k < heads.Count; k++)
        {
            var m = heads[k];
            string id = m.Groups[1].Value;
            int vs = m.Index + m.Length;
            int segEnd = k + 1 < heads.Count ? heads[k + 1].Index : s.Length;
            if (vs >= s.Length) continue;

            var p = new Pat { Id = id };
            int valEnd;
            char c0 = s[vs];
            if (c0 == '"')
            {
                valEnd = IndexOfUnescaped(s, '"', vs + 1);
                if (valEnd < 0 || valEnd > segEnd) continue;
                SetMods(p, Tail(s, valEnd + 1, segEnd));
                string lit = Unescape(s[(vs + 1)..valEnd]);
                if (lit.Length == 0) continue;
                p.Kind = PatKind.Text;
                p.Bytes = p.Wide ? Encoding.Unicode.GetBytes(lit) : Encoding.ASCII.GetBytes(lit);
            }
            else if (c0 == '{')
            {
                valEnd = s.IndexOf('}', vs + 1);
                if (valEnd < 0 || valEnd > segEnd) continue;
                if (!ParseHex(s[(vs + 1)..valEnd], out var by, out var mk)) continue;
                p.Kind = PatKind.Hex; p.Bytes = by; p.Mask = mk;
            }
            else if (c0 == '/')
            {
                valEnd = IndexOfUnescaped(s, '/', vs + 1);
                if (valEnd < 0 || valEnd > segEnd) continue;
                SetMods(p, Tail(s, valEnd + 1, segEnd));
                try
                {
                    p.Kind = PatKind.Regex;
                    p.Re = new Regex(s[(vs + 1)..valEnd],
                        (p.NoCase ? RegexOptions.IgnoreCase : 0) | RegexOptions.CultureInvariant);
                }
                catch { continue; }
            }
            else continue;
            rule.Pats.Add(p);
        }
    }

    private static string Tail(string s, int from, int to)
    {
        to = Math.Min(to, s.Length);
        return from < to ? s[from..to] : "";
    }

    private static void SetMods(Pat p, string tail)
    {
        p.NoCase = Regex.IsMatch(tail, @"\bnocase\b", RegexOptions.IgnoreCase);
        p.Wide = Regex.IsMatch(tail, @"\bwide\b", RegexOptions.IgnoreCase);
    }

    private static int IndexOfUnescaped(string s, char ch, int from)
    {
        for (int i = from; i < s.Length; i++)
        {
            if (s[i] == '\\') { i++; continue; }
            if (s[i] == ch) return i;
        }
        return -1;
    }

    private static bool ParseHex(string s, out byte[] bytes, out byte[] mask)
    {
        var tokens = Regex.Matches(s, @"[0-9A-Fa-f?]{2}").Select(m => m.Value).ToList();
        bytes = new byte[tokens.Count]; mask = new byte[tokens.Count];
        if (tokens.Count == 0) return false;
        for (int i = 0; i < tokens.Count; i++)
        {
            char hi = tokens[i][0], lo = tokens[i][1];
            int b = 0, mk = 0;
            if (hi == '?') { } else { b |= HexVal(hi) << 4; mk |= 0xF0; }
            if (lo == '?') { } else { b |= HexVal(lo); mk |= 0x0F; }
            bytes[i] = (byte)b; mask[i] = (byte)mk;
        }
        return true;
    }

    private static int HexVal(char c) => c <= '9' ? c - '0' : (char.ToLower(c) - 'a' + 10);

    private static string Unescape(string s) => s.Replace("\\\\", "\\").Replace("\\\"", "\"")
        .Replace("\\n", "\n").Replace("\\r", "\r").Replace("\\t", "\t");

    // ---------------- tarama ----------------

    public static List<RuleMatch> Scan(byte[] data, IEnumerable<string> strings, IReadOnlyList<YaraRule> rules)
    {
        var strList = strings as IReadOnlyList<string> ?? strings.ToList();
        var matches = new List<RuleMatch>();
        foreach (var rule in rules)
        {
            var hits = new List<string>();
            long first = long.MaxValue;
            foreach (var p in rule.Pats)
            {
                long off = FindPat(p, data, strList);
                if (off == NoOff) hits.Add(p.Id);
                else if (off >= 0) { hits.Add(p.Id); if (off < first) first = off; }
            }
            bool ok = rule.All ? hits.Count == rule.Pats.Count : hits.Count >= rule.MinHits;
            if (ok && hits.Count > 0)
                matches.Add(new RuleMatch { Rule = rule, HitIds = hits, FirstOffset = first == long.MaxValue ? -1 : first });
        }
        return matches;
    }

    private static long FindPat(Pat p, byte[] data, IReadOnlyList<string> strings)
    {
        switch (p.Kind)
        {
            case PatKind.Text:
                long at = IndexOf(data, p.Bytes, p.NoCase && !p.Wide);
                if (at >= 0 || p.Wide) return at;
                // ham veride yoksa cikarilmis stringlerde de ara
                string lit = Encoding.ASCII.GetString(p.Bytes);
                var cmp = p.NoCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                foreach (var s in strings) if (s.IndexOf(lit, cmp) >= 0) return NoOff; // eslesti, ofset yok
                return -1;
            case PatKind.Hex:
                return IndexOfMasked(data, p.Bytes, p.Mask);
            case PatKind.Regex:
                foreach (var s in strings)
                    if (p.Re!.IsMatch(s)) return NoOff;
                return -1;
            default: return -1;
        }
    }

    private static long IndexOf(byte[] data, byte[] pat, bool noCase)
    {
        if (pat.Length == 0 || data.Length < pat.Length) return -1;
        for (int i = 0; i <= data.Length - pat.Length; i++)
        {
            int k = 0;
            for (; k < pat.Length; k++)
            {
                byte a = data[i + k], b = pat[k];
                if (noCase) { a = Lower(a); b = Lower(b); }
                if (a != b) break;
            }
            if (k == pat.Length) return i;
        }
        return -1;
    }

    private static long IndexOfMasked(byte[] data, byte[] pat, byte[] mask)
    {
        if (pat.Length == 0 || data.Length < pat.Length) return -1;
        for (int i = 0; i <= data.Length - pat.Length; i++)
        {
            int k = 0;
            for (; k < pat.Length; k++)
                if ((data[i + k] & mask[k]) != (pat[k] & mask[k])) break;
            if (k == pat.Length) return i;
        }
        return -1;
    }

    private static byte Lower(byte b) => (b >= 'A' && b <= 'Z') ? (byte)(b + 32) : b;

    // ---------------- gomulu kural seti ----------------

    public static List<YaraRule> Builtins() => Parse(BuiltinText);

    public const string BuiltinText = @"
rule Base64_PE_Header {
    meta: category = ""Gosterge"" severity = ""Orta""
    strings:
        $b64mz = ""TVqQAAMAAAAEAAA""
    condition: any of them
}
rule UPX_Packer {
    meta: category = ""Imza"" severity = ""Orta""
    strings:
        $u1 = ""UPX!""
        $u2 = ""This file is packed with the UPX""
    condition: any of them
}
rule PowerShell_Exec {
    meta: category = ""Yetenek"" severity = ""Yuksek""
    strings:
        $p1 = ""powershell"" nocase
        $p2 = ""-enc"" nocase
        $p3 = ""FromBase64String"" nocase
        $p4 = ""-nop"" nocase
        $p5 = ""IEX"" nocase
    condition: 2 of them
}
rule Shell_Command {
    meta: category = ""Yetenek"" severity = ""Orta""
    strings:
        $c1 = ""cmd.exe /c"" nocase
        $c2 = ""cmd /c"" nocase
        $c3 = ""/c del"" nocase
    condition: any of them
}
rule Run_Key_Persistence {
    meta: category = ""Yetenek"" severity = ""Yuksek""
    strings:
        $r = ""Software\\Microsoft\\Windows\\CurrentVersion\\Run"" nocase
    condition: any of them
}
rule Credential_Theft {
    meta: category = ""Gosterge"" severity = ""Yuksek""
    strings:
        $m1 = ""sekurlsa"" nocase
        $m2 = ""mimikatz"" nocase
        $m3 = ""logonpasswords"" nocase
    condition: any of them
}
rule AES_SBox {
    meta: category = ""Kripto"" severity = ""Bilgi""
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition: any of them
}
rule URL_Indicator {
    meta: category = ""Gosterge"" severity = ""Bilgi""
    strings:
        $u = /https?:\/\/[A-Za-z0-9.\-]+/
    condition: any of them
}
";
}
