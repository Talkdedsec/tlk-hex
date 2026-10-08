using System.Text.RegularExpressions;

namespace tlk_hex;

// Import ve string'lere bakarak sezgisel guvenlik bulgulari uretir.
public static class FindingsEngine
{
    // Siddet siralamasi (dusuk rank = once gosterilir)
    private const int R_HIGH = 0;
    private const int R_MED = 1;
    private const int R_INFO = 2;

    private record Rule(string Severity, string Category, string Title,
        string[] Apis, string DetailTemplate, int Rank);

    private static readonly Rule[] ApiRules =
    {
        new("Yuksek", "Yetenek", "Hata ayiklama karsiti",
            new[]{"IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
                  "OutputDebugString","NtSetInformationThread","DebugActiveProcess"},
            "Hata ayiklamayi tespit/engelleme API'leri; analiz karsiti davranis.", R_HIGH),

        new("Yuksek", "Yetenek", "Tus kaydi / girdi yakalama",
            new[]{"SetWindowsHookEx","GetAsyncKeyState","GetKeyState","GetKeyboardState",
                  "RegisterRawInputDevices","GetRawInputData"},
            "Klavye kancasi veya tus durumu okuma API'leri.", R_HIGH),

        new("Yuksek", "Yetenek", "Kod enjeksiyonu",
            new[]{"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtUnmapViewOfSection",
                  "QueueUserAPC","SetThreadContext","RtlCreateUserThread","NtMapViewOfSection"},
            "Baska surece kod yazma/calistirma API'leri; process injection.", R_HIGH),

        new("Orta", "Yetenek", "Ag iletisimi",
            new[]{"socket","connect","send","recv","WSAStartup","InternetOpen","InternetConnect",
                  "HttpSendRequest","HttpOpenRequest","WinHttpOpen","WinHttpConnect","URLDownloadToFile",
                  "InternetReadFile","gethostbyname","getaddrinfo","WSASend","WSARecv"},
            "Ag API'leri ({0} cagri); indirme / C2 / sizdirma olabilir.", R_MED),

        new("Orta", "Yetenek", "Komut yurutme",
            new[]{"CreateProcess","ShellExecute","WinExec","system","_wsystem","CreateProcessAsUser"},
            "Harici program/komut calistirma API'leri.", R_MED),

        new("Orta", "Yetenek", "Kayit defteri erisimi",
            new[]{"RegOpenKey","RegSetValue","RegCreateKey","RegDeleteKey","RegQueryValue","RegGetValue"},
            "Kayit defteri okuma/yazma; ayar veya kalicilik olabilir.", R_MED),

        new("Orta", "Yetenek", "Kriptografi",
            new[]{"CryptEncrypt","CryptDecrypt","CryptGenKey","BCryptEncrypt","BCryptDecrypt",
                  "CryptAcquireContext","CryptHashData","CryptDeriveKey"},
            "Sifreleme API'leri; fidye yazilimi veya veri gizleme olabilir.", R_MED),

        new("Orta", "Yetenek", "Servis yonetimi",
            new[]{"CreateService","OpenSCManager","StartService","ControlService","ChangeServiceConfig"},
            "Windows servisi olusturma/yonetme; kalicilik olabilir.", R_MED),

        new("Bilgi", "Yetenek", "Surec listeleme",
            new[]{"CreateToolhelp32Snapshot","Process32First","Process32Next","EnumProcesses",
                  "EnumProcessModules"},
            "Calisan surecleri numaralandirma; AV/analiz araci arama olabilir.", R_INFO),

        new("Bilgi", "Yetenek", "Ekran yakalama",
            new[]{"BitBlt","GetDC","CreateCompatibleDC","CreateCompatibleBitmap","GetWindowDC"},
            "Ekran goruntusu alma API'leri.", R_INFO),

        new("Bilgi", "Yetenek", "Pano erisimi",
            new[]{"GetClipboardData","OpenClipboard","SetClipboardData"},
            "Pano (clipboard) okuma/yazma.", R_INFO),

        new("Bilgi", "Yetenek", "Dosya sistemi gezinme",
            new[]{"FindFirstFile","FindNextFile","GetLogicalDrives","GetDriveType"},
            "Dosya/dizin tarama API'leri.", R_INFO),
    };

    // Bilinen paketleyici / koruyucu bolum adlari (kucuk harf) -> arac
    private static readonly (string Sig, string Tool)[] PackerSigs =
    {
        ("upx", "UPX"), (".aspack", "ASPack"), (".adata", "ASPack"), (".nsp", "NsPack"),
        (".fsg", "FSG"), (".petite", "Petite"), (".mpress", "MPRESS"), (".themida", "Themida"),
        (".vmp", "VMProtect"), (".enigma", "Enigma"), (".pec", "PECompact"), (".y0da", "yoda"),
        (".boom", "Boomerang"), (".mew", "MEW"), (".packed", "generic"), (".perplex", "Perplex"),
        ("winlice", "WinLicense"), (".taz", "PESpin"), (".svkp", "SVKP"),
    };

    // String icinde aranan hassas kelimeler
    private static readonly string[] SensitiveWords =
        { "password", "passwd", "secret", "apikey", "api_key", "token", "credential",
          "private key", "-----begin", "authorization", "bearer " };

    public static List<FindingEntry> Analyze(AnalysisResult r)
    {
        var list = new List<FindingEntry>();

        // Tum import fonksiyon adlari (kucuk harf)
        var impNames = r.Imports.Select(i => i.Function.ToLowerInvariant()).ToList();
        var impSet = new HashSet<string>(impNames);

        // API tabanli kurallar
        foreach (var rule in ApiRules)
        {
            int hits = 0;
            foreach (var api in rule.Apis)
            {
                string a = api.ToLowerInvariant();
                // tam eslesme veya A/W son ekli varyant
                hits += impNames.Count(n => n == a || n == a + "a" || n == a + "w"
                                            || n.StartsWith(a));
            }
            if (hits > 0)
            {
                string detail = rule.DetailTemplate.Contains("{0}")
                    ? Loc.F(rule.DetailTemplate, hits)
                    : Loc.T(rule.DetailTemplate);
                list.Add(new FindingEntry
                {
                    Severity = rule.Severity,
                    Category = rule.Category,
                    Title = Loc.T(rule.Title),
                    Detail = detail,
                    Rank = rule.Rank,
                });
            }
        }

        // Dinamik API cozumu (LoadLibrary + GetProcAddress)
        bool hasLoad = impSet.Any(n => n.StartsWith("loadlibrary"));
        bool hasGpa = impSet.Contains("getprocaddress");
        if (hasLoad && hasGpa)
        {
            list.Add(new FindingEntry
            {
                Severity = "Orta", Category = "Gosterge", Title = Loc.T("Dinamik API cozumu"),
                Detail = Loc.T("LoadLibrary + GetProcAddress; fonksiyonlar calisma aninda cozulerek import tablosundan gizleniyor."),
                Rank = R_MED,
            });
        }

        // Hassas anahtar kelimeler (string taramasi)
        var foundWords = new List<string>();
        foreach (var w in SensitiveWords)
        {
            if (r.Strings.Any(s => s.Value.ToLowerInvariant().Contains(w)))
                foundWords.Add(w);
        }
        if (foundWords.Count > 0)
        {
            list.Add(new FindingEntry
            {
                Severity = "Yuksek", Category = "Gosterge",
                Title = Loc.F("{0} hassas anahtar kelime", foundWords.Count),
                Detail = Loc.F("{0} gibi ifadeler Strings'te isaretli.", string.Join(", ", foundWords.Take(6))),
                Rank = R_HIGH,
            });
        }

        // URL ve IP gostergeleri
        int urlCount = r.Strings.Count(s => s.Value.Contains("http://") || s.Value.Contains("https://"));
        var ipRegex = new Regex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b");
        int ipCount = r.Strings.Count(s => ipRegex.IsMatch(s.Value));
        if (urlCount > 0 || ipCount > 0)
        {
            list.Add(new FindingEntry
            {
                Severity = "Bilgi", Category = "Gosterge", Title = Loc.T("URL / IP gostergeleri"),
                Detail = Loc.F("{0} URL, {1} IP benzeri ifade Strings'te bulundu.", urlCount, ipCount),
                Rank = R_INFO,
            });
        }

        // Yuksek entropi (paketlenmis olabilir) - kaynak bolumu haric, esik 7.5
        var packed = r.Sections.Where(s =>
        {
            if (s.Name.Contains(".rsrc")) return false;
            return double.TryParse(s.Entropy, System.Globalization.NumberStyles.Any,
                       System.Globalization.CultureInfo.InvariantCulture, out var e) && e > 7.5;
        }).ToList();
        if (packed.Count > 0)
        {
            list.Add(new FindingEntry
            {
                Severity = "Orta", Category = "Imza", Title = Loc.T("Yuksek entropi (paketli?)"),
                Detail = Loc.F("{0} bolum(ler)i yuksek entropili; paketlenmis/sifreli olabilir.", string.Join(", ", packed.Select(p => p.Name))),
                Rank = R_MED,
            });
        }

        // Bilinen paketleyici bolum adlari
        var packerHits = new List<string>();
        foreach (var s in r.Sections)
        {
            string nm = s.Name.ToLowerInvariant();
            foreach (var (sig, tool) in PackerSigs)
                if (nm.Contains(sig)) { packerHits.Add($"{s.Name} ({tool})"); break; }
        }
        if (packerHits.Count > 0)
        {
            list.Add(new FindingEntry
            {
                Severity = "Yuksek", Category = "Imza", Title = Loc.T("Paketleyici imzasi"),
                Detail = Loc.F("{0} - bilinen paketleyici bolum adi; once acmak (unpack) gerekir.", string.Join(", ", packerHits.Distinct())),
                Rank = R_HIGH,
            });
        }

        // Seyrek import tablosu + dinamik cozum -> paketlenmis gostergesi
        if (r.Imports.Count > 0 && r.Imports.Count < 12 && r.FileType != "DLL")
        {
            list.Add(new FindingEntry
            {
                Severity = "Orta", Category = "Gosterge", Title = Loc.T("Seyrek import tablosu"),
                Detail = Loc.F("Yalnizca {0} import; gercek yetenekler calisma aninda cozuluyor olabilir (paketli/gizlenmis).", r.Imports.Count),
                Rank = R_MED,
            });
        }

        // imphash (import tablosu parmak izi) - ayni ailedeki ornekleri eslestirmek icin
        string imphash = ComputeImphash(r.Imports);
        if (imphash.Length > 0)
        {
            list.Add(new FindingEntry
            {
                Severity = "Bilgi", Category = "Ozet", Title = "imphash",
                Detail = imphash + Loc.T(" - import tablosu parmak izi; ayni derleyici/aile orneklerini eslestirmek icin."),
                Rank = 90,
            });
        }

        // Dijital imza
        if (!r.IsSigned)
        {
            list.Add(new FindingEntry
            {
                Severity = "Orta", Category = "Imza", Title = Loc.T("Dosya imzasiz"),
                Detail = Loc.T("Dijital imza yok - yayinci kimligi dogrulanamaz."),
                Rank = R_MED,
            });
        }

        // Yazilabilir + calistirilabilir bolum (W^X ihlali)
        var wx = r.Sections.Where(s => s.Flags.Contains("W") && s.Flags.Contains("X")).ToList();
        if (wx.Count > 0)
        {
            list.Add(new FindingEntry
            {
                Severity = "Orta", Category = "Imza", Title = Loc.T("Yazilabilir+calistirilabilir bolum"),
                Detail = Loc.F("{0}: hem yazilabilir hem calistirilabilir; self-modifying kod olabilir.", string.Join(", ", wx.Select(s => s.Name))),
                Rank = R_MED,
            });
        }

        // Ozet bulgusu
        string bits = r.Architecture == "x64" ? "64-bit" : r.Architecture == "x86" ? "32-bit" : r.Architecture;
        list.Add(new FindingEntry
        {
            Severity = "Bilgi", Category = "Ozet",
            Title = Loc.F("Dosya turu: {0}", r.FileType == "DLL" ? Loc.T("yerel DLL") : r.FileType),
            Detail = Loc.F("{0} - {1:N0} import - {2:N0} export - {3:N0} fonksiyon - {4:N0} string.",
                     bits, r.Imports.Count, r.Exports.Count, r.Functions.Count, r.Strings.Count),
            Rank = 99,
        });

        // Siralama: siddet, sonra rank
        return list
            .OrderBy(f => SevOrder(f.Severity))
            .ThenBy(f => f.Rank)
            .ToList();
    }

    // Klasik imphash: her import "dll(uzantisiz).fonksiyon" kucuk harf, virgulle birlesir, MD5.
    private static string ComputeImphash(IReadOnlyList<ImportEntry> imports)
    {
        if (imports.Count == 0) return "";
        var parts = new List<string>(imports.Count);
        foreach (var i in imports)
        {
            string dll = i.Dll.ToLowerInvariant();
            int dot = dll.LastIndexOf('.');
            if (dot > 0 && (dll.EndsWith(".dll") || dll.EndsWith(".ocx") || dll.EndsWith(".sys")))
                dll = dll[..dot];
            string fn = i.Function.ToLowerInvariant();
            if (string.IsNullOrEmpty(fn)) continue;
            parts.Add($"{dll}.{fn}");
        }
        if (parts.Count == 0) return "";
        var bytes = System.Text.Encoding.ASCII.GetBytes(string.Join(",", parts));
        var hash = System.Security.Cryptography.MD5.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static int SevOrder(string sev) => sev switch
    {
        "Yuksek" => 0,
        "Orta" => 1,
        "Bilgi" => 2,
        _ => 3,
    };
}
