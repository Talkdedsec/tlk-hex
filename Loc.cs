namespace tlk_hex;

// Basit arayuz yerellestirmesi. Anahtar = Turkce kaynak metin.
// Lang == "en" ise sozlukten Ingilizcesi dondurulur; yoksa Turkce kalir.
// Menu/diyalog/panel yardimcilari metinlerini buradan gecirir.
public static class Loc
{
    public static string Lang = "tr";

    public static bool En => Lang == "en";

    // Duz metin cevirisi (anahtar = Turkce)
    public static string T(string tr)
        => En && Map.TryGetValue(tr, out var v) ? v : tr;

    // Bicimli metin: once sablon cevrilir, sonra string.Format
    public static string F(string tr, params object[] args)
        => string.Format(T(tr), args);

    // Iki dilli dogrudan secim (sozluge koymaya degmeyen, yerinde ceviriler icin)
    public static string TE(string tr, string en) => En ? en : tr;

    private static readonly Dictionary<string, string> Map = Translations.En;
}
