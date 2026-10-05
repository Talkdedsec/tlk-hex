using AvalonDock.Layout;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// Arama paneli baglantisi
public partial class MainWindow
{
    private readonly SearchPane _sp = new();
    private LayoutAnchorable _searchAnch = null!;
    private CancellationTokenSource? _spCts;

    private void SetupSearchPane()
    {
        _sp.SearchRequested += RunPaneSearch;
        _sp.Activated += r => Jump(r.Ea);
        _sp.Previewed += r => { if (_s != null && _s.Db.IsMapped(r.Ea)) Jump(r.Ea, false, false); };
    }

    private void ShowSearch(string? text = null, string scope = "all")
    {
        ShowAnch(_searchAnch);
        if (text != null) _sp.Start(text, scope);
        else _sp.FocusBox();
    }

    private async void RunPaneSearch(SearchQuery q)
    {
        if (_s == null) { _sp.SetStatus("Önce bir dosya aç."); return; }
        _spCts?.Cancel();
        var cts = new CancellationTokenSource();
        _spCts = cts;
        var db = _s.Db;

        // arayuz is parcaciginda anlik kopyalar
        var names = new List<(string, ulong)>();
        var seen = new HashSet<ulong>();
        foreach (var f in db.Funcs.Values)
            if (f.Chunks.Count > 0 && seen.Add(f.Start)) names.Add((db.FuncName(f), f.Start));
        foreach (var r in NameRows())
            if (seen.Add(r.Ea)) names.Add((r.C[1], r.Ea));
        var strings = db.Strings.ToList();
        var comments = db.Comments.Select(kv => (kv.Key, kv.Value))
            .Concat(db.RepComments.Select(kv => (kv.Key, kv.Value))).ToList();
        var worker = _s.List.CloneForWorker();

        _sp.SetStatus("Aranıyor...");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        List<Hit> hits;
        string? err = null;
        try
        {
            hits = await Task.Run(() => SearchEngine.Run(q, db, worker, names, strings, comments, cts.Token, out err), cts.Token);
        }
        catch (OperationCanceledException) { return; }
        if (cts.IsCancellationRequested || _s == null || _s.Db != db) return;
        if (err != null) { _sp.SetStatus(err); return; }

        var rows = hits.Select(h => new Row
        {
            Ea = h.Ea,
            C = new[]
            {
                h.Kind, db.SegOf(h.Ea)?.Name + ":" + db.AddrStr(h.Ea),
                db.FuncAt(h.Ea) is Function f ? db.FuncName(f) : "", h.Text,
            },
        }).ToList();
        _sp.Results.SetRows(rows);
        string more = hits.Count >= 5000 ? " (ilk 5000)" : "";
        _sp.SetStatus(hits.Count == 0
            ? $"'{q.Text}' için sonuç yok."
            : $"{hits.Count:N0} sonuç{more}  •  {sw.Elapsed.TotalSeconds:0.00} sn  •  tıkla = önizle, çift tık / Enter = git");
    }
}
