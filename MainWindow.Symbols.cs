using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// PDB sembolleri: sor / indir / uygula
public partial class MainWindow
{
    private bool _symBusy;

    // Dosya acildiktan sonra cagrilir
    private async void AfterOpenSymbols()
    {
        if (_s == null || _s.Db.SymbolSource != null || Pdb.Key(_s.Db) == null) return;
        if (Application.Current is App { Autonomous: true }) return;
        string mode = _cfg.SymbolMode;
        if (mode == "never") return;
        if (mode == "ask")
        {
            var ans = AskSymbols(Pdb.PdbFileName(_s.Db));
            if (ans == null) return;
            if (ans == "always" || ans == "never")
            {
                _cfg.SymbolMode = ans;
                _cfg.Save();
            }
            if (ans == "never") return;
        }
        await DownloadSymbols();
    }

    private string? AskSymbols(string pdb)
    {
        var w = Dialogs.Make(this, "Semboller (PDB)", 520);
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBlock
        {
            Text = Loc.F("Bu dosyanın sembolleri ({0}) Microsoft sembol sunucusundan indirilebilir.\n\n", pdb) +
                   Loc.T("İndirilirse 'sub_140001A54' gibi isimler gerçek fonksiyon adlarıyla değişir ") +
                   Loc.T("(Windows dosyalarında genelde işe yarar). Sunucuya yalnızca PDB adı ve kimliği gönderilir."),
            TextWrapping = TextWrapping.Wrap,
        });
        string? r = null;
        var always = Dialogs.Btn("Her zaman indir", true);
        var once = Dialogs.Btn("Bu sefer indir");
        var no = Dialogs.Btn("Hayır", false, true);
        var never = Dialogs.Btn("Bir daha sorma");
        always.Click += (_, _) => { r = "always"; w.DialogResult = true; };
        once.Click += (_, _) => { r = "once"; w.DialogResult = true; };
        never.Click += (_, _) => { r = "never"; w.DialogResult = true; };
        sp.Children.Add(Dialogs.Buttons(always, once, no, never));
        w.Content = sp;
        w.ShowDialog();
        return r;
    }

    private async Task DownloadSymbols()
    {
        if (_s == null || _symBusy) return;
        if (Pdb.Key(_s.Db) == null) { _out.Log("Bu dosyada PDB bilgisi (RSDS) yok; sembol indirilemez."); return; }
        var db = _s.Db;
        _symBusy = true;
        SetAu(true, "AU:  sembol indiriliyor");
        try
        {
            var path = await Pdb.DownloadAsync(db, m => Dispatcher.BeginInvoke(() => _out.Log(m)), CancellationToken.None);
            if (path != null && _s != null && _s.Db == db) ApplySymbols(path);
        }
        catch (Exception ex) { _out.Log(Loc.T("Sembol indirme hatası: ") + ex.Message); }
        finally
        {
            _symBusy = false;
            SetAu(false);
        }
    }

    private void ApplySymbols(string path)
    {
        if (_s == null) return;
        ulong here = Here();
        Mouse.OverrideCursor = Cursors.Wait;
        try
        {
            var (n, nf) = _s.ApplyPdb(path);
            _out.Log(Loc.F("Semboller uygulandı: {0} isim, {1} yeni fonksiyon.", n, nf));
            SetStatus(Loc.F("Semboller yüklendi: {0} isim.", n));
        }
        catch (Exception ex)
        {
            _out.Log(Loc.T("PDB okunamadı: ") + ex.Message);
        }
        finally { Mouse.OverrideCursor = null; }
        _result = null;
        _dv.Refresh();
        _gv.MarkDirty();
        _hv.Refresh();
        Nav.Recompute();
        _fp.Reload();
        RefreshLists();
        BuildGoItems();
        _ct.SetSession(_s);
        Jump(here, false, false);
    }

    private void LoadPdbFile()
    {
        if (_s == null) return;
        var dlg = new OpenFileDialog { Title = Loc.T("PDB dosyası seç"), Filter = Loc.T("Program veritabanı (*.pdb)|*.pdb|Tüm dosyalar (*.*)|*.*") };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var bytes = File.ReadAllBytes(dlg.FileName);
            if (!Pdb.IsPdb(bytes)) { Dialogs.Info(this, "PDB", "Seçilen dosya bir PDB değil."); return; }
            var (g, _) = Pdb.Identity(bytes);
            if (_s.Db.PdbGuid != Guid.Empty && g != _s.Db.PdbGuid &&
                !Dialogs.Confirm(this, "PDB eşleşmiyor", "Bu PDB dosyanın kimliğiyle eşleşmiyor; isimler yanlış olabilir. Yine de yüklensin mi?"))
                return;
        }
        catch (Exception ex) { Dialogs.Info(this, "PDB", Loc.T("Okunamadı: ") + ex.Message); return; }
        ApplySymbols(dlg.FileName);
    }
}
