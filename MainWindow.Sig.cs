using System.IO;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

// Hafif kutuphane imzasi (FLIRT benzeri): uret / uygula
public partial class MainWindow
{
    private void GenerateSignatures()
    {
        if (_s == null) return;
        var sigs = Flirt.Generate(_s.Db, _s.Dis);
        if (sigs.Count == 0)
        {
            Dialogs.Info(this, "İmza üret", "Bu dosyada imza üretilebilecek adlandırılmış fonksiyon yok. "
                + "Önce sembolleri yükle (PDB) ya da fonksiyonları adlandır.");
            return;
        }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Loc.T("İmza dosyasını kaydet"),
            Filter = Loc.T("tlk-hex imza (*.sig)|*.sig|Tüm dosyalar (*.*)|*.*"),
            FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + ".sig",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            Flirt.Save(dlg.FileName, sigs);
            _out.Log(Loc.F("İmza: {0} adlandırılmış fonksiyondan imza üretildi → {1}", sigs.Count, Path.GetFileName(dlg.FileName)));
            SetStatus(Loc.F("{0} imza kaydedildi.", sigs.Count));
        }
        catch (Exception ex) { Dialogs.Info(this, "Hata", Loc.T("İmza kaydedilemedi:\n") + ex.Message); }
    }

    private void ExportReport()
    {
        if (_s == null) return;
        _result ??= _s.ToResult();
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = Loc.T("Analiz raporunu kaydet"),
            Filter = Loc.T("HTML rapor (*.html)|*.html|Tüm dosyalar (*.*)|*.*"),
            FileName = Path.GetFileNameWithoutExtension(_s.Db.FilePath) + "-rapor.html",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            Report.Save(dlg.FileName, _result);
            _out.Log(Loc.F("Rapor oluşturuldu → {0}", Path.GetFileName(dlg.FileName)));
            SetStatus("Rapor kaydedildi.");
            if (Dialogs.Confirm(this, "Rapor", "Rapor kaydedildi. Tarayıcıda açılsın mı?"))
                try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true }); }
                catch { }
        }
        catch (Exception ex) { Dialogs.Info(this, "Hata", Loc.T("Rapor oluşturulamadı:\n") + ex.Message); }
    }

    private void ApplySignatures()
    {
        if (_s == null) return;
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = Loc.T("Uygulanacak imza dosyasını seç"),
            Filter = Loc.T("tlk-hex imza (*.sig)|*.sig|Tüm dosyalar (*.*)|*.*"),
        };
        if (dlg.ShowDialog(this) != true) return;
        List<Signature> sigs;
        try { sigs = Flirt.Load(dlg.FileName); }
        catch (Exception ex) { Dialogs.Info(this, "Hata", Loc.T("İmza dosyası okunamadı:\n") + ex.Message); return; }
        if (sigs.Count == 0) { Dialogs.Info(this, "İmza uygula", "Dosyada geçerli imza yok."); return; }

        int n = Flirt.Apply(_s.Db, _s.Dis, sigs, (ea, name) =>
        {
            _s!.Db.LoaderNames[ea] = name;   // sembol benzeri (kullanici adi degil)
        });
        _out.Log(Loc.F("İmza: {0} imzadan {1} fonksiyon adlandırıldı ({2}).", sigs.Count, n, Path.GetFileName(dlg.FileName)));
        if (n > 0) { AfterEdit(Here()); SetStatus(Loc.F("{0} fonksiyon imzayla adlandırıldı.", n)); }
        else SetStatus("Eşleşen imza bulunamadı.");
    }
}
