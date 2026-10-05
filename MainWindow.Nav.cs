using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

public partial class MainWindow
{
    private bool _graphMode;
    private bool _syncing;
    private ulong _curEa;
    private readonly List<ulong> _back = new();
    private readonly List<ulong> _fwd = new();
    private readonly List<string> _jumpHist = new();

    // Etkin gorunumdeki adres
    private ulong Here()
    {
        if (_s == null) return 0;
        return _graphMode ? _gv.CursorEa : _dv.CurrentEa;
    }

    private ulong HereHead() => _s == null ? 0 : _s.Db.HeadOf(Here());

    private void FocusIda()
    {
        if (_graphMode) _gv.Focus(); else _dv.Focus();
    }

    private void ActivateIda(bool focus = true)
    {
        if (!_docs.TryGetValue("idaview", out var d) || d.Parent == null)
            d = ShowDoc("idaview", "IDA View-A", _idaPane, false, focus);
        if (focus) d.IsActive = true; else d.IsSelected = true;
    }

    public void Jump(ulong ea, bool push = true, bool focus = true)
    {
        if (_s == null) return;
        if (!_s.Db.IsMapped(ea))
        {
            _out.Log($"Adres {Db.Hx(ea)} hiçbir segmentte değil.");
            System.Media.SystemSounds.Beep.Play();
            return;
        }
        ulong cur = Here();
        if (push && _curEa != 0 && cur != ea)
        {
            _back.Add(cur);
            if (_back.Count > 500) _back.RemoveAt(0);
            _fwd.Clear();
        }
        ActivateIda(focus);
        if (_graphMode)
        {
            var f = _s.Db.FuncAt(ea);
            if (f != null)
            {
                _gv.Show(_s, f, ea);
                OnViewCursor(ea);
            }
            else
            {
                _out.Log("Yalnızca bir fonksiyona ait komutlar graph modunda gösterilebilir; metin görünümüne geçildi.");
                SetGraph(false, ea);
            }
        }
        else _dv.JumpTo(ea);
        if (focus) FocusIda();
    }

    private void Back()
    {
        if (_back.Count == 0) return;
        ulong ea = _back[^1];
        _back.RemoveAt(_back.Count - 1);
        _fwd.Add(Here());
        Jump(ea, false);
    }

    private void Forward()
    {
        if (_fwd.Count == 0) return;
        ulong ea = _fwd[^1];
        _fwd.RemoveAt(_fwd.Count - 1);
        _back.Add(Here());
        Jump(ea, false);
    }

    private void SetGraph(bool on, ulong? at = null)
    {
        if (_s == null) return;
        ulong ea = at ?? Here();
        if (on)
        {
            var f = _s.Db.FuncAt(ea);
            if (f == null)
            {
                _out.Log("Yalnızca bir fonksiyona ait komutlar graph modunda gösterilebilir.");
                SetStatus("Graph: imleç bir fonksiyon içinde değil.");
                return;
            }
            _graphMode = true;
            _gv.Visibility = Visibility.Visible;
            _dv.Visibility = Visibility.Collapsed;
            _gv.Show(_s, f, ea);
            OnViewCursor(ea);
            _gv.Focus();
        }
        else
        {
            _graphMode = false;
            _dv.Visibility = Visibility.Visible;
            _gv.Visibility = Visibility.Collapsed;
            _dv.JumpTo(ea);
            _dv.Focus();
        }
        UpdateIdaStatus();
    }

    // IDA View imleci degisti -> hex, nav band, agac, durum
    private void OnViewCursor(ulong ea)
    {
        if (_s == null) return;
        _curEa = ea;
        Nav.Current = ea;
        UpdateIdaStatus();
        if (!_syncing)
        {
            _syncing = true;
            try
            {
                ulong head = _s.Db.HeadOf(ea);
                int sz = Math.Max(1, _s.Db.ItemSize(head));
                _hv.SetHighlight(head, head + (ulong)sz);
                if (!_hv.IsKeyboardFocusWithin) _hv.GotoEa(head);
            }
            finally { _syncing = false; }
        }
        _ct.Show(_s.Db.FuncAt(ea));
        ShowHint();
    }

    private void OnHexCursor()
    {
        if (_s == null || _syncing || !_hv.IsKeyboardFocusWithin) return;
        ulong ea = _hv.CursorEa;
        _syncing = true;
        try
        {
            ulong head = _s.Db.HeadOf(ea);
            _hv.SetHighlight(head, head + (ulong)Math.Max(1, _s.Db.ItemSize(head)));
            if (_graphMode)
            {
                var f = _s.Db.FuncAt(head);
                if (f != null) _gv.Show(_s, f, head);
            }
            else _dv.JumpTo(head);
            _curEa = head;
            Nav.Current = head;
            UpdateIdaStatus();
        }
        finally { _syncing = false; }
    }

    private void UpdateIdaStatus()
    {
        if (_s == null) { _idaStatus.Text = ""; return; }
        ulong ea = Here();
        long off = _s.Db.FileOffsetOf(ea);
        string loc = _s.Db.LocStr(ea);
        string offs = off >= 0 ? off.ToString("X8") : "--------";
        string z = _graphMode ? $"{_gv.Zoom * 100:0.00}%  " : "";
        _idaStatus.Text = $"{z}{offs} {_s.Db.AddrStr(ea)}: {loc}   (Hex View-1 ile senkronize)";
        StatusRight.Text = _s.Db.SegOf(ea)?.Name + ":" + _s.Db.AddrStr(ea);
    }

    // ================= Imlec altindaki kelime =================

    private string? Word()
    {
        if (_pv.IsKeyboardFocusWithin) return _pv.WordAtCursor();
        return _graphMode ? _gv.HighlightWord : _dv.WordAtCursor();
    }

    private static bool IsRegister(string w) =>
        Enum.TryParse<Iced.Intel.Register>(w, true, out var r) && r != Iced.Intel.Register.None && !w.All(char.IsDigit);

    private ulong? WordEa(string? w)
    {
        if (_s == null || string.IsNullOrEmpty(w) || IsRegister(w)) return null;
        var db = _s.Db;
        if (db.NameIndex().TryGetValue(w, out var ea)) return ea;
        int us = w.IndexOf('_');
        if (us > 0 && us < w.Length - 1 && db.Resolve(w) is ulong r1 && db.IsMapped(r1)) return r1;
        // salt sayi: rakam icermeli
        if (w.Any(char.IsDigit) && db.Resolve(w) is ulong r2 && db.IsMapped(r2)) return r2;
        if (w == "__ImageBase") return null;
        return null;
    }

    private bool TryStackVar(Function f, string w, out int l)
    {
        l = 0;
        foreach (var kv in f.Vars)
            if (_s!.Dis.StackVarName(f, kv.Key) == w) { l = kv.Key; return true; }
        return false;
    }

    private void FollowUnderCursor()
    {
        if (_s == null) return;
        if (_pv.IsKeyboardFocusWithin)
        {
            var w0 = _pv.WordAtCursor();
            if (w0 != null && WordEa(w0) is ulong pt) { Jump(pt); return; }
            if (_pv.CurrentEa != 0) { Jump(_pv.CurrentEa); }
            return;
        }
        var w = Word();
        if (w != null && WordEa(w) is ulong t) { Jump(t); return; }
        // dal komutu ise hedefe
        if (_s.Dis.TryDecode(HereHead(), out var ins) && ins.Op0Kind is Iced.Intel.OpKind.NearBranch16
                or Iced.Intel.OpKind.NearBranch32 or Iced.Intel.OpKind.NearBranch64 && w == null)
            Jump(ins.NearBranchTarget);
    }

    // ================= Liste pencereleri =================

    private ListPane OpenList(string id, string title, (string, double)[] cols, Func<List<Row>> rows, bool activate = true,
        Action<Row>? act = null, Func<Row?, ContextMenu?>? menu = null)
    {
        if (_lists.TryGetValue(id, out var ex) && _docs.TryGetValue(id, out var d) && d.Parent != null)
        {
            ex.Pane.SetRows(rows());
            if (activate) d.IsActive = true;
            return ex.Pane;
        }
        var pane = new ListPane(cols);
        pane.Activated += act ?? (r => Jump(r.Ea));

        pane.MenuFor = menu ?? (r => r == null ? null : RowMenu(r));
        pane.SetRows(rows());
        _lists[id] = (pane, rows);
        ShowDoc(id, title, pane, true, activate);
        return pane;
    }

    private ContextMenu RowMenu(Row r)
    {
        var m = new ContextMenu();
        m.Items.Add(FunctionsPane.Mi("Atla\tEnter", () => Jump(r.Ea)));
        m.Items.Add(FunctionsPane.Mi("Xref'ler\tX", () => ShowXrefs(r.Ea)));
        m.Items.Add(FunctionsPane.Mi("Satırı kopyala", () => Copy(string.Join("  ", r.C))));
        return m;
    }

    private void RefreshLists()
    {
        foreach (var kv in _lists.ToList())
        {
            if (!_docs.TryGetValue(kv.Key, out var d) || d.Parent == null) { _lists.Remove(kv.Key); continue; }
            if (_s == null) continue;
            try { kv.Value.Pane.SetRows(kv.Value.Rows()); } catch { }
        }
    }

    private void ShowNames()
    {
        if (_s == null) return;
        OpenList("names", "Names", new[] { ("T", 24.0), ("Name", 300.0), ("Address", 220.0), ("Public", 60.0) }, NameRows);
    }

    private List<Row> NameRows()
    {
        var db = _s!.Db;
        var rows = new List<Row>();
        var seen = new HashSet<ulong>();
        void AddN(ulong ea, string n)
        {
            if (!seen.Add(ea)) return;
            string t = db.ImportAt.ContainsKey(ea) ? "I"
                : db.Funcs.TryGetValue(ea, out var f) ? (f.IsThunk || f.IsLibrary ? "L" : "F")
                : db.KindAt(ea) is ItemKind.Ascii or ItemKind.Utf16 ? "A"
                : db.KindAt(ea) == ItemKind.Code ? "C" : "D";
            rows.Add(new Row { Ea = ea, C = new[] { t, n, db.SegOf(ea)?.Name + ":" + db.AddrStr(ea), db.PublicNames.Contains(ea) ? "P" : "" } });
        }
        foreach (var kv in db.UserNames) AddN(kv.Key, kv.Value);
        foreach (var kv in db.LoaderNames) AddN(kv.Key, db.NameAt(kv.Key) ?? kv.Value);
        foreach (var kv in db.StrNames) AddN(kv.Key, db.NameAt(kv.Key) ?? kv.Value);
        return rows.OrderBy(r => r.Ea).ToList();
    }

    private void ShowStrings()
    {
        if (_s == null) return;
        OpenList("strings", "Strings", new[] { ("Address", 170.0), ("Length", 80.0), ("Type", 50.0), ("String", -1.0) }, () =>
        {
            var db = _s!.Db;
            return db.Strings.Select(s => new Row
            {
                Ea = s.Ea,
                C = new[] { db.SegOf(s.Ea)?.Name + ":" + db.AddrStr(s.Ea), s.Len.ToString("X8"), s.Type, Db.Escape(s.Value, 400) },
            }).ToList();
        }, true, null, r =>
        {
            if (r == null) return null;
            var m = RowMenu(r);
            m.Items.Add(FunctionsPane.Mi("String'i kopyala", () => Copy(r.C[3])));
            m.Items.Add(FunctionsPane.Mi("Burada string tanımla (A)", () =>
            {
                if (_s!.Au.MakeString(r.Ea, r.C[2] == "C16")) { _s.Au.Record("A", r.Ea, r.C[2] == "C16" ? 1 : 0); AfterEdit(r.Ea); }
            }));
            return m;
        });
    }

    private void ShowSegments()
    {
        if (_s == null) return;
        OpenList("segments", "Program Segmentation", new[]
        {
            ("Name", 90.0), ("Start", 140.0), ("End", 140.0), ("R", 22.0), ("W", 22.0), ("X", 22.0), ("D", 22.0), ("L", 22.0),
            ("Align", 50.0), ("Base", 50.0), ("Type", 60.0), ("Class", 60.0), ("AD", 40.0),
        }, () =>
        {
            var db = _s!.Db;
            return db.Segs.Select(s => new Row
            {
                Ea = s.Start,
                C = new[]
                {
                    s.Name, db.AddrStr(s.Start), db.AddrStr(s.End), s.R ? "R" : ".", s.W ? "W" : ".", s.X ? "X" : ".", ".", "L",
                    "para", "01", s.IsExtern ? "extern" : "public", s.Class, db.Bitness.ToString(),
                },
            }).ToList();
        });
    }

    private void ShowImports() => ShowImports(true);

    private void ShowImports(bool activate)
    {
        if (_s == null) return;
        OpenList("imports", "Imports", new[] { ("Address", 160.0), ("Ordinal", 60.0), ("Name", 300.0), ("Library", -1.0) }, () =>
        {
            var db = _s!.Db;
            return db.Imports.OrderBy(i => i.Ea).Select(i => new Row
            {
                Ea = i.Ea,
                C = new[] { db.AddrStr(i.Ea), i.Ordinal >= 0 ? i.Ordinal.ToString() : "", i.Name, i.Dll },
            }).ToList();
        }, activate);
    }

    private void ShowExports() => ShowExports(true);

    private void ShowExports(bool activate)
    {
        if (_s == null) return;
        if (_s.Db.Exports.Count == 0 && _s.Db.Entries.Count == 0) return;
        OpenList("exports", "Exports", new[] { ("Name", 320.0), ("Address", 160.0), ("Ordinal", -1.0) }, () =>
        {
            var db = _s!.Db;
            var rows = db.Exports.Select(e => new Row
            {
                Ea = e.Ea,
                C = new[] { e.Name + (e.Forwarder != null ? " -> " + e.Forwarder : ""), db.AddrStr(e.Ea), e.Ordinal.ToString() },
            }).ToList();
            foreach (var en in db.Entries.Where(x => x.Ordinal == 0))
                if (!rows.Any(r => r.Ea == en.Ea))
                    rows.Add(new Row { Ea = en.Ea, C = new[] { db.NameAt(en.Ea) ?? en.Name, db.AddrStr(en.Ea), "[main entry]" } });
            return rows;
        }, activate);
    }

    private void ShowFindings()
    {
        if (_s == null) return;
        _result ??= _s.ToResult();
        OpenList("findings", "Bulgular", new[] { ("Önem", 70.0), ("Kategori", 90.0), ("Bulgu", 230.0), ("Ayrıntı", -1.0) }, () =>
        {
            _result ??= _s!.ToResult();
            return _result.Findings.Select(f => new Row
            {
                Ea = 0,
                Tag = f,
                Fg = UI.Theme.B(f.Severity switch
                {
                    "Yuksek" => System.Windows.Media.Color.FromRgb(0xE0, 0x3A, 0x3A),
                    "Orta" => System.Windows.Media.Color.FromRgb(0xD0, 0x8A, 0x10),
                    _ => System.Windows.Media.Color.FromRgb(0x3A, 0x7B, 0xD5),
                }),
                C = new[] { f.Severity, f.Category, f.Title, f.Detail },
            }).ToList();
        }, true, r => Dialogs.Info(this, r.C[2], $"[{r.C[0]} / {r.C[1]}]\n\n{r.C[3]}"),
            r => r == null ? null : new ContextMenu { Items = { FunctionsPane.Mi("Kopyala", () => Copy($"[{r.C[0]}] {r.C[2]}: {r.C[3]}")) } });
    }

    // ================= Chooser'lar =================

    private void ChooseFunction()
    {
        if (_s == null) return;
        var db = _s.Db;
        var rows = db.Funcs.Values.Where(f => f.Chunks.Count > 0).OrderBy(f => f.Start).Select(f => new Row
        {
            Ea = f.Start,
            C = new[] { db.FuncName(f), db.SegOf(f.Start)?.Name ?? "", db.AddrStr(f.Start), (f.End - f.Start).ToString("X8") },
        }).ToList();
        var cur = db.FuncAt(Here());
        var r = Dialogs.Choose(this, "Atlanacak fonksiyonu seç", new[] { ("Function name", 300.0), ("Segment", 70.0), ("Start", 150.0), ("Length", -1.0) },
            rows, cur?.Start);
        if (r != null) Jump(r.Ea);
    }

    private void ChooseEntry()
    {
        if (_s == null) return;
        var db = _s.Db;
        var rows = db.Entries.DistinctBy(e => e.Ea).Select(e => new Row
        {
            Ea = e.Ea,
            C = new[] { db.NameAt(e.Ea) ?? e.Name, db.AddrStr(e.Ea), e.Ordinal > 0 ? e.Ordinal.ToString() : "" },
        }).ToList();
        var r = Dialogs.Choose(this, "Giriş noktası seç", new[] { ("Name", 320.0), ("Address", 160.0), ("Ordinal", -1.0) }, rows);
        if (r != null) Jump(r.Ea);
    }

    private void ChooseName()
    {
        if (_s == null) return;
        var r = Dialogs.Choose(this, "İsim seç", new[] { ("T", 24.0), ("Name", 320.0), ("Address", 220.0), ("Public", -1.0) }, NameRows());
        if (r != null) Jump(r.Ea);
    }

    private void ChooseSegment()
    {
        if (_s == null) return;
        var db = _s.Db;
        var rows = db.Segs.Select(s => new Row { Ea = s.Start, C = new[] { s.Name, db.AddrStr(s.Start), db.AddrStr(s.End), s.Class } }).ToList();
        var r = Dialogs.Choose(this, "Segment seç", new[] { ("Name", 100.0), ("Start", 160.0), ("End", 160.0), ("Class", -1.0) }, rows,
            null, 560, 320);
        if (r != null) Jump(r.Ea);
    }

    private void JumpDialog()
    {
        if (_s == null) return;
        string init = _jumpHist.FirstOrDefault() ?? Db.Hx(Here());
        var t = Dialogs.Input(this, "Adrese atla", "Adres veya isim (örnek: 140001000, sub_401000, start+10):", init, false, _jumpHist);
        if (string.IsNullOrWhiteSpace(t)) return;
        t = t.Trim();
        ulong? ea = _s.Db.Resolve(t);
        if (ea == null)
        {
            try { if (EvalIdc(t) is ulong v) ea = v; } catch { }
        }
        if (ea is not ulong e || !_s.Db.IsMapped(e))
        {
            _out.Log($"'{t}' çözülemedi ya da haritalanmamış.");
            System.Media.SystemSounds.Beep.Play();
            return;
        }
        _jumpHist.Remove(t);
        _jumpHist.Insert(0, t);
        if (_jumpHist.Count > 30) _jumpHist.RemoveAt(_jumpHist.Count - 1);
        Jump(e);
    }

    private void NextFunc(bool down)
    {
        if (_s == null) return;
        ulong ea = Here();
        var fs = _s.Db.Funcs.Keys.OrderBy(x => x).ToList();
        ulong? t = down ? fs.FirstOrDefault(x => x > ea) : fs.LastOrDefault(x => x < (_s.Db.FuncAt(ea)?.Start ?? ea));
        if (t is ulong v && v != 0) Jump(v);
    }

    private void MarkPosition()
    {
        if (_s == null) return;
        ulong ea = Here();
        var d = Dialogs.Input(this, "Konumu işaretle", "İşaret açıklaması:", _s.Db.LocStr(ea));
        if (d == null) return;
        _s.Db.Marks.RemoveAll(m => m.Ea == ea);
        _s.Db.Marks.Add(new Bookmark { Ea = ea, Text = d });
        _s.Db.Dirty = true;
        UpdateTitle();
    }

    private void JumpMark()
    {
        if (_s == null) return;
        if (_s.Db.Marks.Count == 0) { _out.Log("İşaretli konum yok (Alt+M ile ekle)."); return; }
        var rows = _s.Db.Marks.Select(m => new Row { Ea = m.Ea, C = new[] { _s.Db.AddrStr(m.Ea), m.Text } }).ToList();
        var r = Dialogs.Choose(this, "İşaretli konum seç", new[] { ("Address", 160.0), ("Description", -1.0) }, rows, null, 560, 340);
        if (r != null) Jump(r.Ea);
    }

    // ================= Sag tik menuleri =================

    private void ShowViewMenu(FrameworkElement view, Point p)
    {
        if (_s == null) return;
        var m = new ContextMenu();
        var w = Word();
        if (w != null && WordEa(w) is ulong t)
        {
            m.Items.Add(FunctionsPane.Mi($"'{w}' konumuna atla\tEnter", () => Jump(t)));
            m.Items.Add(FunctionsPane.Mi($"'{w}' xref'leri\tX", () => ShowXrefs(t)));
            m.Items.Add(new Separator());
        }
        m.Items.Add(FunctionsPane.Mi("Yeniden adlandır\tN", Rename));
        m.Items.Add(FunctionsPane.Mi("Yorum\t;", () => Comment(false)));
        m.Items.Add(FunctionsPane.Mi("Tekrarlanan yorum\t:", () => Comment(true)));
        m.Items.Add(new Separator());
        m.Items.Add(FunctionsPane.Mi("Kod\tC", () => DoOp("C")));
        m.Items.Add(FunctionsPane.Mi("Veri\tD", () => DoOp("D")));
        m.Items.Add(FunctionsPane.Mi("String\tA", () => DoOp("A")));
        m.Items.Add(FunctionsPane.Mi("Tanımsız\tU", () => DoOp("U")));
        m.Items.Add(FunctionsPane.Mi("Offset\tO", () => DoOp("O")));
        m.Items.Add(FunctionsPane.Mi("Onaltılık / ondalık\tH", ToggleRadix));
        m.Items.Add(new Separator());
        var f = _s.Db.FuncAt(Here());
        if (f == null) m.Items.Add(FunctionsPane.Mi("Fonksiyon oluştur\tP", () => DoOp("P")));
        else m.Items.Add(FunctionsPane.Mi("Fonksiyonu sil", () => DoOp("DF")));
        m.Items.Add(new Separator());
        m.Items.Add(FunctionsPane.Mi(_graphMode ? "Metin görünümü\tSpace" : "Graph görünümü\tSpace", () => SetGraph(!_graphMode)));
        m.Items.Add(FunctionsPane.Mi("Pseudocode\tF5", () => ShowPseudo(null)));
        if (_graphMode)
        {
            m.Items.Add(FunctionsPane.Mi("Pencereye sığdır\tW", () => _gv.FitAll()));
            m.Items.Add(FunctionsPane.Mi("%100\t1", () => _gv.ZoomTo(1)));
        }
        m.Items.Add(new Separator());
        m.Items.Add(FunctionsPane.Mi("Kopyala\tCtrl+C", CopySelection));
        m.PlacementTarget = view;
        m.IsOpen = true;
    }

    private void ShowHexMenu(Point p)
    {
        if (_s == null) return;
        var m = new ContextMenu();
        m.Items.Add(FunctionsPane.Mi(_hv.EditMode ? "Düzenlemeyi bitir\tF2" : "Düzenle\tF2", () =>
        {
            _hv.Focus();
            _hv.ToggleEdit();
        }));
        m.Items.Add(FunctionsPane.Mi("IDA View'da göster", () => Jump(_s.Db.HeadOf(_hv.CursorEa))));
        m.Items.Add(FunctionsPane.Mi("Satırı kopyala", () => Copy(_hv.SelectedText())));
        m.PlacementTarget = _hv;
        m.IsOpen = true;
    }

    private void ShowPseudoMenu(Point p)
    {
        if (_s == null) return;
        var m = new ContextMenu();
        var w = _pv.WordAtCursor();
        if (w != null && WordEa(w) is ulong t) m.Items.Add(FunctionsPane.Mi($"'{w}' konumuna atla", () => Jump(t)));
        m.Items.Add(FunctionsPane.Mi("Disassembly'ye dön\tTab", () => { if (_pv.CurrentEa != 0) Jump(_pv.CurrentEa); }));
        m.Items.Add(FunctionsPane.Mi("Yenile", () => ShowPseudo(_pseudoFunc?.Start)));
        m.Items.Add(FunctionsPane.Mi("AI ile decompile", AiDecompile));
        m.Items.Add(new Separator());
        m.Items.Add(FunctionsPane.Mi("Kopyala\tCtrl+C", () => Copy(_pv.SelectedText())));
        m.PlacementTarget = _pv;
        m.IsOpen = true;
    }
}
