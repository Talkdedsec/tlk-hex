using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Iced.Intel;
using tlk_hex.Core;
using tlk_hex.UI;

namespace tlk_hex;

public partial class MainWindow
{
    private Function? _pseudoFunc;
    private bool _searchUp;
    private Dialogs.TextSearch? _lastText;
    private Dialogs.TextSearch? _lastBin;
    private CancellationTokenSource? _searchCts;

    // ================= Klavye =================

    protected override void OnPreviewMouseDown(MouseButtonEventArgs e)
    {
        HidePreview();
        if (e.ChangedButton == MouseButton.XButton1) { Back(); e.Handled = true; return; }
        if (e.ChangedButton == MouseButton.XButton2) { Forward(); e.Handled = true; return; }
        base.OnPreviewMouseDown(e);
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        HidePreview();
        base.OnPreviewKeyDown(e);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.Handled) return;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        var mods = Keyboard.Modifiers;
        var fe = Keyboard.FocusedElement;
        bool inText = fe is TextBox or PasswordBox || fe is ComboBox { IsEditable: true };
        bool inList = fe is DataGridCell or DataGrid or DataGridRow or TreeViewItem or TreeView or ListBoxItem;
        if (HandleKey(key, mods, inText, inList)) e.Handled = true;
    }

    private bool HandleKey(Key key, ModifierKeys mods, bool inText, bool inList)
    {
        bool ctrl = mods == ModifierKeys.Control;
        bool alt = mods == ModifierKeys.Alt;
        bool shift = mods == ModifierKeys.Shift;
        bool none = mods == ModifierKeys.None;

        // her yerde gecerli
        if (ctrl && key == Key.O) { OpenDialog(); return true; }
        if (none && key == Key.F1) { ShowGuide(); return true; }
        if (alt && key == Key.X) { Close(); return true; }
        if (_s == null || _busy) return false;
        if (ctrl && key == Key.W) { SaveDb(); return true; }
        if (shift && key == Key.F12) { ShowStrings(); return true; }
        if (shift && key == Key.F3) { ShowAnch(_funcAnch); _fp.List.Grid.Focus(); return true; }
        if (shift && key == Key.F4) { ShowNames(); return true; }
        if (shift && key == Key.F7) { ShowSegments(); return true; }
        if (alt && key == Key.F10) { ExportListing(false); return true; }
        if (ctrl && key == Key.F && !inList && !inText) { _go.FocusBox(); return true; }
        if (mods == (ModifierKeys.Control | ModifierKeys.Shift) && key == Key.F) { ShowSearch(inText ? null : Word()); return true; }
        if (inText) return false;

        if (ctrl)
        {
            switch (key)
            {
                case Key.P: ChooseFunction(); return true;
                case Key.E: ChooseEntry(); return true;
                case Key.L: ChooseName(); return true;
                case Key.S: ChooseSegment(); return true;
                case Key.M: JumpMark(); return true;
                case Key.T: SearchText(true); return true;
                case Key.B: SearchBinary(true); return true;
                case Key.D: NextKind("data"); return true;
                case Key.U: NextKind("unk"); return true;
                case Key.X: XrefsFrom(); return true;
                case Key.Enter: Forward(); return true;
                case Key.Down: NextFunc(true); return true;
                case Key.Up: NextFunc(false); return true;
                case Key.C: CopySelection(); return true;
                case Key.OemPlus:
                case Key.Add: _cfg.FontSize = Math.Min(30, _cfg.FontSize + 1); _cfg.Save(); ApplyViewSettings(); return true;
                case Key.OemMinus:
                case Key.Subtract: _cfg.FontSize = Math.Max(8, _cfg.FontSize - 1); _cfg.Save(); ApplyViewSettings(); return true;
            }
            return false;
        }
        if (alt)
        {
            switch (key)
            {
                case Key.T: SearchText(false); return true;
                case Key.B: SearchBinary(false); return true;
                case Key.I: SearchImmediate(); return true;
                case Key.C: NextKind("code"); return true;
                case Key.M: MarkPosition(); return true;
            }
            return false;
        }
        if (shift && key == Key.OemQuestion) { Calculator(); return true; }
        if (shift && key == Key.OemSemicolon) { Comment(true); return true; }
        if (shift && key == Key.D8) { return false; }

        if (!none) return false;

        // listelerde: G ve Esc gibi genel tuslar; N/X secili satira
        if (inList)
        {
            ulong? sel = SelectedListEa();
            switch (key)
            {
                case Key.G: JumpDialog(); return true;
                case Key.N when sel is ulong a1: RenameAt(a1); return true;
                case Key.X when sel is ulong a2: ShowXrefs(a2); return true;
                case Key.Escape: FocusIda(); return true;
            }
            return false;
        }

        if (_pv.IsKeyboardFocusWithin)
        {
            switch (key)
            {
                case Key.Tab:
                case Key.F5:
                    if (_pv.CurrentEa != 0) Jump(_pv.CurrentEa); else FocusIda();
                    return true;
                case Key.Enter: FollowUnderCursor(); return true;
                case Key.Escape: FocusIda(); return true;
                case Key.N:
                {
                    var w = _pv.WordAtCursor();
                    if (w != null && WordEa(w) is ulong t) { RenameAt(t); ShowPseudo(_pseudoFunc?.Start); }
                    return true;
                }
                case Key.G: JumpDialog(); return true;
                case Key.X:
                {
                    var w = _pv.WordAtCursor();
                    if (w != null && WordEa(w) is ulong t) ShowXrefs(t);
                    return true;
                }
            }
            return false;
        }

        if (_hv.IsKeyboardFocusWithin && _hv.EditMode) return false;

        switch (key)
        {
            case Key.G: JumpDialog(); return true;
            case Key.Escape: Back(); return true;
            case Key.Enter: FollowUnderCursor(); return true;
            case Key.Space: SetGraph(!_graphMode); return true;
            case Key.F5:
            case Key.Tab: ShowPseudo(null); return true;
            case Key.N: Rename(); return true;
            case Key.OemSemicolon: Comment(false); return true;
            case Key.X: XrefsTo(); return true;
            case Key.C: DoOp("C"); return true;
            case Key.D: DoOp("D"); return true;
            case Key.U: DoOp("U"); return true;
            case Key.A: DoOp("A"); return true;
            case Key.P: DoOp("P"); return true;
            case Key.O: DoOp("O"); return true;
            case Key.H: ToggleRadix(); return true;
            case Key.W when _graphMode: _gv.FitAll(); return true;
        }
        return false;
    }

    private ulong? SelectedListEa()
    {
        if (_fp.IsKeyboardFocusWithin)
        {
            if (_fp.FolderMode) return _fp.Tree.SelectedItem is TNode { IsFolder: false } n ? n.Ea : null;
            return _fp.List.Selected?.Ea;
        }
        foreach (var kv in _lists)
            if (kv.Value.Pane.IsKeyboardFocusWithin) return kv.Value.Pane.Selected is { Ea: > 0 } r ? r.Ea : null;
        return null;
    }

    // ================= Duzenleme =================

    private void AfterEdit(ulong keep)
    {
        if (_s == null) return;
        _s.Db.Dirty = true;
        _s.Rebuild();
        _result = null;
        _dv.Refresh();
        _gv.MarkDirty();
        _hv.Refresh();
        Nav.Recompute();
        _fp.Reload();
        RefreshLists();
        _ct.SetSession(_s);
        if (_graphMode)
        {
            var f = _s.Db.FuncAt(keep);
            if (f != null) { _gv.Show(_s, f, keep); OnViewCursor(keep); }
            else SetGraph(false, keep);
        }
        else _dv.JumpTo(keep, false);
        BuildGoItems();
        UpdateTitle();
    }

    private void DoOp(string op)
    {
        if (_s == null) return;
        var au = _s.Au;
        ulong ea = HereHead();

        // metin gorunumunde secim varsa U/C araliga uygulanir
        if (!_graphMode && _dv.Selection is var (a, b) && op is "U" or "C" && b > a)
        {
            ulong first = _s.List.EaOfLine(a), last = _s.List.EaOfLine(b);
            int n = 0;
            for (ulong x = first; x <= last && n < 100000;)
            {
                ulong next = _s.Db.NextHead(x);
                bool ok = op == "U" ? au.Undefine(x) : au.MakeCode(x);
                if (ok) { au.Record(op, x); n++; }
                x = op == "C" && _s.Db.IsCode(x) ? _s.Db.NextHead(x) : next;
            }
            _out.Log(Loc.F("{0} öğe {1}.", n, Loc.T(op == "U" ? "tanimsiz yapildi" : "koda donusturuldu")));
            _dv.SelAnchor = -1;
            AfterEdit(first);
            return;
        }

        bool done;
        int arg = 0;
        switch (op)
        {
            case "D":
            {
                var k = _s.Db.IsHead(ea) ? _s.Db.KindAt(ea) : ItemKind.Unknown;
                var nk = k is ItemKind.Byte or ItemKind.Word or ItemKind.Dword ? AutoAnalysis.NextDataKind(k) : k == ItemKind.Qword ? ItemKind.Byte : ItemKind.Byte;
                arg = (int)nk;
                done = au.MakeData(ea, nk);
                break;
            }
            case "A":
            {
                bool wide = _s.Db.TryByte(ea + 1, out var b1) && b1 == 0 && _s.Db.TryByte(ea, out var b0) && b0 != 0;
                arg = wide ? 1 : 0;
                done = au.MakeString(ea, wide);
                break;
            }
            case "P": done = au.CreateFunction(Here()); ea = Here(); break;
            case "DF":
            {
                var f = _s.Db.FuncAt(ea);
                if (f == null) { done = false; break; }
                if (!Dialogs.Confirm(this, "Fonksiyonu sil", Loc.F("'{0}' fonksiyonu silinsin mi? (kod korunur)", _s.Db.FuncName(f)))) return;
                done = au.DeleteFunction(ea);
                break;
            }
            case "C": done = au.MakeCode(ea); break;
            case "U": done = au.Undefine(ea); break;
            case "O": done = au.ToggleOffset(ea); break;
            default: return;
        }
        if (!done)
        {
            System.Media.SystemSounds.Beep.Play();
            SetStatus(Loc.F("'{0}' komutu {1} adresinde uygulanamadı.", op, _s.Db.AddrStr(ea)));
            return;
        }
        au.Record(op, ea, arg);
        AfterEdit(ea);
    }

    private void ToggleRadix()
    {
        if (_s == null) return;
        ulong ea = HereHead();
        if (!_s.Db.IsCode(ea)) return;
        if (!_s.Db.DecimalOps.Remove(ea)) _s.Db.DecimalOps.Add(ea);
        _s.Db.Dirty = true;
        _dv.Refresh();
        _gv.MarkDirty();
        if (_graphMode && _s.Db.FuncAt(ea) is Function f) _gv.Show(_s, f, ea);
        UpdateTitle();
    }

    private void Rename()
    {
        if (_s == null) return;
        var w = Word();
        ulong here = HereHead();
        var f = _s.Db.FuncAt(here);
        if (w != null && f != null && TryStackVar(f, w, out int l))
        {
            var nn = Dialogs.Input(this, "Yığın değişkenini yeniden adlandır", $"{w} ({_s.Db.FuncName(f)}):", w);
            if (nn == null) return;
            nn = nn.Trim();
            if (nn.Length == 0 || nn == w) _s.Db.StackNames.Remove((f.Start, l));
            else if (!_s.Db.IsValidName(nn)) { _out.Log("Geçersiz isim."); return; }
            else _s.Db.StackNames[(f.Start, l)] = nn;
            AfterEdit(Here());
            return;
        }
        ulong target = here;
        if (w != null && WordEa(w) is ulong t && t != here) target = t;
        RenameAt(target);
    }

    private void RenameAt(ulong target)
    {
        if (_s == null) return;
        string cur = _s.Db.NameAt(target) ?? "";
        var name = Dialogs.Input(this, "Adresi yeniden adlandır",
            Loc.F("Adres: {0}:{1}\nIsim (boş = otomatik isim):", _s.Db.SegOf(target)?.Name ?? "", _s.Db.AddrStr(target)), cur);
        if (name == null) return;
        var err = _s.Db.SetUserName(target, name);
        if (err != null) { Dialogs.Info(this, "Hata", err); return; }
        AfterEdit(Here());
    }

    private void Comment(bool repeatable)
    {
        if (_s == null) return;
        ulong ea = HereHead();
        var dict = repeatable ? _s.Db.RepComments : _s.Db.Comments;
        dict.TryGetValue(ea, out var cur);
        var t = Dialogs.Input(this, repeatable ? "Tekrarlanan yorum" : "Yorum",
            Loc.F("{0}:{1} için yorum:", _s.Db.SegOf(ea)?.Name ?? "", _s.Db.AddrStr(ea)), cur ?? "", true);
        if (t == null) return;
        t = t.TrimEnd();
        if (t.Length == 0) dict.Remove(ea); else dict[ea] = t;
        AfterEdit(Here());
    }

    private void PatchBytesDialog()
    {
        if (_s == null) return;
        ulong ea = HereHead();
        var sb = new StringBuilder();
        for (int i = 0; i < 16; i++)
            if (_s.Db.TryByte(ea + (ulong)i, out var b)) sb.Append(b.ToString("X2")).Append(' ');
        var t = Dialogs.Input(this, "Baytları yamala", Loc.F("Adres {0} - yeni baytlar (hex):", _s.Db.AddrStr(ea)), sb.ToString().Trim());
        if (t == null) return;
        var parts = t.Split(new[] { ' ', ',', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        int n = 0;
        foreach (var p in parts)
        {
            if (!byte.TryParse(p, NumberStyles.HexNumber, null, out var v)) { _out.Log(Loc.F("Geçersiz bayt: {0}", p)); return; }
            _s.Db.PatchByte(ea + (ulong)n++, v);
        }
        Reanalyze(ea);
        _out.Log(Loc.F("{0} bayt yamalandı @ {1}", n, _s.Db.AddrStr(ea)));
    }

    private void OnBytePatched(ulong ea)
    {
        if (_s == null) return;
        Reanalyze(_s.Db.HeadOf(ea));
        _hv.Focus();
    }

    // Yama sonrasi ogeyi yeniden coz
    private void Reanalyze(ulong ea)
    {
        if (_s == null) return;
        ulong head = _s.Db.HeadOf(ea);
        bool wasCode = _s.Db.IsCode(head);
        if (wasCode)
        {
            _s.Au.Undefine(head);
            _s.Au.MakeCode(head);
        }
        AfterEdit(head);
    }

    private void ListPatches()
    {
        if (_s == null) return;
        var db = _s.Db;
        OpenList("patches", "Yamalı baytlar", new[] { ("Address", 170.0), ("Offset", 90.0), ("Orijinal", 70.0), ("Yeni", 70.0) },
            () => db.Patches.OrderBy(k => k.Key).Select(kv => new Row
            {
                Ea = kv.Key,
                C = new[]
                {
                    db.SegOf(kv.Key)?.Name + ":" + db.AddrStr(kv.Key), db.FileOffsetOf(kv.Key).ToString("X8"),
                    kv.Value.ToString("X2"), db.TryByte(kv.Key, out var nb) ? nb.ToString("X2") : "??",
                },
            }).ToList());
    }

    // ================= Xref =================

    private void XrefsTo()
    {
        if (_s == null) return;
        var w = Word();
        ulong here = HereHead();
        var f = _s.Db.FuncAt(here);
        if (w != null && f != null && TryStackVar(f, w, out int l)) { StackXrefs(f, l, w); return; }
        ulong target = w != null && WordEa(w) is ulong t ? t : here;
        ShowXrefs(target);
    }

    private string InsnText(ulong ea)
    {
        var line = _s!.List.GetLine(_s.List.LineOfEa(ea, false));
        string p = line.Plain;
        return (line.BodyCol < p.Length ? p[line.BodyCol..] : p).Trim();
    }

    private void ShowXrefs(ulong target)
    {
        if (_s == null) return;
        var xs = _s.Db.XrefsTo(target).OrderBy(x => x.From).ToList();
        string name = _s.Db.RefName(target) ?? _s.Db.AddrStr(target);
        if (xs.Count == 0)
        {
            SetStatus(Loc.F("{0}: xref yok.", name));
            _out.Log(Loc.F("{0} için xref bulunamadı.", name));
            return;
        }
        var rows = xs.Select(x => new Row
        {
            Ea = x.From,
            C = new[] { x.From < target ? "Up" : "Down", ((char)x.Type).ToString(), _s.Db.LocStr(x.From), InsnText(x.From) },
        }).ToList();
        var r = Dialogs.Choose(this, Loc.F("{0} adresine xref'ler", name), new[] { ("Direction", 70.0), ("Type", 45.0), ("Address", 230.0), ("Text", -1.0) },
            rows, null, 860, 420);
        if (r != null) Jump(r.Ea);
    }

    private void XrefsFrom()
    {
        if (_s == null) return;
        ulong ea = HereHead();
        var xs = _s.Db.XrefsFrom(ea).ToList();
        if (xs.Count == 0) { SetStatus("Bu öğeden çıkan xref yok."); return; }
        var rows = xs.Select(x => new Row
        {
            Ea = x.To,
            C = new[] { ((char)x.Type).ToString(), _s.Db.RefName(x.To) ?? _s.Db.AddrStr(x.To), _s.Db.AddrStr(x.To) },
        }).ToList();
        var r = Dialogs.Choose(this, Loc.F("{0} adresinden xref'ler", _s.Db.AddrStr(ea)), new[] { ("Type", 45.0), ("Target", 300.0), ("Address", -1.0) },
            rows, null, 640, 360);
        if (r != null) Jump(r.Ea);
    }

    private void StackXrefs(Function f, int l, string name)
    {
        var rows = new List<Row>();
        foreach (var ea in f.Instrs)
        {
            if (!_s!.Dis.TryDecode(ea, out var ins)) continue;
            for (int i = 0; i < ins.OpCount; i++)
            {
                if (ins.GetOpKind(i) != OpKind.Memory) continue;
                long disp = _s.Db.Bitness == 64 ? (long)ins.MemoryDisplacement64 : (int)ins.MemoryDisplacement32;
                int delta;
                if (Disasm.IsStackReg(ins.MemoryBase)) { if (!f.SpAt.TryGetValue(ea, out delta)) continue; }
                else if (Disasm.IsFrameReg(ins.MemoryBase) && f.BpBased && f.BpDelta != int.MinValue) delta = f.BpDelta;
                else continue;
                if ((int)(delta + disp) != l) continue;
                string t = ins.Mnemonic == Mnemonic.Lea ? "o" : i == 0 ? "w" : "r";
                rows.Add(new Row { Ea = ea, C = new[] { t, _s.Db.LocStr(ea), InsnText(ea) } });
            }
        }
        if (rows.Count == 0) { SetStatus(Loc.F("{0}: referans yok.", name)); return; }
        var r = Dialogs.Choose(this, Loc.F("Yığın değişkeni {0} xref'leri", name), new[] { ("Type", 45.0), ("Address", 230.0), ("Text", -1.0) },
            rows, null, 760, 380);
        if (r != null) Jump(r.Ea);
    }

    // ================= Arama =================

    private void BeginSearch(string what)
    {
        _searchCts?.Cancel();
        _searchCts = new CancellationTokenSource();
        SetAu(true, "AU:  aranıyor");
        SetStatus(Loc.F("{0} aranıyor... (Esc ile iptal)", what));
        Mouse.OverrideCursor = Cursors.AppStarting;
        PreviewKeyDown += CancelSearchKey;
    }

    private void EndSearch()
    {
        PreviewKeyDown -= CancelSearchKey;
        Mouse.OverrideCursor = null;
        SetAu(false);
    }

    private void CancelSearchKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape) { _searchCts?.Cancel(); e.Handled = true; }
    }

    private async void SearchText(bool next)
    {
        if (_s == null) return;
        var q = _lastText;
        if (!next || q == null)
        {
            q = Dialogs.SearchText(this, _lastText?.Text ?? Word() ?? "", false);
            if (q == null || q.Text.Length == 0) return;
            _lastText = q;
            _searchUp = q.Up;
            DirText.Text = _searchUp ? "Up" : "Down";
        }
        var worker = _s.List.CloneForWorker();
        long start = _graphMode ? _s.List.LineOfEa(Here(), false) : _dv.Cursor;
        bool up = next ? _searchUp : q.Up;
        BeginSearch($"'{q.Text}'");
        var ct = _searchCts!.Token;
        try
        {
            if (q.All)
            {
                var hits = await Task.Run(() =>
                {
                    var res = new List<(ulong ea, string text)>();
                    Regex? rx = q.Regex ? new Regex(q.Text, q.MatchCase ? RegexOptions.None : RegexOptions.IgnoreCase) : null;
                    var cmp = q.MatchCase ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
                    for (long l = 0; l < worker.TotalLines && res.Count < 10000; l++)
                    {
                        if ((l & 0xFFF) == 0 && ct.IsCancellationRequested) break;
                        var ln = worker.GetLine(l);
                        string p = ln.Plain;
                        if (rx != null ? rx.IsMatch(p) : p.Contains(q.Text, cmp))
                            res.Add((ln.Ea, (ln.BodyCol < p.Length ? p[ln.BodyCol..] : p).Trim()));
                    }
                    return res;
                }, ct);
                ShowOccurrences($"Metin: {q.Text}", hits);
            }
            else
            {
                long from = up ? start - 1 : start + 1;
                long hit = await Task.Run(() => worker.FindText(q.Text, from, !up, q.MatchCase, q.Regex, ct), ct);
                if (hit < 0) { SetStatus(Loc.F("'{0}' bulunamadı.", q.Text)); System.Media.SystemSounds.Beep.Play(); }
                else
                {
                    ulong ea = _s.List.EaOfLine(hit);
                    if (_graphMode && _s.Db.FuncAt(ea) == null) SetGraph(false, ea);
                    if (_graphMode) Jump(ea);
                    else
                    {
                        _back.Add(Here());
                        _dv.SetCursor(hit, -1, false, true);
                        _dv.HighlightWord = q.Regex ? null : q.Text;
                        _dv.Focus();
                    }
                    SetStatus(Loc.F("'{0}' bulundu: {1}", q.Text, _s.Db.AddrStr(ea)));
                }
            }
        }
        catch (OperationCanceledException) { SetStatus("Arama iptal edildi."); }
        catch (Exception ex) { _out.Log(Loc.T("Arama hatası: ") + ex.Message); }
        finally { EndSearch(); }
    }

    private static (byte[] pat, bool[] mask)? ParsePattern(string s)
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
            if (Uri.IsHexDigit(c))
            {
                bytes.Add(Convert.ToByte(c.ToString(), 16));
                mask.Add(true);
                i++;
                continue;
            }
            return null;
        }
        return bytes.Count == 0 ? null : (bytes.ToArray(), mask.ToArray());
    }

    private async void SearchBinary(bool next)
    {
        if (_s == null) return;
        var q = _lastBin;
        if (!next || q == null)
        {
            q = Dialogs.SearchText(this, _lastBin?.Text ?? "", true);
            if (q == null || q.Text.Length == 0) return;
            _lastBin = q;
        }
        var pp = ParsePattern(q.Text);
        if (pp == null) { _out.Log(Loc.T("Geçersiz bayt dizisi: ") + q.Text); return; }
        var (pat, mask) = pp.Value;
        var db = _s.Db;
        ulong here = Here();
        bool up = q.Up;
        BeginSearch(Loc.T("Bayt dizisi"));
        var ct = _searchCts!.Token;
        try
        {
            var hits = await Task.Run(() =>
            {
                var res = new List<ulong>();
                var segs = up ? db.Segs.AsEnumerable().Reverse() : db.Segs;
                foreach (var s in segs)
                {
                    long n = s.InitSize - pat.Length;
                    long o0 = up ? n : 0, step = up ? -1 : 1;
                    for (long o = o0; o >= 0 && o <= n; o += step)
                    {
                        if ((o & 0xFFFF) == 0 && ct.IsCancellationRequested) return res;
                        ulong ea = s.Start + (ulong)o;
                        if (!q.All && (up ? ea >= here : ea <= here)) continue;
                        bool ok = true;
                        for (int k = 0; k < pat.Length; k++)
                            if (mask[k] && s.Data[o + k] != pat[k]) { ok = false; break; }
                        if (!ok) continue;
                        res.Add(ea);
                        if (!q.All || res.Count >= 10000) return res;
                    }
                }
                return res;
            }, ct);
            if (q.All) ShowOccurrences("Bayt: " + q.Text, hits.Select(e => (e, "")).ToList());
            else if (hits.Count == 0) { SetStatus("Bayt dizisi bulunamadı."); System.Media.SystemSounds.Beep.Play(); }
            else { Jump(db.HeadOf(hits[0])); SetStatus(Loc.F("Bulundu: {0}", db.AddrStr(hits[0]))); }
        }
        catch (OperationCanceledException) { SetStatus("Arama iptal edildi."); }
        finally { EndSearch(); }
    }

    private async void SearchImmediate()
    {
        if (_s == null) return;
        var t = Dialogs.Input(this, "Sabit değer ara", "Değer (örnek: 0x1F, 31, 1Fh):", "");
        if (string.IsNullOrWhiteSpace(t)) return;
        ulong? v = t.Trim().EndsWith('h') || t.Trim().StartsWith("0x") ? Db.ParseNum(t) : ulong.TryParse(t.Trim(), out var dv) ? dv : Db.ParseNum(t);
        if (v is not ulong val) { _out.Log("Geçersiz değer."); return; }
        var db = _s.Db;
        var dis = new Disasm(db);
        BeginSearch(Loc.T("Sabit değer"));
        var ct = _searchCts!.Token;
        try
        {
            var hits = await Task.Run(() =>
            {
                var res = new List<ulong>();
                foreach (var s in db.Segs)
                {
                    if (!s.X) continue;
                    for (long o = 0; o < s.InitSize;)
                    {
                        if ((o & 0xFFFF) == 0 && ct.IsCancellationRequested) return res;
                        if ((s.F[o] & FF.Head) != 0 && (s.F[o] & FF.KindMask) == (byte)ItemKind.Code)
                        {
                            ulong ea = s.Start + (ulong)o;
                            if (dis.TryDecode(ea, out var ins))
                            {
                                bool hit = false;
                                for (int i = 0; i < ins.OpCount && !hit; i++)
                                {
                                    var k = ins.GetOpKind(i);
                                    if (k.ToString().StartsWith("Immediate") && (ins.GetImmediate(i) == val || (ulong)(long)(int)ins.GetImmediate(i) == val)) hit = true;
                                    if (k == OpKind.Memory && ins.MemoryDisplacement64 == val) hit = true;
                                }
                                if (hit) { res.Add(ea); if (res.Count >= 10000) return res; }
                            }
                            o += Db.ItemSize(s, o);
                        }
                        else o++;
                    }
                }
                return res;
            }, ct);
            ShowOccurrences($"Sabit: {Db.HexNum(val)}", hits.Select(e => (e, "")).ToList());
        }
        catch (OperationCanceledException) { SetStatus("Arama iptal edildi."); }
        finally { EndSearch(); }
    }

    private void ShowOccurrences(string title, List<(ulong ea, string text)> hits)
    {
        if (_s == null) return;
        if (hits.Count == 0) { SetStatus("Eşleşme yok."); System.Media.SystemSounds.Beep.Play(); return; }
        var db = _s.Db;
        var rows = hits.Select(h => new Row
        {
            Ea = h.ea,
            C = new[] { db.SegOf(h.ea)?.Name + ":" + db.AddrStr(h.ea), db.FuncAt(h.ea) is Function f ? db.FuncName(f) : "",
                h.text.Length > 0 ? h.text : InsnText(db.HeadOf(h.ea)) },
        }).ToList();
        _lists.Remove("occ");
        if (_docs.TryGetValue("occ", out var d)) d.Close();
        OpenList("occ", "Occurrences - " + title, new[] { ("Address", 180.0), ("Function", 200.0), ("Instruction", -1.0) }, () => rows);
        _out.Log(Loc.F("{0}: {1} eşleşme{2}.", title, hits.Count, hits.Count >= 10000 ? Loc.T(" (ilk 10000)") : ""));
    }

    private void NextKind(string what)
    {
        if (_s == null) return;
        var db = _s.Db;
        ulong ea = db.NextHead(HereHead());
        while (true)
        {
            var s = db.SegOf(ea);
            if (s == null)
            {
                var ns = db.Segs.FirstOrDefault(x => x.Start > ea);
                if (ns == null) { SetStatus("Bulunamadı."); System.Media.SystemSounds.Beep.Play(); return; }
                ea = ns.Start;
                continue;
            }
            var k = db.KindAt(ea);
            bool head = db.IsHead(ea) || k == ItemKind.Unknown;
            bool m = what switch
            {
                "code" => k == ItemKind.Code && head,
                "data" => head && k is not (ItemKind.Code or ItemKind.Unknown or ItemKind.Align),
                _ => k == ItemKind.Unknown && s.IsInit((long)(ea - s.Start)),
            };
            if (m) { Jump(ea); return; }
            ea = db.NextHead(ea);
        }
    }

    // ================= Pseudocode =================

    private void ShowPseudo(ulong? at)
    {
        if (_s == null) return;
        ulong ea = at ?? Here();
        var f = _s.Db.FuncAt(ea);
        if (f == null) { _out.Log("İmleç bir fonksiyon içinde değil; pseudocode üretilemez."); return; }
        try
        {
            var lines = _s.Pseudo.Decompile(f);
            _pseudoFunc = f;
            _pv.SetLines(lines);
            _pseudoTitle.Text = "  " + _s.Db.FuncName(f) + Loc.T("  (basit pseudocode - kesin değil)");
            ShowDoc("pseudo", "Pseudocode-A", _pseudoPane);
            _pv.SelectEa(Here());
            _pv.Focus();
        }
        catch (Exception ex) { _out.Log(Loc.T("Pseudocode hatası: ") + ex.Message); }
    }

    private string FunctionAsm(Function f, int maxLines)
    {
        var sb = new StringBuilder();
        int n = 0;
        foreach (var ea in f.Instrs)
        {
            foreach (var l in _s!.List.ItemLinesForGraph(ea))
            {
                sb.AppendLine(_s.Db.AddrStr(ea) + "  " + l.Plain);
                if (++n >= maxLines) { sb.AppendLine(Loc.T("... (kırpıldı)")); return sb.ToString(); }
            }
        }
        return sb.ToString();
    }

    private async void AiDecompile()
    {
        if (_s == null) return;
        var f = _pseudoFunc ?? _s.Db.FuncAt(Here());
        if (f == null) { _out.Log("Önce bir fonksiyon seç."); return; }
        if (string.IsNullOrWhiteSpace(_cfg.AiApiKey))
        {
            _out.Log("AI anahtarı tanımlı değil: Seçenekler > Genel > AI desteği.");
            return;
        }
        string asm = FunctionAsm(f, 1500);
        string fname = _s.Db.FuncName(f);
        _pseudoTitle.Text = "  " + fname + Loc.T("  (AI çalışıyor...)");
        SetAu(true, "AU:  AI");
        string q = $"Asagidaki {_s.Db.Machine} fonksiyonunu ({fname}) Hex-Rays tarzı, okunabilir C pseudocode'una çevir. " +
                   "Sadece C kodunu ver (markdown kod bloğu kullanma), kısa Turkce yorumlar ekleyebilirsin. " +
                   "Bilinmeyen tipler için __int64/int kullan, çağrılan fonksiyonların adlarını koru.\n\n" + asm;
        string ans = await AiClient.AskAsync(_cfg, $"Dosya: {System.IO.Path.GetFileName(_s.Db.FilePath)} ({_s.Db.Format})", q);
        SetAu(false);
        ans = Regex.Replace(ans, "^```[a-zA-Z]*\\s*|```\\s*$", "", RegexOptions.Multiline).Trim('\n', '\r');
        var lines = new List<Line>();
        var head = new Line { Ea = f.Start };
        head.Toks.Add(new Tok(Loc.T("// AI ile üretildi - doğrulayarak kullan"), Tk.Cmt));
        lines.Add(head);
        foreach (var raw in ans.Replace("\r", "").Split('\n')) lines.Add(CLine(raw, f.Start));
        _pseudoFunc = f;
        _pv.SetLines(lines);
        _pseudoTitle.Text = "  " + fname + "  (AI)";
        ShowDoc("pseudo", "Pseudocode-A", _pseudoPane);
    }

    private static readonly HashSet<string> CKeywords = new()
    {
        "if", "else", "while", "for", "do", "return", "goto", "switch", "case", "default", "break", "continue",
        "int", "char", "void", "unsigned", "signed", "long", "short", "const", "struct", "union", "static", "sizeof",
        "__int64", "__int32", "__int16", "__int8", "_BYTE", "_WORD", "_DWORD", "_QWORD", "bool", "double", "float",
        "__fastcall", "__cdecl", "__stdcall", "DWORD", "HANDLE", "BOOL", "LPVOID", "size_t", "uint64_t", "int64_t",
        "uint32_t", "uint8_t", "true", "false", "NULL",
    };

    // AI ciktisini basitce renklendir
    private static Line CLine(string s, ulong ea)
    {
        var l = new Line { Ea = ea };
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') { l.Toks.Add(new Tok(s[i..], Tk.Cmt)); break; }
            if (c == '"')
            {
                int j = i + 1;
                while (j < s.Length && s[j] != '"') { if (s[j] == '\\') j++; j++; }
                j = Math.Min(s.Length, j + 1);
                l.Toks.Add(new Tok(s[i..j], Tk.Str));
                i = j;
                continue;
            }
            if (char.IsDigit(c))
            {
                int j = i;
                while (j < s.Length && (char.IsLetterOrDigit(s[j]))) j++;
                l.Toks.Add(new Tok(s[i..j], Tk.Num));
                i = j;
                continue;
            }
            if (char.IsLetter(c) || c == '_')
            {
                int j = i;
                while (j < s.Length && (char.IsLetterOrDigit(s[j]) || s[j] == '_')) j++;
                string w = s[i..j];
                Tk k = CKeywords.Contains(w) ? Tk.Kw : j < s.Length && s[j] == '(' ? Tk.Name : Tk.LocalVar;
                l.Toks.Add(new Tok(w, k));
                i = j;
                continue;
            }
            l.Toks.Add(new Tok(c.ToString(), char.IsWhiteSpace(c) ? Tk.Text : Tk.Punct));
            i++;
        }
        return l;
    }

    // ================= Pano =================

    private void Copy(string text)
    {
        try
        {
            Clipboard.SetText(text);
            SetStatus("Panoya kopyalandı.");
        }
        catch { }
    }

    private void CopySelection()
    {
        if (_s == null) return;
        if (_pv.IsKeyboardFocusWithin) Copy(_pv.SelectedText());
        else if (_hv.IsKeyboardFocusWithin) Copy(_hv.SelectedText());
        else if (_graphMode)
        {
            var w = _gv.HighlightWord;
            Copy(w ?? InsnText(HereHead()));
        }
        else Copy(_dv.SelectedText());
    }

    // ================= Hesap makinesi / IDC =================

    private void Calculator()
    {
        var t = Dialogs.Input(this, "İfade hesapla", "İfade (örnek: 0x401000+20h*2, here, sub_401000):", "");
        if (string.IsNullOrWhiteSpace(t)) return;
        try
        {
            var r = EvalIdc(t);
            string res = r is ulong v ? FormatNum(v) : r?.ToString() ?? Loc.T("(boş)");
            _out.Log($"{t} = {res}");
            Dialogs.Info(this, "Sonuç", $"{t}\n\n{res}");
        }
        catch (Exception ex) { Dialogs.Info(this, "Hata", ex.Message); }
    }

    private static string FormatNum(ulong v)
    {
        var sb = new StringBuilder();
        sb.Append($"0x{v:X}   {(long)v}   ");
        if (v <= 0xFFFFFFFF) sb.Append($"0o{Convert.ToString((long)v, 8)}   ");
        var bytes = BitConverter.GetBytes(v).TakeWhile(b => b != 0).ToArray();
        if (bytes.Length > 0 && bytes.All(b => b >= 0x20 && b < 0x7F)) sb.Append('\'' + Encoding.ASCII.GetString(bytes.Reverse().ToArray()) + '\'');
        return sb.ToString();
    }

    private static string IdcHelp =>
        Loc.T("IDC komutları (Output > IDC):\n") +
        Loc.T("  here() / ScreenEA()           imlecin adresi\n") +
        Loc.T("  jumpto(ea) / Jump(ea)         adrese git\n") +
        Loc.T("  get_name(ea) / set_name(ea, \"isim\")\n") +
        Loc.T("  set_cmt(ea, \"yorum\", rep)    rep=1 tekrarlanan\n") +
        "  get_func_name(ea)  get_func_start(ea)  get_func_end(ea)\n" +
        "  byte(ea) word(ea) dword(ea) qword(ea)\n" +
        "  get_bytes(ea, n)   patch_byte(ea, v)\n" +
        "  xrefs_to(ea)  xrefs_from(ea)  functions()  segments()\n" +
        Loc.T("  get_str(ea)   msg(\"metin\")   print(x)\n") +
        Loc.T("  Düz ifade de yazabilirsin: 0x401000+0x20, sub_401000+10h ...\n") +
        Loc.T("AI modunda: dosya/fonksiyon hakkında soru sor.");

    private async void OnCommand(string mode, string text)
    {
        if (mode == "AI")
        {
            _out.Log("AI> " + text);
            if (_s == null) { _out.Log("Önce bir dosya aç."); return; }
            if (string.IsNullOrWhiteSpace(_cfg.AiApiKey)) { _out.Log("AI anahtarı tanımlı değil: Seçenekler > Genel > AI desteği."); return; }
            _result ??= _s.ToResult();
            var ctx = AiClient.BuildContext(_result);
            var f = _s.Db.FuncAt(Here());
            if (f != null) ctx += $"\n\nAKTIF FONKSIYON {_s.Db.FuncName(f)}:\n" + FunctionAsm(f, 300);
            SetAu(true, "AU:  AI");
            string ans = await AiClient.AskAsync(_cfg, ctx, text);
            SetAu(false);
            foreach (var l in ans.Replace("\r", "").Split('\n')) _out.Log("  " + l);
            return;
        }
        _out.Log(text);
        if (text.Trim() is "help" or "?" or "help()") { _out.Log(IdcHelp); return; }
        try
        {
            var r = EvalIdc(text);
            if (r is ulong v) _out.Log(FormatNum(v));
            else if (r is string s) _out.Log(s);
        }
        catch (Exception ex) { _out.Log("Hata: " + ex.Message); }
    }

    // Kucuk IDC/ifade yorumlayicisi
    private object? EvalIdc(string src)
    {
        var p = new IdcParser(src, this);
        var r = p.Expr();
        p.End();
        return r;
    }

    private sealed class IdcParser
    {
        private readonly string _s;
        private int _i;
        private readonly MainWindow _w;

        public IdcParser(string s, MainWindow w)
        {
            _s = s.Trim().TrimEnd(';');
            _w = w;
        }

        private void Ws() { while (_i < _s.Length && char.IsWhiteSpace(_s[_i])) _i++; }
        private bool Eat(string t)
        {
            Ws();
            if (string.CompareOrdinal(_s, _i, t, 0, t.Length) == 0) { _i += t.Length; return true; }
            return false;
        }
        public void End()
        {
            Ws();
            if (_i < _s.Length) throw new Exception(Loc.F("Beklenmeyen: '{0}'", _s[_i..]));
        }

        private static ulong U(object? o) => o is ulong v ? v : throw new Exception("Sayi bekleniyordu");

        public object? Expr() => Or();
        private object? Or() { var a = Xor(); while (!Peek("||") && Eat("|")) a = U(a) | U(Xor()); return a; }
        private object? Xor() { var a = And(); while (Eat("^")) a = U(a) ^ U(And()); return a; }
        private object? And() { var a = Shift(); while (!Peek("&&") && Eat("&")) a = U(a) & U(Shift()); return a; }
        private object? Shift()
        {
            var a = Add();
            while (true)
            {
                if (Eat("<<")) a = U(a) << (int)U(Add());
                else if (Eat(">>")) a = U(a) >> (int)U(Add());
                else return a;
            }
        }
        private object? Add()
        {
            var a = Mul();
            while (true)
            {
                if (Eat("+")) { var b = Mul(); a = a is string sa ? sa + (b is ulong bv ? bv.ToString("X") : b) : U(a) + U(b); }
                else if (Eat("-")) a = U(a) - U(Mul());
                else return a;
            }
        }
        private object? Mul()
        {
            var a = Unary();
            while (true)
            {
                if (Eat("*")) a = U(a) * U(Unary());
                else if (Eat("/")) { var d = U(Unary()); if (d == 0) throw new Exception(Loc.T("Sıfıra bölme")); a = U(a) / d; }
                else if (Eat("%")) { var d = U(Unary()); if (d == 0) throw new Exception(Loc.T("Sıfıra bölme")); a = U(a) % d; }
                else return a;
            }
        }
        private object? Unary()
        {
            if (Eat("-")) return (ulong)(-(long)U(Unary()));
            if (Eat("~")) return ~U(Unary());
            if (Eat("!")) return U(Unary()) == 0 ? 1UL : 0UL;
            return Primary();
        }
        private bool Peek(string t)
        {
            Ws();
            return string.CompareOrdinal(_s, _i, t, 0, t.Length) == 0;
        }
        private object? Primary()
        {
            Ws();
            if (_i >= _s.Length) throw new Exception(Loc.T("İfade eksik"));
            if (Eat("(")) { var v = Expr(); if (!Eat(")")) throw new Exception("')' bekleniyordu"); return v; }
            char c = _s[_i];
            if (c == '"')
            {
                int j = _s.IndexOf('"', _i + 1);
                if (j < 0) throw new Exception(Loc.T("Kapanmamış string"));
                var str = _s[(_i + 1)..j].Replace("\\n", "\n");
                _i = j + 1;
                return str;
            }
            int st = _i;
            while (_i < _s.Length && (char.IsLetterOrDigit(_s[_i]) || _s[_i] is '_' or '$' or '@' or '?' or '.' or ':')) _i++;
            if (_i == st) throw new Exception(Loc.F("Beklenmeyen karakter '{0}'", c));
            string id = _s[st.._i];
            if (Eat("("))
            {
                var args = new List<object?>();
                if (!Eat(")"))
                {
                    do args.Add(Expr()); while (Eat(","));
                    if (!Eat(")")) throw new Exception("')' bekleniyordu");
                }
                return _w.IdcCall(id, args);
            }
            if (char.IsDigit(id[0]))
            {
                ulong? n = id.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || id.EndsWith('h') || id.EndsWith('H')
                    ? Db.ParseNum(id)
                    : id.All(char.IsDigit) ? ulong.Parse(id) : Db.ParseNum(id);
                return n ?? throw new Exception(Loc.T("Geçersiz sayı: ") + id);
            }
            if (id is "here" or "BADADDR") return id == "here" ? _w.Here() : ulong.MaxValue;
            var ea = _w._s?.Db.Resolve(id);
            return ea ?? throw new Exception(Loc.T("Bilinmeyen isim: ") + id);
        }
    }

    private object? IdcCall(string fn, List<object?> a)
    {
        var db = _s?.Db ?? throw new Exception(Loc.T("Açık dosya yok"));
        ulong A(int i) => i < a.Count && a[i] is ulong v ? v : throw new Exception(Loc.F("{0}: {1}. argüman sayı olmalı", fn, i + 1));
        string S(int i) => i < a.Count && a[i] is string v ? v : throw new Exception(Loc.F("{0}: {1}. argüman string olmalı", fn, i + 1));
        ulong R(int n) => db.TryRead(A(0), n, out var v) ? v : throw new Exception(Loc.T("Okunamadı"));
        switch (fn.ToLowerInvariant())
        {
            case "here": case "screenea": case "get_screen_ea": return Here();
            case "jumpto": case "jump": Jump(A(0)); return null;
            case "get_name": case "name": return db.NameAt(A(0)) ?? "";
            case "set_name": case "makename":
            {
                var err = db.SetUserName(A(0), S(1));
                if (err != null) throw new Exception(err);
                AfterEdit(Here());
                return 1UL;
            }
            case "set_cmt": case "makecomm":
            {
                bool rep = a.Count > 2 && A(2) != 0;
                var d = rep ? db.RepComments : db.Comments;
                if (S(1).Length == 0) d.Remove(A(0)); else d[A(0)] = S(1);
                AfterEdit(Here());
                return 1UL;
            }
            case "get_cmt": return db.Comments.GetValueOrDefault(A(0)) ?? db.RepComments.GetValueOrDefault(A(0)) ?? "";
            case "get_func_name": return db.FuncAt(A(0)) is Function f ? db.FuncName(f) : "";
            case "get_func_start": return db.FuncAt(A(0))?.Start ?? ulong.MaxValue;
            case "get_func_end": return db.FuncAt(A(0))?.End ?? ulong.MaxValue;
            case "byte": case "get_wide_byte": return R(1);
            case "word": case "get_wide_word": return R(2);
            case "dword": case "get_wide_dword": return R(4);
            case "qword": case "get_qword": return R(8);
            case "get_bytes":
            {
                var sb = new StringBuilder();
                for (ulong i = 0; i < Math.Min(A(1), 4096UL); i++)
                    sb.Append(db.TryByte(A(0) + i, out var b) ? b.ToString("X2") + " " : "?? ");
                return sb.ToString().Trim();
            }
            case "patch_byte":
            {
                if (!db.PatchByte(A(0), (byte)A(1))) throw new Exception(Loc.T("Yamalanamadı"));
                Reanalyze(A(0));
                return 1UL;
            }
            case "get_str": case "get_strlit_contents": return db.StringAt(A(0)) ?? db.ReadAscii(A(0), 1024);
            case "xrefs_to":
                return string.Join("\n", db.XrefsTo(A(0)).Select(x => $"  {(char)x.Type} {db.LocStr(x.From)} ({db.AddrStr(x.From)})"));
            case "xrefs_from":
                return string.Join("\n", db.XrefsFrom(A(0)).Select(x => $"  {(char)x.Type} {db.RefName(x.To)} ({db.AddrStr(x.To)})"));
            case "functions": return (ulong)db.Funcs.Count;
            case "segments": return string.Join("\n", db.Segs.Select(s => $"  {s.Name,-10} {db.AddrStr(s.Start)} - {db.AddrStr(s.End)} {s.Class}"));
            case "msg": case "print": return a.Count == 0 ? "" : a[0] is ulong v ? FormatNum(v) : a[0]?.ToString();
            case "atoi": return ulong.TryParse(S(0), out var n) ? n : 0UL;
            case "help": return IdcHelp;
            default: throw new Exception(Loc.T("Bilinmeyen fonksiyon: ") + fn + Loc.T("  (help yaz)"));
        }
    }
}
