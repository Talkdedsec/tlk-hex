// The hero window's three tabs show the same function three ways, like the app: listing, bytes, pseudocode.
(() => {
  const win = document.querySelector(".hero .win");
  if (!win) return;
  const tabs = [...win.querySelectorAll(".tab")];
  const listing = win.querySelector(".listing");
  const panes = { 0: listing };

  // bytes behind the listing; the elided middle of the function is filler so the dump stays contiguous
  const CODE = {
    0x08: "4C 8B DC", 0x0b: "48 81 EC 88 00 00 00", 0x12: "48 8B 05 E7 2F 00 00", 0x19: "48 33 C4",
    0x1c: "48 89 44 24 70", 0x53: "48 8D 0D B6 41 00 00", 0x5a: "8B D6", 0x73: "E8 58 01 00 00",
    0x78: "48 8B 4C 24 70", 0x7d: "48 33 CC", 0x80: "E8 9B 02 00 00", 0x85: "48 81 C4 88 00 00 00", 0x8c: "C3"
  };
  const bytes = new Array(0x90).fill(null);
  for (const [at, hex] of Object.entries(CODE)) hex.split(" ").forEach((b, i) => (bytes[+at + i] = b));
  let seed = 11;
  const filler = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) % 256).toString(16).toUpperCase().padStart(2, "0");
  for (let i = 0; i < bytes.length; i++) if (bytes[i] === null) bytes[i] = i < 8 ? "CC" : filler();
  const hexPane = document.createElement("div");
  hexPane.className = "listing";
  for (let row = 0; row < bytes.length; row += 16) {
    const chunk = bytes.slice(row, row + 16);
    const ascii = chunk.map((b) => { const c = parseInt(b, 16); return c > 32 && c < 127 ? String.fromCharCode(c) : "."; }).join("");
    const cells = chunk.map((b, i) => (CODE[row + i] !== undefined ? `<span class="m">${b}</span>` : b)).join(" ");
    hexPane.insertAdjacentHTML("beforeend", `<div class="ln"><span class="a">${(0x140001000 + row).toString(16).toUpperCase()}</span>  ${cells}  <span class="cm">${ascii.replace(/[<>&]/g, ".")}</span></div>`);
  }
  panes[1] = hexPane;

  const pseudo = document.createElement("div");
  pseudo.className = "listing";
  pseudo.innerHTML = [
    '<span class="kw">void</span> <span class="kw">__fastcall</span> <span class="nm">ParseConfigFile</span>(<span class="kw">const char</span> *path, <span class="kw">int</span> count)',
    "{",
    '  <span class="kw">unsigned __int64</span> cookie; <span class="cm">// [rsp+70h] [rbp-18h]</span>',
    "",
    '  cookie = <span class="nm">__security_cookie</span> ^ (<span class="kw">unsigned __int64</span>)&amp;cookie;',
    '  <span class="cm">// ... reads and parses path ...</span>',
    '  <span class="nm">LogMessage</span>(<span class="n">"config loaded: %s"</span>, count);',
    '  <span class="im">__security_check_cookie</span>(cookie ^ (<span class="kw">unsigned __int64</span>)&amp;cookie);',
    "}"
  ].map((l) => `<div class="ln${l.includes("LogMessage") ? " hl" : ""}">${l || " "}</div>`).join("");
  panes[2] = pseudo;

  win.removeAttribute("aria-hidden");
  win.querySelector(".win-bar").setAttribute("role", "tablist");
  tabs.forEach((t, i) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = t.className;
    b.textContent = t.textContent;
    b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", i === 0);
    b.tabIndex = i === 0 ? 0 : -1;
    t.replaceWith(b);
    tabs[i] = b;
  });
  let cur = 0;
  const show = (i) => {
    win.querySelector(".listing").replaceWith(panes[i]);
    tabs.forEach((t, j) => { t.classList.toggle("on", i === j); t.setAttribute("aria-selected", i === j); t.tabIndex = i === j ? 0 : -1; });
    cur = i;
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => show(i));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) { e.preventDefault(); const n = (i + d + tabs.length) % tabs.length; show(n); tabs[n].focus(); }
    });
  });
  // F5 is the app's pseudocode key; it toggles back to the listing like there
  addEventListener("keydown", (e) => {
    if (e.key !== "F5" || e.ctrlKey || e.metaKey) return;
    const r = win.getBoundingClientRect();
    if (r.bottom < 0 || r.top > innerHeight) return;
    e.preventDefault();
    show(cur === 2 ? 0 : 2);
  });
})();
