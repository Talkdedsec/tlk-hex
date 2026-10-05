# tlk-hex practice crackmes

A small set of **original** reverse-engineering practice programs, one per difficulty level.
They are made to be *solved* — perfect targets for [Module 07](https://talkdedsec.github.io/tlk-hex/learn.html#m7)
of the tutorials. Each is a tiny, benign Windows x64 console program: no network, no anti-debug tricks,
no real protection — just logic to understand with tlk-hex.

> Prebuilt binaries are on the **[crackmes release](https://github.com/Talkdedsec/tlk-hex/releases/tag/crackmes-v1)**.
> The C sources live in `crackmes/src/` (they are *spoilers* — try to solve from the binary first).

## The levels

| # | Level | What it teaches |
|---|---|---|
| 01 | easy | A plaintext password. Find it with **Strings** → xref → `strcmp`. |
| 02 | easy-medium | The password is **XOR-encoded** (not in Strings). Read the decode loop / key byte. |
| 03 | medium | A **name → serial** check. Read the hash loop and reconstruct the algorithm (keygen). |
| 04 | medium-hard | An 8-char key transformed per-index and compared to an embedded array. **Reverse the transform or patch the check.** |

## How to play

1. Download a `crackmeNN.exe` from the release.
2. Run it once to see what it asks for.
3. Open it in **tlk-hex**, follow the Module 07 workflow: strings → xref → graph → return values → `F5`.
4. Recover the correct input **from the binary only**, then run the exe to confirm.
5. Bonus: for 03 and 04, write a tiny "keygen" that produces a valid input for any case.

## Rules & ethics

These are **your own** practice targets — analysing them is fully legal and safe. The skills are for
learning, CTFs, security research and authorized analysis. Don't use reverse engineering to defeat the
licensing/DRM of software you didn't buy.

## Build from source

Needs a C compiler (MinGW-w64 `gcc` or MSVC `cl`). From this folder:

```sh
python gen.py            # (re)generate sources with the embedded byte arrays
gcc -O2 -s -o bin/crackme01.exe src/crackme01.c
# ... same for 02..04
```

---

<details>
<summary><b>⚠️ Spoilers — solutions (don't open until you've tried)</b></summary>

<br>

- **01** — password: `letmein` (visible directly in Strings).
- **02** — password: `Zync#42` (bytes are XOR-ed with `0xA7`; decode `enc[] ^ 0xA7`).
- **03** — serial = `djb2`-style hash of the name: `key=0x1505; key=key*33+c; serial = key % 90000 + 10000`.
  Example: name `talkdedsec` → serial `38105`.
- **04** — key: `RE_2026!` (each byte: `target[i] = ((key[i] ^ (i*0x11)) + 0x20) & 0xFF`; reverse it per index).

</details>

---

<details>
<summary><b>Türkçe</b></summary>

<br>

Dört adet **özgün** tersine mühendislik alıştırma programı — her biri farklı bir seviye ve teknik.
Çözülmek için yapıldılar; [Modül 07](https://talkdedsec.github.io/tlk-hex/tr/egitim.html#m7) için birebir
hedef. Hepsi küçük, zararsız Windows x64 konsol programı: ağ yok, anti-debug yok, gerçek koruma yok —
sadece tlk-hex ile anlaşılacak mantık.

| # | Seviye | Öğrettiği |
|---|---|---|
| 01 | kolay | Düz metin parola. **Strings** → xref → `strcmp` ile bul. |
| 02 | kolay-orta | Parola **XOR'lu** (Strings'te yok). Çözme döngüsünü / anahtar baytı oku. |
| 03 | orta | **İsim → seri** kontrolü. Hash döngüsünü oku, algoritmayı çıkar (keygen). |
| 04 | orta-zor | 8 karakterlik anahtar indekse göre dönüştürülüp gömülü diziyle karşılaştırılır. Dönüşümü tersine çevir ya da kontrolü yama. |

**Kurallar:** Bunlar **senin** alıştırma hedeflerin — analiz tamamen yasal ve güvenli. Beceriler öğrenme,
CTF, güvenlik araştırması ve izinli analiz içindir. Satın almadığın yazılımın korumasını kırmak için değil.

</details>
