# -*- coding: utf-8 -*-
# tlk-hex pratik crackme'lerini üretir (özgün, yasal RE alıştırmaları).
# Gömülü bayt dizilerini (XOR'lu parola, hedef dizi) doğru hesaplayıp .c dosyalarını yazar.
import os
HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
os.makedirs(SRC, exist_ok=True)

def carr(bs):
    return "{ " + ", ".join("0x%02X" % b for b in bs) + " }"

# ---------- 01: düz metin parola ----------
c01 = r'''/* tlk-hex crackme 01  -  level: easy
 * Goal: find the password.  Technique: strings -> xref -> strcmp.
 * (Original practice binary. No real protection. Benign.) */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[64];
    printf("== tlk-hex crackme 01 (easy) ==\n");
    printf("Find the password.\n\nPassword: ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;

    if (strcmp(buf, "letmein") == 0)
        printf("\n[+] Correct! Level 01 solved.\n");
    else
        printf("\n[-] Wrong.\n");
    return 0;
}
'''

# ---------- 02: XOR ile gizlenmiş parola ----------
PW2 = "Zync#42"
KEY2 = 0xA7
enc2 = [ord(ch) ^ KEY2 for ch in PW2]
assert all(b != 0 for b in enc2)  # null yok
c02 = r'''/* tlk-hex crackme 02  -  level: easy-medium
 * Goal: the password is NOT in plaintext. It is XOR-encoded and decoded at
 *       runtime. Read the loop (or the key byte) to recover it.
 * Technique: immediates, a decode loop, then strcmp. */
#include <stdio.h>
#include <string.h>

/* encoded password bytes (xor-ed) */
static const unsigned char enc[] = %s;
static const int enc_len = %d;

int main(void)
{
    char buf[64];
    unsigned char pw[64];
    int i;

    printf("== tlk-hex crackme 02 (easy-medium) ==\n");
    printf("The password is hidden. Find it.\n\nPassword: ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;

    for (i = 0; i < enc_len; i++)
        pw[i] = enc[i] ^ 0xA7;     /* decode */
    pw[enc_len] = 0;

    if (strcmp(buf, (char *)pw) == 0)
        printf("\n[+] Correct! Level 02 solved.\n");
    else
        printf("\n[-] Wrong.\n");
    return 0;
}
''' % (carr(enc2), len(enc2))

# ---------- 03: name -> serial (keygen) ----------
def djb2_16(name):
    key = 0x1505
    for ch in name:
        key = ((key << 5) + key + ord(ch)) & 0xFFFFFFFF   # key*33 + c
    return key % 90000 + 10000  # 5 haneli
c03 = r'''/* tlk-hex crackme 03  -  level: medium
 * Goal: for a given name, compute the correct serial (keygen).
 * Technique: read the hash loop (shift/add), modulo; reconstruct the algorithm.
 * The serial is derived from the name, so you must understand the math. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned expected_serial(const char *name)
{
    unsigned key = 0x1505;
    for (; *name; name++)
        key = (key << 5) + key + (unsigned char)*name;   /* key = key*33 + c */
    return key % 90000 + 10000;                          /* 5-digit serial */
}

int main(void)
{
    char name[64], serial[64];

    printf("== tlk-hex crackme 03 (medium) ==\n");
    printf("Enter a name, then its serial.\n\n");
    printf("Name:   ");
    if (!fgets(name, sizeof name, stdin)) return 1;
    name[strcspn(name, "\r\n")] = 0;
    printf("Serial: ");
    if (!fgets(serial, sizeof serial, stdin)) return 1;
    serial[strcspn(serial, "\r\n")] = 0;

    if (name[0] && (unsigned)atoi(serial) == expected_serial(name))
        printf("\n[+] Correct! Level 03 solved. (You can keygen any name.)\n");
    else
        printf("\n[-] Wrong serial.\n");
    return 0;
}
'''

# ---------- 04: çok aşamalı bayrak kontrolü ----------
FLAG4 = "RE_2026!"
def transform4(s):
    return [ (((ord(s[i]) ^ (i * 0x11)) + 0x20) & 0xFF) for i in range(len(s)) ]
tgt4 = transform4(FLAG4)
c04 = r'''/* tlk-hex crackme 04  -  level: medium-hard
 * Goal: find the 8-char key. Each byte is transformed and compared to an
 *       embedded target array. Reverse the transform (keygen) or patch the check.
 * Technique: per-index transform (xor + add), loop, compare to target.
 * Combine graph + pseudocode + assembly. */
#include <stdio.h>
#include <string.h>

static const unsigned char target[] = %s;
#define KLEN %d

int main(void)
{
    char buf[64];
    int i, ok = 1;

    printf("== tlk-hex crackme 04 (medium-hard) ==\n");
    printf("Enter the %%d-char key.\n\nKey: ", KLEN);
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;

    if ((int)strlen(buf) != KLEN) {
        printf("\n[-] Wrong length.\n");
        return 0;
    }
    for (i = 0; i < KLEN; i++) {
        unsigned char t = (unsigned char)(((buf[i] ^ (i * 0x11)) + 0x20) & 0xFF);
        if (t != target[i]) ok = 0;
    }
    printf(ok ? "\n[+] Flag accepted! Level 04 solved.\n"
              : "\n[-] Wrong key.\n");
    return 0;
}
''' % (carr(tgt4), len(tgt4))

open(os.path.join(SRC, "crackme01.c"), "w", encoding="utf-8").write(c01)
open(os.path.join(SRC, "crackme02.c"), "w", encoding="utf-8").write(c02)
open(os.path.join(SRC, "crackme03.c"), "w", encoding="utf-8").write(c03)
open(os.path.join(SRC, "crackme04.c"), "w", encoding="utf-8").write(c04)

# çözümleri (test + README spoiler için) yazdır
print("SOLUTIONS")
print(" 01 password:", "letmein")
print(" 02 password:", PW2)
print(" 03 name:", "talkdedsec", "serial:", djb2_16("talkdedsec"))
print(" 04 key:", FLAG4)

# ---------- 05: yama hedefi (patching) ----------
c05 = r'''/* tlk-hex crackme 05  -  level: medium (patching)
 * The license check hashes your key and compares it to a fixed constant that is
 * impractical to hit by typing. The intended solution is to PATCH the branch in
 * Hex View (F2): flip the conditional jump, then apply-to-file / export a DIF. */
#include <stdio.h>
#include <string.h>

static int verify(const char *s)
{
    unsigned h = 0;
    for (; *s; s++)
        h = h * 131u + (unsigned char)*s;
    return h == 0xDEADBEEFu;     /* a very hard-to-reach target */
}

int main(void)
{
    char buf[64];
    printf("== tlk-hex crackme 05 (medium - patch me) ==\n");
    printf("License key: ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;

    if (verify(buf))
        printf("\n[+] Access granted. Level 05 solved.\n");
    else
        printf("\n[-] Access denied.  (Hint: find the branch and patch it.)\n");
    return 0;
}
'''

# ---------- 06: stack string ----------
PW6 = "st4ck_k3y"
c06 = r'''/* tlk-hex crackme 06  -  level: medium (stack string)
 * The password is built on the stack byte-by-byte (volatile), so it is NOT a
 * contiguous string in .rdata and Strings will not show it. Read the byte
 * stores (mov byte ptr [rsp+x], 'c') to recover it. */
#include <stdio.h>
#include <string.h>

int main(void)
{
    volatile char pw[16];
    char buf[64];
    int i = 0;
    pw[i++]='s'; pw[i++]='t'; pw[i++]='4'; pw[i++]='c'; pw[i++]='k';
    pw[i++]='_'; pw[i++]='k'; pw[i++]='3'; pw[i++]='y'; pw[i]=0;

    printf("== tlk-hex crackme 06 (medium - stack string) ==\n");
    printf("Password: ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;

    if (strcmp(buf, (char *)pw) == 0)
        printf("\n[+] Correct! Level 06 solved.\n");
    else
        printf("\n[-] Wrong.\n");
    return 0;
}
'''

open(os.path.join(SRC, "crackme05.c"), "w", encoding="utf-8").write(c05)
open(os.path.join(SRC, "crackme06.c"), "w", encoding="utf-8").write(c06)
print(" 05 solution: PATCH the jump after the cmp with 0DEADBEEFh (no simple key)")
print(" 06 password:", PW6)
