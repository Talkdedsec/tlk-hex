/* tlk-hex crackme 04  -  level: medium-hard
 * Goal: find the 8-char key. Each byte is transformed and compared to an
 *       embedded target array. Reverse the transform (keygen) or patch the check.
 * Technique: per-index transform (xor + add), loop, compare to target.
 * Combine graph + pseudocode + assembly. */
#include <stdio.h>
#include <string.h>

static const unsigned char target[] = { 0x72, 0x74, 0x9D, 0x21, 0x94, 0x87, 0x70, 0x76 };
#define KLEN 8

int main(void)
{
    char buf[64];
    int i, ok = 1;

    printf("== tlk-hex crackme 04 (medium-hard) ==\n");
    printf("Enter the %d-char key.\n\nKey: ", KLEN);
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
