/* tlk-hex crackme 02  -  level: easy-medium
 * Goal: the password is NOT in plaintext. It is XOR-encoded and decoded at
 *       runtime. Read the loop (or the key byte) to recover it.
 * Technique: immediates, a decode loop, then strcmp. */
#include <stdio.h>
#include <string.h>

/* encoded password bytes (xor-ed) */
static const unsigned char enc[] = { 0xFD, 0xDE, 0xC9, 0xC4, 0x84, 0x93, 0x95 };
static const int enc_len = 7;

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
