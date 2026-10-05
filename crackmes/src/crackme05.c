/* tlk-hex crackme 05  -  level: medium (patching)
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
