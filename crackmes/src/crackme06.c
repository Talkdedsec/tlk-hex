/* tlk-hex crackme 06  -  level: medium (stack string)
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
