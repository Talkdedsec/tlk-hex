/* tlk-hex crackme 01  -  level: easy
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
