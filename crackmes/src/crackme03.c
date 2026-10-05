/* tlk-hex crackme 03  -  level: medium
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
