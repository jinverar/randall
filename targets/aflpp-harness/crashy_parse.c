/*
 * Minimal file harness for AFL++ / honggfuzz campaigns via Randfuzz.
 * Reads argv[1], crashes if the buffer contains '!'.
 *
 * Build (preferred — real AFL instrumentation):
 *   afl-clang-fast -O2 -o crashy_parse crashy_parse.c
 * Fallback (no AFL compiler):
 *   gcc -O2 -o crashy_parse crashy_parse.c
 *   # then fuzz with engineExtraArgs: "-Q" (QEMU) or accept slower binary-only mode
 *
 * AUTHORIZED LOCAL USE ONLY — proof that the AFL++ adapter works. Point the same
 * project shape at your authorized real binary under projects/local/.
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 2;

    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '!') {
            volatile int *p = (volatile int *)0;
            *p = 1;
        }
    }
    return 0;
}
