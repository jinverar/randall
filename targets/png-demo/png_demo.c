/*
 * Cold out-of-process PNG demo target — argv[1] = input path ({file}).
 * Build: scripts/build-png-demo.ps1 | scripts/build-png-demo.sh
 */
#include "png_parse.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.png>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 2;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 2;
    }
    long sz = ftell(f);
    if (sz < 0 || sz > 8 * 1024 * 1024) {
        fclose(f);
        return PNG_REJECT;
    }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 2;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    int rc = png_parse(buf, n);
    free(buf);
    return rc; /* 0 ok, 1 reject — never crash-shaped for soft rejects */
}
