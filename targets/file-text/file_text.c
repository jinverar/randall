/*
 * Mini in-repo structured-text / XML file target for projects/file-text.yaml.
 * Intentionally crashable — teaching floor for doctor/fuzz out of the box.
 *
 * Bugs (abort for reliable capture under -O1):
 *   A) Element name longer than 64 → abort
 *   B) Tag <BOOM> anywhere → abort
 *   C) Attribute len="N" that lies about following text → abort
 *
 * Build: scripts/build-file-text.sh | scripts/build-file-text.ps1
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 2;

    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    /* Bug B */
    if (strstr(buf, "<BOOM>") || strstr(buf, "<boom>"))
        abort();

    for (size_t i = 0; i < n; i++) {
        if (buf[i] != '<')
            continue;
        if (buf[i + 1] == '/' || buf[i + 1] == '!' || buf[i + 1] == '?')
            continue;

        size_t namelen = 0;
        const char *s = buf + i + 1;
        while (s[namelen] && s[namelen] != '>' && s[namelen] != ' ' &&
               s[namelen] != '/' && s[namelen] != '\t')
            namelen++;

        /* Bug A */
        if (namelen > 64)
            abort();

        /* Bug C: len="NNN" claims body size */
        char *lenp = strstr(buf + i, "len=\"");
        if (lenp && lenp < buf + n) {
            int claimed = atoi(lenp + 5);
            char *gt = strchr(buf + i, '>');
            if (gt && claimed > 0) {
                char *body = gt + 1;
                size_t remain = (size_t)(buf + n - body);
                if ((size_t)claimed > remain + 8)
                    abort();
            }
        }
    }

    return 0;
}
