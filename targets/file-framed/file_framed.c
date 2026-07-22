/*
 * Mini length-prefixed binary file target for projects/file-framed.yaml.
 *
 * Accepts either:
 *   A) FRM0 | u32le length | payload[length] | u32le xor  (seed / dict style)
 *   B) u32le length | payload[length] | u32le checksum   (protocol model style)
 *
 * Bugs (abort for reliable capture):
 *   1) claimed length past end of file
 *   2) FRM0 + length == 0x41414141
 *   3) payload starts with "DEEP" + high bit
 *
 * Build: scripts/build-file-framed.sh | scripts/build-file-framed.ps1
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static uint32_t read_u32le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void check_payload(const unsigned char *payload, uint32_t len)
{
    if (len == 0x41414141u)
        abort();
    if (len >= 4 && memcmp(payload, "BOOM", 4) == 0)
        abort();
    if (len >= 4 && memcmp(payload, "DEAD", 4) == 0)
        abort();
    if (len >= 5 && memcmp(payload, "DEEP", 4) == 0 && (payload[4] & 0x80))
        abort();
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 2;

    unsigned char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (n < 8)
        return 0;

    size_t off = 0;
    if (n >= 12 && memcmp(buf, "FRM0", 4) == 0)
        off = 4;

    uint32_t len = read_u32le(buf + off);
    if (off + 4 + (size_t)len + 4 > n)
        abort(); /* length lie */

    check_payload(buf + off + 4, len);
    return 0;
}
