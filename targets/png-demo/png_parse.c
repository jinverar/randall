#include "png_parse.h"

#include <stdlib.h>
#include <string.h>

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* PNG / ISO-3309 CRC-32 (same poly as zlib). */
static uint32_t png_crc32(const uint8_t *data, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1u) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
    }
    return ~crc;
}

static int chunk_type_eq(const uint8_t *t, const char *s)
{
    return t[0] == (uint8_t)s[0] && t[1] == (uint8_t)s[1] &&
           t[2] == (uint8_t)s[2] && t[3] == (uint8_t)s[3];
}

static void check_ihdr(const uint8_t *data, uint32_t len)
{
    if (len < 13)
        return;
    uint32_t w = read_be32(data);
    uint32_t h = read_be32(data + 4);
    /* Bug B: classic width*height product overflow. */
    if (w != 0 && h != 0 && w > (0xFFFFFFFFu / h))
        abort();
}

int png_parse(const uint8_t *data, size_t size)
{
    static const uint8_t sig[8] = {
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    if (data == NULL || size < 8)
        return PNG_REJECT;
    if (memcmp(data, sig, 8) != 0)
        return PNG_REJECT;

    size_t off = 8;
    while (off + 12 <= size) {
        uint32_t len = read_be32(data + off);
        const uint8_t *type = data + off + 4;
        size_t data_off = off + 8;

        /* Bug A: length lie — claimed payload past EOF (before CRC). */
        if (data_off + (size_t)len + 4 > size)
            abort();

        const uint8_t *payload = data + data_off;
        uint32_t file_crc = read_be32(data + data_off + len);
        /* CRC covers type+data; mismatch is soft (many mutants break CRC). */
        (void)png_crc32(type, 4 + (size_t)len);
        (void)file_crc;

        if (chunk_type_eq(type, "IHDR"))
            check_ihdr(payload, len);

        /* Bug C: private FUZZ + BOOM marker (dictionary / chunk-insert friendly). */
        if (chunk_type_eq(type, "FUZZ") && len >= 4 &&
            memcmp(payload, "BOOM", 4) == 0)
            abort();

        int is_iend = chunk_type_eq(type, "IEND");
        off = data_off + (size_t)len + 4;
        if (is_iend)
            break;
    }

    return PNG_OK;
}
