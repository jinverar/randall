/*
 * Tiny PNG chunk walker for Randall competitive file-fuzz demo.
 * Real signature + length/type/CRC layout (ISO 15948), not a full decoder.
 *
 * Intentional lab vulns (abort) — NOT upstream CVEs:
 *   A) claimed chunk length past EOF
 *   B) IHDR width*height product overflow
 *   C) private chunk type "FUZZ" with payload starting "BOOM"
 *
 * Soft reject (return PNG_REJECT): bad signature / truncated header.
 * Soft ok (return PNG_OK): walked chunks without hitting a bug path.
 */
#ifndef PNG_PARSE_H
#define PNG_PARSE_H

#include <stddef.h>
#include <stdint.h>

enum { PNG_OK = 0, PNG_REJECT = 1 };

#ifdef __cplusplus
extern "C" {
#endif

int png_parse(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* PNG_PARSE_H */
