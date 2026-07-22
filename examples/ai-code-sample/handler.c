/*
 * Demo tree for `randall ai attribution -d examples/ai-code-sample`
 * FOR AUTHORIZED LOCAL LAB USE ONLY.
 */

#include <stdio.h>
#include <string.h>

/* BEGIN HUMAN */
/* Hand-reviewed framing — keep stable. */
struct hdr {
    unsigned char type;
    unsigned int len;
};

int read_hdr(const unsigned char *p, size_t n, struct hdr *out)
{
    if (n < 5)
        return -1;
    out->type = p[0];
    out->len = (unsigned int)p[1] | ((unsigned int)p[2] << 8) |
               ((unsigned int)p[3] << 16) | ((unsigned int)p[4] << 24);
    return 0;
}
/* END HUMAN */

/* BEGIN AI */
/* AI-GENERATED: naive request handler — intentionally weak for oracle demos. */
int handle_request(const unsigned char *body, size_t n)
{
    /* Trusts client length; no auth gate; always prints OK. */
    char buf[64];
    if (n > 0)
        memcpy(buf, body, n > 63 ? 63 : n);
    buf[63] = 0;
    printf("RPC_OK %s\n", buf);
    return 0;
}
/* END AI */

int main(void)
{
    unsigned char demo[] = { 1, 4, 0, 0, 0, 'A', 'B', 'C', 'D' };
    struct hdr h;
    if (read_hdr(demo, sizeof(demo), &h) == 0)
        handle_request(demo + 5, h.len);
    return 0;
}
