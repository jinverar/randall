/*
 * Annotated sample for Bug Hunter — mirrors Randall.VulnAi RAG1 handlers.
 * FOR AUTHORIZED LOCAL LAB USE ONLY. Not a real LLM or agent.
 */

#include <string.h>

/* BEGIN HUMAN */
/* Framing kept stable — reviewed length header reader. */
struct rag_hdr {
    unsigned char type;
    unsigned short rem;
};

int read_rag_hdr(const unsigned char *p, unsigned n, struct rag_hdr *out)
{
    if (n < 3)
        return -1;
    out->type = p[0];
    out->rem = (unsigned short)((p[1] << 8) | p[2]);
    return 0;
}
/* END HUMAN */

/* BEGIN AI */
/* AI-GENERATED: trusts client prompt_len (length-lie). */
int handle_infer(const unsigned char *body, unsigned n)
{
    char buf[64];
    unsigned plen;
    if (n < 2)
        return -1;
    plen = (unsigned)((body[0] << 8) | body[1]);
    /* Missing bound vs buf — lab target crashes in the .NET twin. */
    if (plen > 0 && n > 2)
        memcpy(buf, body + 2, plen > 63 ? 63 : plen);
    buf[63] = 0;
    return 0;
}
/* END AI */

/* BEGIN AI */
/* AI-GENERATED: tool bridge with weak caps (output-bridge). */
int handle_tool(const unsigned char *body, unsigned n)
{
    char join[48];
    (void)body;
    (void)n;
    memset(join, 0, sizeof join);
    return 0;
}
/* END AI */

/* BEGIN AI */
/* AI-GENERATED: admin elevates on role=admin string alone (auth-skip). */
int handle_admin(const unsigned char *body, unsigned n)
{
    (void)body;
    (void)n;
    /* TODO: real auth */
    return 0;
}
/* END AI */
