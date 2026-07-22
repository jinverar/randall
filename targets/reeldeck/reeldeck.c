/*
 * ReelDeck — lab media player / video-studio file target for Randfuzz.
 *
 * Parses a toy container ".rndl" (Randall Media) with multiple deep paths:
 *   header → catalog → PCM audio | MAD (mp3-like) | VID frames | META → studio compose
 *
 * Intentional bugs live at different depths so shallow fuzz finds easy crashes,
 * then stalking / path novelty is needed to push into MAD, VID, and studio code.
 *
 * Build:
 *   scripts/build-reeldeck.sh
 *   # or: gcc -O1 -g -o targets/reeldeck/reeldeck targets/reeldeck/reeldeck.c
 *
 * Usage: reeldeck <file.rndl>
 * Path log: set REELDECK_PATHLOG=/path/to/out.paths (one function name per line)
 *
 * AUTHORIZED LAB USE ONLY.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REEL_MAGIC "RNDL"
#define FLAG_STUDIO 0x0001u
#define FLAG_PLAYLIST 0x0002u

static char g_pathlog[512];
static int g_traced;

static void path_hit(const char *fn)
{
    if (!g_traced)
        return;
    FILE *f = fopen(g_pathlog, "a");
    if (!f)
        return;
    fprintf(f, "%s\n", fn);
    fclose(f);
}

static uint16_t rd_u16(const unsigned char *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd_u32(const unsigned char *p)
{
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

/* —— shallow: title copy into fixed stack buffer —— */
static int parse_header(const unsigned char *buf, size_t n, size_t *off,
                        uint16_t *flags_out, char *title_out, size_t title_cap)
{
    path_hit("parse_header");
    if (*off + 12 > n)
        return -1;
    if (memcmp(buf + *off, REEL_MAGIC, 4) != 0)
        return -2;
    *off += 4;
    uint16_t ver = rd_u16(buf + *off);
    *off += 2;
    uint16_t flags = rd_u16(buf + *off);
    *off += 2;
    uint32_t hdr_size = rd_u32(buf + *off);
    *off += 4;
    (void)ver;
    (void)hdr_size;
    *flags_out = flags;

    if (*off + 2 > n)
        return -1;
    uint16_t tlen = rd_u16(buf + *off);
    *off += 2;
    if (*off + tlen > n)
        return -1;

    /* BUG A (shallow): oversized title — reliable lab crash + stack smash attempt. */
    char stack_title[32];
    if (tlen >= 48) {
        path_hit("parse_header_title_overflow");
        abort();
    }
    memcpy(stack_title, buf + *off, tlen); /* still dangerous for mid-size titles */
    stack_title[tlen < sizeof(stack_title) ? tlen : sizeof(stack_title) - 1] = 0;
    *off += tlen;

    size_t copy = tlen < title_cap - 1 ? tlen : title_cap - 1;
    memcpy(title_out, stack_title, copy);
    title_out[copy] = 0;
    path_hit("parse_header_ok");
    return 0;
}

static int decode_pcm(const unsigned char *data, uint32_t len)
{
    path_hit("decode_pcm");
    if (len < 4) {
        path_hit("decode_pcm_short");
        return 0;
    }
    /* First dword = declared sample bytes (may lie). */
    uint32_t claimed = rd_u32(data);
    const unsigned char *body = data + 4;
    size_t avail = len - 4;
    /* BUG B (medium): trusts claimed over avail. */
    unsigned char *pcm = (unsigned char *)malloc(claimed ? claimed : 1);
    if (!pcm)
        return -1;
    memcpy(pcm, body, claimed); /* intentional when claimed > avail */
    volatile unsigned char sink = 0;
    for (uint32_t i = 0; i < claimed && i < 64; i++)
        sink ^= pcm[i];
    (void)sink;
    (void)avail;
    free(pcm);
    path_hit("decode_pcm_ok");
    return 0;
}

/* MAD: mp3-ish frames — need 0xFFEx sync before deep parse */
static int decode_mad(const unsigned char *data, uint32_t len)
{
    path_hit("decode_mad");
    if (len < 4)
        return 0;

    size_t sync = (size_t)-1;
    for (size_t i = 0; i + 1 < len; i++) {
        if (data[i] == 0xFF && (data[i + 1] & 0xE0) == 0xE0) {
            sync = i;
            break;
        }
    }
    if (sync == (size_t)-1) {
        path_hit("decode_mad_no_sync");
        return 0;
    }
    path_hit("decode_mad_sync");

    if (sync + 4 > len)
        return 0;
    unsigned char bitrate_idx = (data[sync + 2] >> 4) & 0x0F;
    unsigned char layer = (data[sync + 1] >> 1) & 0x03;

    /* Deep path: only "Layer III" shaped (layer == 1 in our toy) */
    if (layer != 1) {
        path_hit("decode_mad_other_layer");
        return 0;
    }
    path_hit("decode_mad_layer3");

    /* BUG C (deep): bitrate_idx == 0xF triggers null deref after sync+layer checks */
    if (bitrate_idx == 0x0F) {
        path_hit("decode_mad_bug");
        volatile int *p = (volatile int *)0;
        *p = (int)len;
    }

    /* Side-info toy walk */
    size_t side = sync + 4;
    if (side + 2 <= len && data[side] == 0x42 && data[side + 1] == 0x52) {
        path_hit("decode_mad_sideinfo");
        if (side + 6 <= len && data[side + 2] == 'X') {
            path_hit("decode_mad_extension");
            /* rarer crash: extension marker */
            if (data[side + 3] == 0xFF) {
                path_hit("decode_mad_extension_bug");
                abort();
            }
        }
    }
    path_hit("decode_mad_ok");
    return 0;
}

static int decode_vid(const unsigned char *data, uint32_t len)
{
    path_hit("decode_vid");
    int saw_i = 0, saw_p = 0;
    size_t i = 0;
    while (i + 5 <= len) {
        unsigned char typ = data[i];
        uint32_t flen = rd_u32(data + i + 1);
        i += 5;
        if (flen > len || i + flen > len)
            break;
        if (typ == 'I') {
            path_hit("decode_vid_I");
            saw_i = 1;
        } else if (typ == 'P') {
            path_hit("decode_vid_P");
            saw_p = 1;
        } else if (typ == 'B') {
            path_hit("decode_vid_B");
        } else if (typ == 'X') {
            path_hit("decode_vid_X");
            /* BUG D (deeper): exotic X only meaningful after I+P — then overflow */
            if (saw_i && saw_p) {
                path_hit("decode_vid_X_after_IP");
                char name[16];
                memcpy(name, data + i, flen); /* intentional */
                name[sizeof(name) - 1] = 0;
                (void)name;
            }
        }
        i += flen;
    }
    path_hit("decode_vid_ok");
    return 0;
}

static int apply_meta(const unsigned char *data, uint32_t len)
{
    path_hit("apply_meta");
    size_t i = 0;
    while (i + 4 <= len) {
        char key[5];
        memcpy(key, data + i, 4);
        key[4] = 0;
        i += 4;
        if (i + 2 > len)
            break;
        uint16_t vlen = rd_u16(data + i);
        i += 2;
        if (i + vlen > len)
            break;
        if (memcmp(key, "ART ", 4) == 0)
            path_hit("apply_meta_ART");
        else if (memcmp(key, "ALB ", 4) == 0)
            path_hit("apply_meta_ALB");
        else if (memcmp(key, "LYC ", 4) == 0)
            path_hit("apply_meta_LYC");
        else if (memcmp(key, "CUE ", 4) == 0) {
            path_hit("apply_meta_CUE");
            /* cue sheet nested */
            if (vlen >= 3 && data[i] == 'Q' && data[i + 1] == 'Q')
                path_hit("apply_meta_CUE_QQ");
        }
        i += vlen;
    }
    path_hit("apply_meta_ok");
    return 0;
}

/* Studio / video-maker path — only with FLAG_STUDIO */
static int studio_compose(const unsigned char *buf, size_t n, size_t off)
{
    path_hit("studio_compose");
    if (off + 8 > n)
        return 0;
    if (memcmp(buf + off, "EDIT", 4) != 0) {
        path_hit("studio_compose_no_edit");
        return 0;
    }
    path_hit("studio_compose_edit");
    off += 4;
    uint16_t clips = rd_u16(buf + off);
    off += 2;
    uint16_t filter_len = rd_u16(buf + off);
    off += 2;

    char filter[24];
    if (off + filter_len > n)
        return 0;
    /* BUG E (deepest): filter name smash in studio timeline */
    memcpy(filter, buf + off, filter_len); /* intentional */
    filter[sizeof(filter) - 1] = 0;
    off += filter_len;
    path_hit("studio_compose_filter");

    for (uint16_t c = 0; c < clips && off + 6 <= n; c++) {
        path_hit("studio_compose_clip");
        uint32_t start = rd_u32(buf + off);
        off += 4;
        uint16_t dur = rd_u16(buf + off);
        off += 2;
        (void)start;
        (void)dur;
        if (dur == 0xFFFF) {
            path_hit("studio_compose_clip_bug");
            abort();
        }
    }

    if (off + 4 <= n && memcmp(buf + off, "RENDER", 4) == 0) {
        path_hit("studio_export_timeline");
        /* final export gate */
        if (off + 8 <= n && buf[off + 4] == 0xDE && buf[off + 5] == 0xAD) {
            path_hit("studio_export_deadbeef");
            volatile char *q = (volatile char *)0;
            *q = 'R';
        }
    }
    path_hit("studio_compose_ok");
    return 0;
}

static int open_track(const unsigned char *fourcc, const unsigned char *data, uint32_t len)
{
    path_hit("open_track");
    if (memcmp(fourcc, "PCM ", 4) == 0 || memcmp(fourcc, "PCM\0", 4) == 0)
        return decode_pcm(data, len);
    if (memcmp(fourcc, "MAD ", 4) == 0 || memcmp(fourcc, "MAD\0", 4) == 0)
        return decode_mad(data, len);
    if (memcmp(fourcc, "VID ", 4) == 0 || memcmp(fourcc, "VID\0", 4) == 0)
        return decode_vid(data, len);
    if (memcmp(fourcc, "META", 4) == 0)
        return apply_meta(data, len);
    path_hit("open_track_unknown");
    return 0;
}

static int parse_catalog(const unsigned char *buf, size_t n, size_t *off)
{
    path_hit("parse_catalog");
    if (*off + 2 > n)
        return -1;
    uint16_t tracks = rd_u16(buf + *off);
    *off += 2;
    if (tracks > 64)
        tracks = 64;

    for (uint16_t t = 0; t < tracks; t++) {
        path_hit("parse_catalog_track");
        if (*off + 12 > n)
            return -1;
        unsigned char fourcc[4];
        memcpy(fourcc, buf + *off, 4);
        *off += 4;
        uint32_t rate = rd_u32(buf + *off);
        *off += 4;
        uint32_t dlen = rd_u32(buf + *off);
        *off += 4;
        (void)rate;
        if (*off + dlen > n)
            return -1;
        open_track(fourcc, buf + *off, dlen);
        *off += dlen;
    }
    path_hit("parse_catalog_ok");
    return 0;
}

static int load_container(const unsigned char *buf, size_t n)
{
    path_hit("load_container");
    size_t off = 0;
    uint16_t flags = 0;
    char title[128];
    int rc = parse_header(buf, n, &off, &flags, title, sizeof(title));
    if (rc != 0) {
        path_hit("load_container_bad_header");
        return rc;
    }
    fprintf(stderr, "reeldeck: title='%s' flags=0x%04x\n", title, flags);

    rc = parse_catalog(buf, n, &off);
    if (rc != 0)
        return rc;

    if (flags & FLAG_PLAYLIST) {
        path_hit("playlist_mode");
        /* playlist appendix: count + indices */
        if (off + 2 <= n) {
            uint16_t items = rd_u16(buf + off);
            off += 2;
            for (uint16_t i = 0; i < items && off + 2 <= n; i++) {
                path_hit("playlist_item");
                off += 2;
            }
        }
    }

    if (flags & FLAG_STUDIO)
        studio_compose(buf, n, off);

    path_hit("load_container_ok");
    return 0;
}

static unsigned char *read_file(const char *path, size_t *out_n)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    unsigned char *buf = (unsigned char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *out_n = n;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.rndl>\n", argv[0]);
        return 2;
    }

    const char *plog = getenv("REELDECK_PATHLOG");
    if (plog && *plog) {
        snprintf(g_pathlog, sizeof(g_pathlog), "%s", plog);
        g_traced = 1;
        /* truncate previous */
        FILE *f = fopen(g_pathlog, "w");
        if (f)
            fclose(f);
    }

    path_hit("main");
    size_t n = 0;
    unsigned char *buf = read_file(argv[1], &n);
    if (!buf) {
        fprintf(stderr, "reeldeck: cannot read %s\n", argv[1]);
        return 2;
    }
    path_hit("main_loaded");
    int rc = load_container(buf, n);
    free(buf);
    path_hit("main_done");
    return rc == 0 ? 0 : 1;
}
