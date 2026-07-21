/*
 * Randall VulnLab — a deliberately vulnerable Linux TCP service for authorized fuzzing / exploit
 * practice. FOR AUTHORIZED LOCAL LAB USE ONLY.
 *
 * One simple line protocol, several classic memory-safety bugs spanning basic -> advanced:
 *   ECHO <data>   stack buffer overflow (strcpy into a 64-byte stack buffer)   [basic]
 *   FMT  <data>   format-string bug (printf(user))                             [intermediate]
 *   HEAP <data>   heap buffer overflow (strcpy into malloc(32))                [intermediate]
 *   DFREE         tcache double-free                                           [advanced]
 *   HELP          list commands
 *
 * Build it at several exploit-mitigation tiers with scripts/build-mitigation-lab.sh so the same
 * bugs can be practised from "no mitigations" up to canary+NX+PIE(ASLR)+RELRO+FORTIFY.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static const char *BANNER =
    "Randall VulnLab — authorized practice only.\r\n"
    "Commands: ECHO <d> | FMT <d> | HEAP <d> | DFREE | HELP\r\n";

/* [basic] Classic stack smash: unbounded strcpy into a fixed stack buffer. */
static void do_echo(const char *arg) {
    char buf[64];
    strcpy(buf, arg);            /* overflow past 64 bytes clobbers saved RIP */
    printf("ECHO: %s\n", buf);
}

/* [intermediate] Format-string bug: user data used as the format. */
static void do_fmt(const char *arg) {
    printf(arg);                 /* %n / %s / %p primitives */
    printf("\n");
}

/* [intermediate] Heap overflow: strcpy into an undersized heap chunk. */
static void do_heap(const char *arg) {
    char *p = malloc(32);
    strcpy(p, arg);              /* overflow smashes adjacent chunk metadata */
    printf("HEAP: %s\n", p);
    free(p);
}

/* [advanced] tcache double-free. */
static void do_dfree(void) {
    char *p = malloc(32);
    free(p);
    free(p);                     /* glibc: "free(): double free detected in tcache 2" */
    printf("DFREE done\n");
}

static void dispatch(char *line) {
    if (strncmp(line, "ECHO ", 5) == 0)      do_echo(line + 5);
    else if (strncmp(line, "FMT ", 4) == 0)  do_fmt(line + 4);
    else if (strncmp(line, "HEAP ", 5) == 0) do_heap(line + 5);
    else if (strncmp(line, "DFREE", 5) == 0) do_dfree();
    else if (strncmp(line, "HELP", 4) == 0)  { /* fallthrough to banner below */ }
}

int main(int argc, char **argv) {
    int port = 9999;
    const char *host = "127.0.0.1";
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) && i + 1 < argc) port = atoi(argv[++i]);
        else if ((!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")) && i + 1 < argc) host = argv[++i];
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    listen(srv, 16);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Randall VulnLab listening on %s:%d\n", host, port);

    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        send(c, BANNER, strlen(BANNER), 0);
        char in[8192];
        ssize_t n = recv(c, in, sizeof(in) - 1, 0);
        if (n > 0) {
            in[n] = '\0';
            /* strip trailing CR/LF */
            while (n > 0 && (in[n - 1] == '\n' || in[n - 1] == '\r')) in[--n] = '\0';
            dispatch(in);
            send(c, BANNER, strlen(BANNER), 0);
        }
        close(c);
    }
}
