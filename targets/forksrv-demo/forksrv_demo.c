/*
 * Minimal AFL classic forkserver demo for Randfuzz.
 * Speaks FORKSRV_FD (198/199). Processes the file in argv[1]; crashes if it contains '!'.
 * FOR AUTHORIZED LOCAL LAB USE ONLY.
 */
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FORKSRV_FD 198

static void run_case(const char *path)
{
    unsigned char buf[4096];
    FILE *f = fopen(path, "rb");
    if (!f)
        _exit(2);
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '!') {
            /* deliberate SIGSEGV for the fuzzer to harvest */
            volatile int *p = (volatile int *)0;
            *p = 1;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    unsigned char hello[4] = {0, 0, 0, 0};
    if (write(FORKSRV_FD + 1, hello, 4) != 4) {
        /* Not under a forkserver — single-shot for manual testing. */
        run_case(argv[1]);
        return 0;
    }

    while (1) {
        unsigned int was_killed = 0;
        if (read(FORKSRV_FD, &was_killed, 4) != 4)
            _exit(1);

        pid_t child = fork();
        if (child < 0)
            _exit(1);

        if (child == 0) {
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            run_case(argv[1]);
            _exit(0);
        }

        if (write(FORKSRV_FD + 1, &child, 4) != 4)
            _exit(1);

        int status = 0;
        if (waitpid(child, &status, 0) < 0)
            _exit(1);

        if (write(FORKSRV_FD + 1, &status, 4) != 4)
            _exit(1);
    }
}
