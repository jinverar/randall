/*
 * Randfuzz Linux FORKSRV helper — owns posix_spawn + FORKSRV_FD (198/199) so the
 * managed host never forks. Protocol on stdin/stdout (little-endian):
 *
 *   → u32 payload_len | payload bytes     (writes payload to input path, then "go")
 *   ← u32 wait_status                     (child waitpid status from the forksrv)
 *
 * Startup: helper spawns the target under FORKSRV, waits for 4-byte hello, then
 * prints "READY\n" on stdout and serves the loop until stdin EOF / error.
 *
 * Usage: randall_forksrv_helper <input-path> <target-exe> [target-args...]
 */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define FORKSRV_FD 198

static int write_all(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t n)
{
    unsigned char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <input-path> <target-exe> [args...]\n", argv[0]);
        return 2;
    }

    const char *input_path = argv[1];
    char **targ = &argv[2];

    int ctl[2], st[2];
    if (pipe(ctl) != 0 || pipe(st) != 0) {
        perror("pipe");
        return 1;
    }

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&actions);
    posix_spawnattr_init(&attr);
    posix_spawn_file_actions_adddup2(&actions, ctl[0], FORKSRV_FD);
    posix_spawn_file_actions_adddup2(&actions, st[1], FORKSRV_FD + 1);
    posix_spawn_file_actions_addclose(&actions, ctl[1]);
    posix_spawn_file_actions_addclose(&actions, st[0]);
    posix_spawn_file_actions_addclose(&actions, ctl[0]);
    posix_spawn_file_actions_addclose(&actions, st[1]);

    pid_t child = 0;
    int rc = posix_spawn(&child, targ[0], &actions, &attr, targ, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    if (rc != 0) {
        fprintf(stderr, "posix_spawn: %s\n", strerror(rc));
        return 1;
    }

    close(ctl[0]);
    close(st[1]);

    unsigned char hello[4];
    if (read_all(st[0], hello, 4) != 0) {
        fprintf(stderr, "forksrv hello failed\n");
        kill(child, 9);
        return 1;
    }

    if (write_all(STDOUT_FILENO, "READY\n", 6) != 0)
        return 1;

    for (;;) {
        uint32_t len = 0;
        if (read_all(STDIN_FILENO, &len, 4) != 0)
            break;

        unsigned char *buf = NULL;
        if (len > 0) {
            if (len > 64u * 1024u * 1024u) {
                fprintf(stderr, "payload too large\n");
                break;
            }
            buf = malloc(len);
            if (!buf || read_all(STDIN_FILENO, buf, len) != 0) {
                free(buf);
                break;
            }
        }

        FILE *f = fopen(input_path, "wb");
        if (!f) {
            free(buf);
            break;
        }
        if (len && fwrite(buf, 1, len, f) != len) {
            fclose(f);
            free(buf);
            break;
        }
        fclose(f);
        free(buf);

        uint32_t go = 0;
        if (write_all(ctl[1], &go, 4) != 0)
            break;

        uint32_t cpid = 0, status = 0;
        if (read_all(st[0], &cpid, 4) != 0)
            break;
        if (read_all(st[0], &status, 4) != 0)
            break;

        if (write_all(STDOUT_FILENO, &status, 4) != 0)
            break;
    }

    close(ctl[1]);
    close(st[0]);
    kill(child, 9);
    waitpid(child, NULL, 0);
    return 0;
}
