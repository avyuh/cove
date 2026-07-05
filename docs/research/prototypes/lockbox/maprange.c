#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *m) {
    fprintf(stderr, "%s: %s\n", m, strerror(errno));
    exit(111);
}

static int run(const char *tool, pid_t pid, const char *kind) {
    char p[32];
    snprintf(p, sizeof(p), "%d", pid);
    pid_t c = fork();
    if (c < 0) die("fork helper");
    if (c == 0) {
        execl(tool, tool, p, "0", "100000", "65536", NULL);
        die(tool);
    }
    int st;
    waitpid(c, &st, 0);
    printf("%s exit=%d\n", kind, WIFEXITED(st) ? WEXITSTATUS(st) : 255);
    return st;
}

int main(void) {
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) die("pipe");
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        close(ready[0]);
        close(go[1]);
        if (unshare(CLONE_NEWUSER)) die("child unshare user");
        int fd = open("/proc/self/uid_map", O_WRONLY);
        if (fd < 0) {
            printf("direct uid_map open failed: %s\n", strerror(errno));
        } else {
            const char *range = "0 100000 65536\n";
            ssize_t n = write(fd, range, strlen(range));
            printf("direct uid_map range write=%zd errno=%s\n", n, n < 0 ? strerror(errno) : "none");
            close(fd);
        }
        fflush(stdout);
        char b = 'x';
        if (write(ready[1], &b, 1) != 1) die("ready write");
        if (read(go[0], &b, 1) != 1) die("go read");
        execl("/bin/sh", "sh", "-c", "id; echo uid_map; cat /proc/self/uid_map; echo gid_map; cat /proc/self/gid_map", NULL);
        die("exec sh");
    }
    close(ready[1]);
    close(go[0]);
    char b;
    if (read(ready[0], &b, 1) != 1) die("ready read");
    int st1 = run("/usr/bin/newuidmap", pid, "newuidmap");
    int st2 = run("/usr/bin/newgidmap", pid, "newgidmap");
    if (write(go[1], "x", 1) != 1) die("go write");
    int st;
    waitpid(pid, &st, 0);
    return (st1 || st2 || st) ? 1 : 0;
}
