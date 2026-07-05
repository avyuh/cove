#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/limits.h>
#include <net/if.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (errno) fprintf(stderr, ": %s", strerror(errno));
    fputc('\n', stderr);
    exit(111);
}

static void xwrite_file(const char *path, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof(buf)) die("format overflow for %s", path);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) die("open %s", path);
    if (write(fd, buf, n) != n) die("write %s", path);
    close(fd);
}

static void mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) && errno != EEXIST) die("mkdir %s", tmp);
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) && errno != EEXIST) die("mkdir %s", tmp);
}

static void bind_ro(const char *src, const char *dst) {
    mkdir_p(dst, 0755);
    if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL)) die("bind %s -> %s", src, dst);
    if (mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_REC, NULL))
        die("remount ro %s", dst);
}

static void write_text(const char *path, const char *text, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) die("create %s", path);
    size_t len = strlen(text);
    if (write(fd, text, len) != (ssize_t)len) die("write %s", path);
    close(fd);
}

static void setup_userns(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER)) die("unshare(CLONE_NEWUSER)");
    xwrite_file("/proc/self/setgroups", "deny\n");
    xwrite_file("/proc/self/uid_map", "0 %d 1\n", uid);
    xwrite_file("/proc/self/gid_map", "0 %d 1\n", gid);
    if (setresgid(0, 0, 0)) die("setresgid");
    if (setresuid(0, 0, 0)) die("setresuid");
}

static void setup_netns(void) {
    if (unshare(CLONE_NEWNET)) die("unshare(CLONE_NEWNET)");
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) die("socket for lo ioctl");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "lo");
    if (ioctl(fd, SIOCGIFFLAGS, &ifr)) die("SIOCGIFFLAGS lo");
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr)) die("SIOCSIFFLAGS lo up");
    close(fd);
}

static void mask_path(const char *path) {
    struct stat st;
    if (lstat(path, &st)) return;
    if (S_ISDIR(st.st_mode)) {
        if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k,mode=0700"))
            die("tmpfs mask %s", path);
    } else {
        if (mount("/dev/null", path, NULL, MS_BIND, NULL)) die("file mask %s", path);
    }
}

static void setup_mask(const char *bait) {
    if (unshare(CLONE_NEWNS)) die("unshare(CLONE_NEWNS)");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("make / private");
    const char *home = getenv("HOME");
    char p[PATH_MAX];
    if (home) {
        const char *rel[] = {".ssh", ".aws", ".claude", ".config/gh", ".config/github-copilot", ".mozilla", ".config/google-chrome", NULL};
        for (int i = 0; rel[i]; i++) {
            snprintf(p, sizeof(p), "%s/%s", home, rel[i]);
            mask_path(p);
        }
    }
    if (bait) mask_path(bait);
}

static void setup_deny(const char *project, const char *proxy) {
    if (unshare(CLONE_NEWNS)) die("unshare(CLONE_NEWNS)");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) die("make / private");

    char root[] = "/tmp/lockbox-root.XXXXXX";
    if (!mkdtemp(root)) die("mkdtemp");
    if (mount("tmpfs", root, "tmpfs", MS_NOSUID | MS_NODEV, "size=64m,mode=0755")) die("tmpfs new root");

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/usr", root);
    bind_ro("/usr", path);

    snprintf(path, sizeof(path), "%s/bin", root);
    if (symlink("usr/bin", path) && errno != EEXIST) die("symlink /bin");
    snprintf(path, sizeof(path), "%s/lib", root);
    if (symlink("usr/lib", path) && errno != EEXIST) die("symlink /lib");
    snprintf(path, sizeof(path), "%s/sbin", root);
    if (symlink("usr/sbin", path) && errno != EEXIST) die("symlink /sbin");

    snprintf(path, sizeof(path), "%s/etc", root);
    mkdir_p(path, 0755);
    snprintf(path, sizeof(path), "%s/etc/passwd", root);
    write_text(path, "root:x:0:0:lockbox:/work:/bin/sh\n", 0644);
    snprintf(path, sizeof(path), "%s/etc/group", root);
    write_text(path, "root:x:0:\n", 0644);
    snprintf(path, sizeof(path), "%s/etc/resolv.conf", root);
    write_text(path, "nameserver 127.0.0.1\n", 0644);
    snprintf(path, sizeof(path), "%s/etc/hosts", root);
    write_text(path, "127.0.0.1 localhost\n", 0644);

    snprintf(path, sizeof(path), "%s/proc", root);
    mkdir_p(path, 0555);
    if (mount("proc", path, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
        fprintf(stderr, "lockbox: warning: proc mount skipped: %s\n", strerror(errno));

    snprintf(path, sizeof(path), "%s/tmp", root);
    mkdir_p(path, 01777);
    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV, "size=64m,mode=1777")) die("tmpfs /tmp");

    snprintf(path, sizeof(path), "%s/dev", root);
    mkdir_p(path, 0755);
    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NOEXEC, "size=4m,mode=0755")) die("tmpfs /dev");
    const char *devs[] = {"null", "zero", "random", "urandom", NULL};
    for (int i = 0; devs[i]; i++) {
        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, sizeof(src), "/dev/%s", devs[i]);
        snprintf(dst, sizeof(dst), "%s/dev/%s", root, devs[i]);
        int fd = open(dst, O_CREAT | O_RDONLY, 0666);
        if (fd >= 0) close(fd);
        if (mount(src, dst, NULL, MS_BIND, NULL)) die("bind %s", src);
    }

    snprintf(path, sizeof(path), "%s/work", root);
    mkdir_p(path, 0755);
    if (project) bind_ro(project, path);

    if (proxy) {
        snprintf(path, sizeof(path), "%s/proxy", root);
        mkdir_p(path, 0755);
        char dst[PATH_MAX];
        snprintf(dst, sizeof(dst), "%s/proxy/proxy.sock", root);
        int fd = open(dst, O_CREAT | O_RDONLY, 0600);
        if (fd >= 0) close(fd);
        if (mount(proxy, dst, NULL, MS_BIND, NULL)) die("bind proxy socket");
    }

    if (chdir(root)) die("chdir new root");
    if (chroot(".")) die("chroot");
    if (chdir("/")) die("chdir /");
}

static void usage(void) {
    fprintf(stderr, "usage: lockbox --mode deny|mask [--project PATH] [--proxy-sock PATH] [--bait PATH] -- command ...\n");
    exit(2);
}

int main(int argc, char **argv) {
    const char *mode = "deny", *project = NULL, *proxy = NULL, *bait = NULL;
    int cmd = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { cmd = i + 1; break; }
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--project") && i + 1 < argc) project = argv[++i];
        else if (!strcmp(argv[i], "--proxy-sock") && i + 1 < argc) proxy = argv[++i];
        else if (!strcmp(argv[i], "--bait") && i + 1 < argc) bait = argv[++i];
        else usage();
    }
    if (cmd < 0 || cmd >= argc) usage();

    setup_userns();
    if (!strcmp(mode, "deny")) setup_deny(project ? project : ".", proxy);
    else if (!strcmp(mode, "mask")) setup_mask(bait);
    else usage();
    setup_netns();

    fprintf(stderr, "lockbox: uid=%d gid=%d mode=%s netns=isolated\n", getuid(), getgid(), mode);
    execvp(argv[cmd], &argv[cmd]);
    die("exec %s", argv[cmd]);
}
