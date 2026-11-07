/* Fixed demonstration executor. No plan interpretation, Curator, shell or network. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argv;
    uid_t r, e, s;
    gid_t gr, ge, gs;
    if (argc != 1 || getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) ||
        r < 30000 || r > 30019 || r != e || r != s || gr != r || ge != r || gs != r ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 71;
    const char *name = getenv("USER");
    if (!name || (strcmp(name, "swarma-demo-01") && strcmp(name, "swarma-demo-02") && strcmp(name, "swarma-demo-03"))) return 72;
    /* Check the complete inherited descriptor set, not just a low FD sample. */
    int probe = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (probe < 0) return 73;
    /* Linux close_range is used by the launcher; verify via getdents using fdopendir. */
    DIR *dir = fdopendir(probe);
    if (!dir) { close(probe); return 73; }
    struct dirent *item;
    bool fds_ok = true;
    errno = 0;
    while ((item = readdir(dir))) {
        char *end = NULL;
        long fd = strtol(item->d_name, &end, 10);
        if (*item->d_name && !*end && fd > 3 && fd != probe) fds_ok = false;
    }
    if (errno) fds_ok = false;
    closedir(dir);
    if (!fds_ok || (fcntl(3, F_GETFL) & O_ACCMODE) != O_RDONLY) return 74;
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fcntl(3, F_GET_SEALS) != required) return 75;
    char data[4096];
    size_t count = 0;
    ssize_t n;
    while ((n = read(3, data, sizeof data)) > 0) {
        count += (size_t)n;
        if (count > 48 * 1024) return 76;
    }
    if (n < 0 || close(3)) return 77;
    char workspace[128];
    int len = snprintf(workspace, sizeof workspace, "/srv/swarma-demo/work/%s", name);
    if (len < 0 || (size_t)len >= sizeof workspace) return 78;
    int root = open(workspace, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (root < 0 || fstat(root, &info) || info.st_uid != r || info.st_gid != r || (info.st_mode & 07777) != 0700) return 79;
    int fd = openat(root, "identity-witness.json", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    close(root);
    if (fd < 0) return 80;
    struct timespec mono;
    struct tm tm;
    time_t wall = time(NULL);
    char stamp[32];
    if (!gmtime_r(&wall, &tm) || !strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", &tm) || clock_gettime(CLOCK_MONOTONIC, &mono)) { close(fd); return 81; }
    char record[1024];
    len = snprintf(record, sizeof record,
        "{\"executor\":\"swarma-demo-executor\",\"curator_qualified\":false,"
        "\"pid\":%ld,\"uid\":%lu,\"euid\":%lu,\"suid\":%lu,"
        "\"gid\":%lu,\"egid\":%lu,\"sgid\":%lu,\"groups\":[],"
        "\"inherited_fds\":[0,1,2,3],\"plan_bytes\":%zu,"
        "\"at\":\"%s\",\"monotonic_seconds\":%lld.%09ld}\n",
        (long)getpid(), (unsigned long)r, (unsigned long)e, (unsigned long)s,
        (unsigned long)gr, (unsigned long)ge, (unsigned long)gs,
        count, stamp, (long long)mono.tv_sec, mono.tv_nsec);
    if (len < 0 || (size_t)len >= sizeof record) { close(fd); return 82; }
    size_t off = 0;
    while (off < (size_t)len) {
        n = write(fd, record + off, (size_t)len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return 83; }
        off += (size_t)n;
    }
    if (fsync(fd) || close(fd)) return 84;
    /* The operator reads the witness; the dispatcher must explicitly stop us. */
    for (;;) pause();
}
