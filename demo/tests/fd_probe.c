/* Unprivileged offline fixture: descriptor/plan pipeline, never a root executor. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    if (getuid() == 0 || geteuid() == 0) return 90;
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return 91;
    int probe = dirfd(dir);
    struct dirent *item;
    while ((item = readdir(dir))) {
        char *end;
        long fd = strtol(item->d_name, &end, 10);
        if (*item->d_name && !*end && fd > 3 && fd != probe) { closedir(dir); return 92; }
    }
    closedir(dir);
    if ((fcntl(3, F_GETFL) & O_ACCMODE) != O_RDONLY) return 93;
    int seals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (fcntl(3, F_GET_SEALS) != seals) return 94;
    size_t count = 0;
    unsigned char buffer[4096];
    ssize_t n;
    while ((n = read(3, buffer, sizeof buffer)) > 0) {
        for (ssize_t i = 0; i < n; i++) if (buffer[i] != (unsigned char)((count + (size_t)i) % 256)) return 95;
        count += (size_t)n;
    }
    if (n < 0 || count != 48 * 1024) return 96;
    if (printf("{\"plan_bytes\":%zu,\"inherited_fds\":[0,1,2,3],\"scope\":\"unprivileged fixture\"}\n", count) < 0) return 97;
    return 0;
}
