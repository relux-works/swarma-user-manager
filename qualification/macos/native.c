// Bounded workloads, built and executed only on hosted qualification runners.
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <mach/mach.h>

// Volatile writes make page touching observable even under -O2.
static void touch(void *p, size_t bytes) {
    volatile unsigned char *v = p;
    for (size_t i = 0; i < bytes; i += 4096) v[i] = (unsigned char)(i / 4096 + 1);
    v[bytes - 1] = 0xa5;
}

static double now(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
static int limit(int resource, rlim_t n) {
    struct rlimit r = {n, n};
    if (setrlimit(resource, &r)) {
        printf("{\"setrlimit_errno\":%d}\n", errno); return -1;
    }
    return 0;
}
static int memory(const char *kind) {
    if (!strcmp(kind, "as-headroom")) {
        struct mach_task_basic_info info;
        mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
        if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) != KERN_SUCCESS) return 2;
        if (limit(RLIMIT_AS, info.virtual_size + (128ULL << 20))) return 2;
        printf("{\"baseline_virtual_bytes\":%llu,\"limit_bytes\":%llu,", (unsigned long long)info.virtual_size,
               (unsigned long long)info.virtual_size + (128ULL << 20));
    }
    if (!strcmp(kind, "as") && limit(RLIMIT_AS, 128ULL << 20)) return 2;
    if (!strcmp(kind, "data") && limit(RLIMIT_DATA, 128ULL << 20)) return 2;
    const size_t step = 16ULL << 20;
    size_t total = 0; int error = 0;
    void *chunks[64];
    for (int i = 0; i < 64; ++i) {
        chunks[i] = malloc(step);
        if (!chunks[i]) { error = errno; break; }
        touch(chunks[i], step); total += step;
    }
    printf("%s\"bytes\":%zu,\"errno\":%d,\"bound_bytes\":1073741824}\n",
           !strcmp(kind, "as-headroom") ? "" : "{", total, error);
    return 0;
}
static int nproc(int n) {
    if (n && limit(RLIMIT_NPROC, n)) return 2;
    pid_t children[100]; int count = 0, error = 0;
    for (int i = 0; i < 100; ++i) {
        pid_t p = fork();
        if (p < 0) { error = errno; break; }
        if (!p) { sleep(10); _exit(0); }
        children[count++] = p;
    }
    printf("{\"children\":%d,\"errno\":%d,\"limit\":%d,\"attempts\":100}\n", count, error, n);
    for (int i = 0; i < count; ++i) kill(children[i], SIGKILL);
    for (int i = 0; i < count; ++i) waitpid(children[i], NULL, 0);
    return 0;
}
static volatile uint64_t sink;
static void bench(uint64_t iterations) {
    uint64_t x = 7;
    for (uint64_t i = 0; i < iterations; ++i) x = x * 6364136223846793005ULL + 1;
    sink = x;
}
int main(int argc, char **argv) {
    if (argc < 2) return 64;
    if (!strcmp(argv[1], "nproc")) return nproc(argc > 2 ? atoi(argv[2]) : 0);
    if (!strcmp(argv[1], "memory")) return memory(argc > 2 ? argv[2] : "control");
    if (!strcmp(argv[1], "grow")) {
        void *chunks[60];
        for (int i = 0; i < 60; ++i) {
            chunks[i] = malloc(50ULL << 20); if (!chunks[i]) return 2;
            touch(chunks[i], 50ULL << 20);
            printf("{\"bytes\":%llu,\"time\":%.6f}\n", (unsigned long long)(i + 1) * (50ULL << 20), now());
            fflush(stdout); usleep(250000);
        }
        sleep(2); return 0;
    }
    if (!strcmp(argv[1], "cpu") || !strcmp(argv[1], "burn")) {
        if (!strcmp(argv[1], "cpu") && argc > 2 && limit(RLIMIT_CPU, 1)) return 2;
        double start = now();
        while (now() - start < 8) bench(1000000);
        printf("{\"wall_seconds\":%.6f}\n", now() - start); return 0;
    }
    if (!strcmp(argv[1], "bench")) {
        double start = now(); bench(500000000ULL);
        printf("{\"wall_seconds\":%.6f}\n", now() - start); return 0;
    }
    if (!strcmp(argv[1], "resolve")) {
        struct addrinfo *result = NULL;
        int e = getaddrinfo("www.apple.com", "443", NULL, &result);
        printf("{\"gai_error\":%d,\"resolved\":%s}\n", e, e ? "false" : "true");
        if (result) freeaddrinfo(result); return e ? 1 : 0;
    }
    if (!strcmp(argv[1], "escape")) {
        pid_t p = fork(); if (p < 0) return 2;
        if (!p) {
            if (setsid() < 0) _exit(2);
            p = fork(); if (p < 0) _exit(2);
            if (p) _exit(0);
            sleep(30); _exit(0);
        }
        waitpid(p, NULL, 0); return 0;
    }
    if (!strcmp(argv[1], "groups")) {
        gid_t groups[256]; int n = getgroups(256, groups);
        if (n < 0) return 2;
        printf("{\"effective_groups\":[");
        for (int i = 0; i < n; ++i) printf("%s%u", i ? "," : "", groups[i]);
        printf("]}\n"); return 0;
    }
    return 64;
}
