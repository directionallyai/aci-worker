/*
 * run-cartesi-worker: boots a Cartesi machine from a JSON configuration through libcartesi's
 * C API and keeps it running until it halts. This is the cartesi-machine command line without
 * Lua: everything the command line turns into flags (the kernel, the read-only root drive, the
 * virtio network with its port forward, the boot commands) is already data in the configuration,
 * so it is passed straight to the library.
 *
 * UNATTESTED, DEV ONLY: the network device is the host user-mode network (libslirp), which makes
 * the machine unreproducible (no state hash, no stored image).
 *
 *   run-cartesi-worker CONFIG.json
 *
 * CONFIG.json is a machine configuration, for example one written by
 * `cartesi-machine ... --max-mcycle=0 --store-config=CONFIG.json`. Before it is used, every
 * "{{NOW}}" in the text is replaced with the current Unix time plus one second, so a boot command
 * such as `busybox date -s @{{NOW}}` sets the guest clock when the machine starts and not when
 * the file was written (a wrong clock breaks signed requests and TLS: a guest at the epoch fails
 * every TLS handshake with "certificate is not yet valid").
 *
 * Guest console output goes to stdout. SIGINT and SIGTERM stop the machine between slices of
 * cycles. Exit status: the guest's own exit code if it halted, 1 on a library error, 2 on usage,
 * 130 when stopped by a signal.
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cm.h"

#define SLICE_MCYCLES (UINT64_C(1) << 27) /* about a second of emulation; bounds signal latency */

static volatile sig_atomic_t g_stop;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static char *read_file(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    for (;;) {
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (len < cap) break; /* end of file or read error */
        cap *= 2;
        char *bigger = realloc(buf, cap + 1);
        if (!bigger) {
            free(buf);
            fclose(f);
            return NULL;
        }
        buf = bigger;
    }
    int failed = ferror(f);
    fclose(f);
    if (failed) {
        fprintf(stderr, "error reading %s\n", path);
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    if (length) *length = len;
    return buf;
}

/* Returns a newly allocated copy of text with every occurrence of needle replaced by with. */
static char *replace_all(const char *text, const char *needle, const char *with) {
    size_t nlen = strlen(needle), wlen = strlen(with), count = 0;
    for (const char *p = text; (p = strstr(p, needle)); p += nlen) count++;
    char *out = malloc(strlen(text) + count * (wlen > nlen ? wlen - nlen : 0) + 1);
    if (!out) return NULL;
    char *w = out;
    const char *p = text, *hit;
    while ((hit = strstr(p, needle))) {
        memcpy(w, p, (size_t)(hit - p));
        w += hit - p;
        memcpy(w, with, wlen);
        w += wlen;
        p = hit + nlen;
    }
    strcpy(w, p);
    return out;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s CONFIG.json\n", argv[0]);
        return 2;
    }
    char *config = read_file(argv[1], NULL);
    if (!config) return 1;
    char now[32];
    snprintf(now, sizeof now, "%lld", (long long)time(NULL) + 1);
    char *expanded = replace_all(config, "{{NOW}}", now);
    free(config);
    if (!expanded) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    cm_machine *machine = NULL;
    if (cm_create_new(expanded, NULL, NULL, &machine) != CM_ERROR_OK) {
        fprintf(stderr, "could not create the machine: %s\n", cm_get_last_error_message());
        free(expanded);
        return 1;
    }
    free(expanded);
    uint64_t version = cm_get_version(); /* major * 1000000 + minor * 1000 + patch */
    fprintf(stderr, "run-cartesi-worker: machine created (libcartesi %llu.%llu.%llu)\n",
        (unsigned long long)(version / 1000000), (unsigned long long)((version / 1000) % 1000),
        (unsigned long long)(version % 1000));

#ifdef _WIN32 /* no sigaction; signal() covers Ctrl-C (SIGINT) and SIGTERM */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
#endif

    int status = 0;
    for (;;) {
        uint64_t mcycle = 0;
        if (cm_read_reg(machine, CM_REG_MCYCLE, &mcycle) != CM_ERROR_OK) {
            fprintf(stderr, "could not read mcycle: %s\n", cm_get_last_error_message());
            status = 1;
            break;
        }
        uint64_t target = mcycle > UINT64_MAX - SLICE_MCYCLES ? UINT64_MAX : mcycle + SLICE_MCYCLES;
        cm_break_reason reason = CM_BREAK_REASON_FAILED;
        if (cm_run(machine, target, &reason) != CM_ERROR_OK || reason == CM_BREAK_REASON_FAILED) {
            fprintf(stderr, "the machine failed: %s\n", cm_get_last_error_message());
            status = 1;
            break;
        }
        if (reason == CM_BREAK_REASON_HALTED) {
            uint64_t data = 0;
            cm_read_reg(machine, CM_REG_HTIF_TOHOST_DATA, &data);
            status = (int)((data >> 1) & 0xff);
            cm_read_reg(machine, CM_REG_MCYCLE, &mcycle);
            fprintf(stderr, "run-cartesi-worker: the machine halted at mcycle %llu with exit code %d\n",
                (unsigned long long)mcycle, status);
            break;
        }
        if (reason == CM_BREAK_REASON_MCYCLE_OVERFLOW) {
            fprintf(stderr, "the machine's cycle counter overflowed\n");
            status = 1;
            break;
        }
        /* Reached the target cycle, or a yield or console break the configuration does not use:
         * keep going. */
        if (g_stop) {
            fprintf(stderr, "run-cartesi-worker: stopped by signal\n");
            status = 130;
            break;
        }
    }
    cm_delete(machine);
    return status;
}
