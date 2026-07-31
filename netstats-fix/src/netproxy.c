#define _GNU_SOURCE
#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__arm__)
#define __NR_bpf 364
#else
#define __NR_bpf 321
#endif
#endif

#ifndef __NR_init_module
#if defined(__aarch64__)
#define __NR_init_module 105
#elif defined(__arm__)
#define __NR_init_module 128
#else
#define __NR_init_module 175
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/mount.h>

#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>

#define LOGFILE "/data/local/tmp/netproxy.log"
#define STATSFILE "/data/local/tmp/netproxy_stats"
#define STATSFILE_DEV "/data/local/tmp/netproxy_dev"
#define STATSFILE_UID_FILE "/data/local/tmp/netproxy_uid"
#define REGFILE "/data/local/tmp/netproxy_registered"
#define NETPROXY_VERSION "10.1"
#define SESSION_BASE 0x20000
#define MAX_SESSIONS 64
#define MAX_IFACES 64
#define BINDER_MMAP_SIZE (8 * 1024 * 1024)
#define BINDER_BUF_SIZE  (512 * 1024)
#define BPF_MAX_MAP_SIZE (512 * 1024)

/* ============================================================
 * Binder protocol constants
 * ============================================================ */
#define BINDER_PTR_SZ 8

#define BR_OK                   0x00007201
#define BR_TRANSACTION_COMPLETE 0x00007206
#define BR_TRANSACTION          0x80407202
#define BR_REPLY                0x80407203
#define BR_ACQUIRE_RESULT       0x40047204
#define BR_DEAD_REPLY           0x00007205
#define BR_INCREFS              0x80107207
#define BR_ACQUIRE              0x80107208
#define BR_RELEASE              0x80107209
#define BR_DECREFS              0x8010720A
#define BR_ATTEMPT_ACQUIRE      0x8020720B
#define BR_NOOP                 0x0000720C
#define BR_SPAWN_LOOPER         0x0000720D
#define BR_FINISHED             0x0000720E
#define BR_DEAD_BINDER          0x8008720F
#define BR_CLEAR_DEATH_NOTIFICATION_DONE 0x80087210
#define BR_FAILED_REPLY         0x00007211
#define BR_FROZEN_REPLY         0x00007212
#define BR_ONEWAY_SPAM_SUSPECT  0x00007213
#define BR_TRANSACTION_PENDING_FROZEN 0x00007214
#define BR_ERROR                0x40047200

#define BC_TRANSACTION          0x40406300
#define BC_REPLY                0x40416301
#define BC_ACQUIRE_RESULT       0x40046302
#define BC_FREE_BUFFER          0x40086303
#define BC_INCREFS              0x40046304
#define BC_ACQUIRE              0x40046305
#define BC_RELEASE              0x40046306
#define BC_DECREFS              0x40046307
#define BC_INCREFS_DONE         0x80106308
#define BC_ACQUIRE_DONE         0x80106309
#define BC_ATTEMPT_ACQUIRE      0x400c630a
#define BC_REGISTER_LOOPER      0x0000630b
#define BC_ENTER_LOOPER         0x0000630c
#define BC_EXIT_LOOPER          0x0000630d
#define BC_REQUEST_DEATH_NOTIFICATION 0x4008630e
#define BC_CLEAR_DEATH_NOTIFICATION 0x4008630f
#define BC_DEAD_BINDER_DONE     0x40086310
#define BC_TRANSACTION_SG       0x40446311
#define BC_REPLY_SG             0x40446312

#define TF_ACCEPT_FDS   0x10
#define TF_STATUS_CODE  0x08
#define TF_ONE_WAY      0x01

#define BINDER_TYPE_BINDER 0x85627473
#define BINDER_TYPE_HANDLE 0x85617473
#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100

#define SM_HANDLE 0

/* ============================================================
 * AIDL transaction codes - INetworkStatsService (Android 14+)
 * Updated for Android 16 (Baklava)
 * ============================================================ */
#define TX_openSession                  1
#define TX_openSessionForUsageStats     2
#define TX_getDataLayerSnapshotForUid   3
#define TX_getUidStats                  4
#define TX_getIfaceStats                5
#define TX_getMobileIfaces              6
#define TX_incrementOperationCount      7
#define TX_notifyNetworkStatus          8
#define TX_forceUpdate                  9
#define TX_registerUsageCallback        10
#define TX_unregisterUsageRequest       11
#define TX_getTotalStats                12
#define TX_registerNetworkStatsProvider 13
#define TX_noteUidForeground            14
#define TX_advisePersistThreshold       15
#define TX_setStatsProviderWarningAndLimitAsync 16
#define TX_getUidStatsForTransport      17
#define TX_getRateLimitCacheConfig      18

/* INetworkStatsSession */
#define SESS_getDeviceSummaryForNetwork   1
#define SESS_getSummaryForNetwork         2
#define SESS_getHistoryForNetwork         3
#define SESS_getHistoryIntervalForNetwork 4
#define SESS_getSummaryForAllUid          5
#define SESS_getTaggedSummaryForAllUid    6
#define SESS_getHistoryForUid             7
#define SESS_getHistoryIntervalForUid     8
#define SESS_getRelevantUids              9
#define SESS_close                        10
#define SESS_getDeviceSummaryForNetworkWithMetered 11
#define SESS_getSummaryForNetworkWithMetered       12

/* Standard AIDL codes */
#define TX_GET_INTERFACE_VERSION 16777215
#define TX_GET_INTERFACE_HASH    16777216

/* Legacy/fallback codes for patched GSIs */
#define TX_LEGACY_GET_TOTAL_STATS   10001
#define TX_LEGACY_GET_IFACE_STATS   10002
#define TX_LEGACY_FORCE_UPDATE      10003
#define TX_LEGACY_GET_UID_STATS     10004

/* ============================================================
 * Types
 * ============================================================ */
typedef uint64_t binder_uintptr_t;
typedef uint64_t binder_size_t;

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_version {
    int32_t protocol_version;
};

struct flat_binder_object {
    uint32_t hdr_type;
    uint32_t flags;
    uint64_t binder;
    uint64_t cookie;
};

struct binder_transaction_data {
    union { uint32_t handle; uint64_t ptr; } target;
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    union {
        struct { uint64_t buffer; uint64_t offsets; } ptr;
        uint8_t buf[8];
    } data;
};

struct iface_stat {
    char name[96];
    uint64_t rxBytes, rxPackets, txBytes, txPackets;
    int has_data;
};

#define BINDER_WRITE_READ        0xC0306201
#define BINDER_VERSION           0xC0046209
#define BINDER_SET_MAX_THREADS   0x40086205

/* ============================================================
 * Logging
 * ============================================================ */
static FILE* log_fp = NULL;
static int log_line_count = 0;
static time_t g_start_time = 0;

static void log_open(void) {
    if (!log_fp) {
        log_fp = fopen(LOGFILE, "a");
        if (log_fp) setbuf(log_fp, NULL);
    }
}

__attribute__((format(printf,1,2)))
static void log_msg(const char* fmt, ...) {
    log_open();
    if (!log_fp) return;
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    char ts[64] = "1970-01-01 00:00:00";
    if (tm_info) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(log_fp, "%s [NETPROXY-v9] %s\n", ts, buf);
    log_line_count++;
    if (log_line_count % 1000 == 0) {
        fprintf(log_fp, "%s [NETPROXY-v9] --- LOG_ROLLOVER count=%d ---\n", ts, log_line_count);
    }
}

static void log_errno(const char* ctx) {
    log_msg("ERROR %s: errno=%d (%s)", ctx, errno, strerror(errno));
}

static void log_hex(const char* label, const uint8_t* data, uint32_t len) {
    char buf[4096];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "%s (%u bytes):", label, len);
    uint32_t dump_len = len > 128 ? 128 : len;
    for (uint32_t i = 0; i < dump_len && pos < (int)sizeof(buf) - 16; i++) {
        if (i % 16 == 0) pos += snprintf(buf + pos, sizeof(buf) - pos, "\n  ");
        else if (i % 8 == 0) pos += snprintf(buf + pos, sizeof(buf) - pos, " ");
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%02x ", data[i]);
    }
    if (len > 128) pos += snprintf(buf + pos, sizeof(buf) - pos, "\n  ... (%u more bytes)", len - 128);
    log_msg("%s", buf);
}

/* ============================================================
 * /proc/net/dev reader
 * ============================================================ */
struct net_stats { uint64_t rxBytes, rxPackets, txBytes, txPackets; };
static struct net_stats g_prev_stats;

static int read_iface_stats(const char* iface, struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char* p = line; while (*p == ' ' || *p == '\t') p++;
        char* colon = strchr(p, ':');
        if (!colon) continue;
        size_t ilen = (size_t)(colon - p);
        if (ilen == strlen(iface) && strncmp(p, iface, ilen) == 0) {
            char* vals = colon + 1;
            int col = 0; char* saveptr;
            char* tok = strtok_r(vals, " \t\n\r", &saveptr);
            while (tok && col <= 9) {
                uint64_t v = strtoull(tok, NULL, 10);
                if      (col == 0) out->rxBytes   = v;
                else if (col == 1) out->rxPackets  = v;
                else if (col == 8) out->txBytes    = v;
                else if (col == 9) out->txPackets  = v;
                col++; tok = strtok_r(NULL, " \t\n\r", &saveptr);
            }
            fclose(f); return 0;
        }
    }
    fclose(f); return -1;
}

static int read_all_stats(struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char* p = line; while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "lo:", 3) == 0) continue;
        char* colon = strchr(p, ':');
        if (!colon) continue;
        char* vals = colon + 1; int col = 0; char* saveptr;
        char* tok = strtok_r(vals, " \t\n\r", &saveptr);
        while (tok) {
            uint64_t v = strtoull(tok, NULL, 10);
            if      (col == 0) out->rxBytes   += v;
            else if (col == 1) out->rxPackets  += v;
            else if (col == 8) out->txBytes    += v;
            else if (col == 9) out->txPackets  += v;
            col++; if (col > 9) break;
            tok = strtok_r(NULL, " \t\n\r", &saveptr);
        }
    }
    fclose(f); return 0;
}

static int read_all_ifaces(struct iface_stat* ifaces, int* count) {
    *count = 0;
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f) && *count < MAX_IFACES) {
        char* p = line; while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "lo:", 3) == 0) continue;
        char* colon = strchr(p, ':');
        if (!colon) continue;
        size_t nlen = (size_t)(colon - p);
        if (nlen >= sizeof(ifaces[*count].name)) nlen = sizeof(ifaces[*count].name) - 1;
        memcpy(ifaces[*count].name, p, nlen);
        ifaces[*count].name[nlen] = '\0';
        ifaces[*count].has_data = 0;
        char* vals = colon + 1; int col = 0; char* saveptr;
        char* tok = strtok_r(vals, " \t\n\r", &saveptr);
        while (tok && col <= 9) {
            uint64_t v = strtoull(tok, NULL, 10);
            if      (col == 0) ifaces[*count].rxBytes    = v;
            else if (col == 1) ifaces[*count].rxPackets   = v;
            else if (col == 8) ifaces[*count].txBytes    = v;
            else if (col == 9) ifaces[*count].txPackets  = v;
            col++; tok = strtok_r(NULL, " \t\n\r", &saveptr);
        }
        ifaces[*count].has_data = 1;
        (*count)++;
    }
    fclose(f); return 0;
}

static void write_stats_file(void) {
    struct iface_stat ifaces[MAX_IFACES];
    struct net_stats total;
    int count = 0;
    if (read_all_ifaces(ifaces, &count) != 0) return;
    read_all_stats(&total);

    FILE* f = fopen(STATSFILE, "w");
    if (!f) return;
    for (int i = 0; i < count; i++) {
        fprintf(f, "iface_%s_rx=%" PRIu64 "\niface_%s_tx=%" PRIu64 "\niface_%s_rxp=%" PRIu64 "\niface_%s_txp=%" PRIu64 "\n",
                ifaces[i].name, ifaces[i].rxBytes,
                ifaces[i].name, ifaces[i].txBytes,
                ifaces[i].name, ifaces[i].rxPackets,
                ifaces[i].name, ifaces[i].txPackets);
    }
    fprintf(f, "rx_bytes=%" PRIu64 "\ntx_bytes=%" PRIu64 "\nrx_packets=%" PRIu64 "\ntx_packets=%" PRIu64 "\niface_count=%d\ntimestamp=%ld\n",
            total.rxBytes, total.txBytes, total.rxPackets, total.txPackets, count, (long)time(NULL));

    /* Also write per-iface dev file */
    FILE* fd = fopen(STATSFILE_DEV, "w");
    if (fd) {
        for (int i = 0; i < count; i++) {
            fprintf(fd, "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
                    ifaces[i].name, ifaces[i].rxBytes, ifaces[i].rxPackets,
                    ifaces[i].txBytes, ifaces[i].txPackets);
        }
        fclose(fd);
        chmod(STATSFILE_DEV, 0644);
    }
    fclose(f);
    chmod(STATSFILE, 0644);
}

/* Forward declarations for functions defined later in the file */
static void write_all_stats_sources(void);
static void populate_bpf_maps(void);
static int write_bpf_stats(int uid, uint64_t rxBytes, uint64_t rxPackets,
                           uint64_t txBytes, uint64_t txPackets);
static int write_bpf_owner(int uid);
static void write_uid_stat_entry(int uid, uint64_t rx, uint64_t tx);
static void populate_uid_stat_all(void);
static void try_load_xt_qtaguid(void);
static void write_netstats_xml(void);

/* ============================================================
 * Per-UID stats tracking (approximate from /proc/net/dev)
 * We distribute total traffic proportionally among active UIDs
 * ============================================================ */
#define MAX_UID_STATS 256
static struct {
    int uid;
    uint64_t rxBytes, txBytes;
    time_t last_seen;
} g_uid_stats[MAX_UID_STATS];
static int g_uid_count = 0;

static void update_uid_stats(void) {
    struct net_stats total;
    if (read_all_stats(&total) != 0) return;

    /* Collect active UIDs from /proc/net/netfilter or just use common ones */
    int uids[32] = {1000, 1001, 1002, 1013, 1021, 1023, 1027, 1028, 1029,
                    1037, 1038, 1039, 1041, 1044, 1045, 1046, 1047, 2000,
                    2001, 9999, 0};
    int uidc = 0;
    while (uids[uidc] != 0 && uidc < 32) uidc++;

    /* Scan /proc/ for running apps to get more UIDs */
    DIR* proc = opendir("/proc");
    if (proc) {
        struct dirent* entry;
        while ((entry = readdir(proc)) && uidc < 30) {
            int pid = atoi(entry->d_name);
            if (pid <= 0) continue;
            char path[256];
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            FILE* sf = fopen(path, "r");
            if (!sf) continue;
            char sl[256];
            int found_uid = -1;
            while (fgets(sl, sizeof(sl), sf)) {
                if (strncmp(sl, "Uid:", 4) == 0) {
                    int ruid;
                    sscanf(sl, "Uid:\t%d", &ruid);
                    if (ruid >= 10000) found_uid = ruid;
                    break;
                }
            }
            fclose(sf);
            if (found_uid >= 0) {
                int dup = 0;
                for (int i = 0; i < uidc; i++) {
                    if (uids[i] == found_uid) { dup = 1; break; }
                }
                if (!dup) uids[uidc++] = found_uid;
            }
        }
        closedir(proc);
    }
    if (uidc == 0) {
        uids[uidc++] = 1000;
        uids[uidc++] = 10027;
    }

    /* Distribute total traffic among UIDs */
    uint64_t per_uid_rx = total.rxBytes / (uint64_t)(uidc > 0 ? uidc : 1);
    uint64_t per_uid_tx = total.txBytes / (uint64_t)(uidc > 0 ? uidc : 1);

    g_uid_count = uidc;
    for (int i = 0; i < uidc && i < MAX_UID_STATS; i++) {
        g_uid_stats[i].uid = uids[i];
        g_uid_stats[i].rxBytes = per_uid_rx;
        g_uid_stats[i].txBytes = per_uid_tx;
        g_uid_stats[i].last_seen = time(NULL);
    }

    /* Write per-UID stats file */
    FILE* uf = fopen("/data/local/tmp/netproxy_uid", "w");
    if (uf) {
        for (int i = 0; i < uidc; i++) {
            fprintf(uf, "uid_%d_rx=%" PRIu64 "\nuid_%d_tx=%" PRIu64 "\n",
                    uids[i], per_uid_rx, uids[i], per_uid_tx);
        }
        fprintf(uf, "uid_count=%d\ntimestamp=%ld\n", uidc, (long)time(NULL));
        fclose(uf);
        chmod("/data/local/tmp/netproxy_uid", 0644);
    }

    /* Also push to BPF maps and /proc/uid_stat/ */
    for (int i = 0; i < uidc && i < MAX_UID_STATS; i++) {
        write_uid_stat_entry(g_uid_stats[i].uid, g_uid_stats[i].rxBytes, g_uid_stats[i].txBytes);
    }
    populate_bpf_maps();
}

static uint64_t get_uid_rx(int uid) {
    for (int i = 0; i < g_uid_count && i < MAX_UID_STATS; i++) {
        if (g_uid_stats[i].uid == uid) return g_uid_stats[i].rxBytes;
    }
    struct net_stats total;
    if (read_all_stats(&total) == 0) return total.rxBytes / 10;
    return 0;
}

static uint64_t get_uid_tx(int uid) {
    for (int i = 0; i < g_uid_count && i < MAX_UID_STATS; i++) {
        if (g_uid_stats[i].uid == uid) return g_uid_stats[i].txBytes;
    }
    struct net_stats total;
    if (read_all_stats(&total) == 0) return total.txBytes / 10;
    return 0;
}

/* ============================================================
 * Binder IPC
 * ============================================================ */
static int binder_fd = -1;
static uint8_t* binder_map = NULL;

static int do_ioctl(int fd, unsigned long cmd, void* arg) {
    int ret = ioctl(fd, cmd, arg);
    if (ret < 0 && errno != EINTR && errno != EAGAIN) {
        log_msg("ioctl 0x%lx cmd=%lu failed: errno=%d (%s)", cmd, cmd, errno, strerror(errno));
    }
    return ret;
}

static int open_binder(void) {
    const char* paths[] = {"/dev/binder", "/dev/vndbinder", "/dev/hwbinder", NULL};

    for (int pi = 0; paths[pi]; pi++) {
        const char* devpath = paths[pi];
        log_msg("Trying binder device: %s", devpath);
        for (int attempt = 0; attempt < 15; attempt++) {
            int fd = open(devpath, O_RDWR | O_CLOEXEC);
            if (fd >= 0) {
                log_msg("opened %s (attempt %d fd=%d)", devpath, attempt + 1, fd);

                struct binder_version ver;
                memset(&ver, 0, sizeof(ver));
                int vret = ioctl(fd, BINDER_VERSION, &ver);
                if (vret == 0) {
                    log_msg("  %s: binder protocol version %d", devpath, ver.protocol_version);
                } else {
                    log_msg("  %s: BINDER_VERSION ioctl failed (errno=%d), assuming v1", devpath, errno);
                }

                uint32_t max_threads = 64;
                ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);

                /* Try PROT_READ first, then MAP_SHARED, then PROT_READ|PROT_WRITE */
                uint8_t* map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                              MAP_PRIVATE | MAP_NORESERVE, fd, 0);
                if (map == MAP_FAILED) {
                    map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_NORESERVE, fd, 0);
                }
                if (map == MAP_FAILED) {
                    map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                        MAP_SHARED, fd, 0);
                }
                if (map == MAP_FAILED) {
                    log_msg("  %s: mmap failed (errno=%d), trying next device", devpath, errno);
                    close(fd);
                    break;
                }

                binder_fd = fd;
                binder_map = map;
                log_msg("binder ready: %s mmap=%p size=%d prot=%s",
                        devpath, (void*)binder_map, BINDER_MMAP_SIZE,
                        "READ");
                return 0;
            }

            if (errno == ENOENT) {
                log_msg("  %s: not found (ENOENT), skipping", devpath);
                break;
            }
            if (errno == EBUSY) {
                log_msg("  %s: busy (EBUSY), retrying...", devpath);
            } else if (attempt > 0) {
                log_msg("  %s: retry %d failed (errno=%d)", devpath, attempt + 1, errno);
            }
            if (attempt < 14) usleep(500000);
        }
    }

    log_msg("FATAL: no binder device could be opened after all attempts");
    return -1;
}

static int send_binder_cmd(const void* cmd, size_t cmd_size) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = cmd_size;
    bwr.write_buffer = (uint64_t)(uintptr_t)cmd;
    return do_ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
}

static int send_bc_with_reply(const void* write_buf, size_t write_size,
                               uint8_t* read_buf, size_t read_size,
                               size_t* read_consumed) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = write_size;
    bwr.write_buffer = (uint64_t)(uintptr_t)write_buf;
    bwr.read_size    = read_size;
    bwr.read_buffer  = (uint64_t)(uintptr_t)read_buf;
    int ret = do_ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0 && errno != EINTR) return ret;
    if (read_consumed) *read_consumed = (size_t)bwr.read_consumed;
    return 0;
}

/* ============================================================
 * Parcel helpers (forward declarations)
 * ============================================================ */
static void write_int32(uint8_t** buf, int32_t val);
static void write_int64(uint8_t** buf, int64_t val);

/* ============================================================ */
static void write_str16(uint8_t** buf, const char* s) {
    if (!s) { write_int32(buf, -1); return; }
    uint32_t len = (uint32_t)strlen(s);
    memcpy(*buf, &len, 4); *buf += 4;
    for (uint32_t i = 0; i < len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(*buf, &c, 2); *buf += 2;
    }
    uint16_t nul = 0;
    memcpy(*buf, &nul, 2); *buf += 2;
    while ((uintptr_t)(*buf) % 4 != 0) { **buf = 0; (*buf)++; }
}

__attribute__((unused)) static void write_str16_raw(uint8_t** buf, const uint8_t* data, uint32_t len) {
    memcpy(*buf, &len, 4); *buf += 4;
    for (uint32_t i = 0; i < len; i++) {
        uint16_t c = (uint16_t)data[i];
        memcpy(*buf, &c, 2); *buf += 2;
    }
    uint16_t nul = 0;
    memcpy(*buf, &nul, 2); *buf += 2;
    while ((uintptr_t)(*buf) % 4 != 0) { **buf = 0; (*buf)++; }
}

static void skip_str16(const uint8_t** pp) {
    uint32_t len; memcpy(&len, *pp, 4); *pp += 4;
    if (len == 0xFFFFFFFFu) return;
    *pp += (len + 1) * 2;
    while ((uintptr_t)(*pp) % 4 != 0) (*pp)++;
}

static void write_int32(uint8_t** buf, int32_t val) {
    memcpy(*buf, &val, 4); *buf += 4;
}

static void write_int64(uint8_t** buf, int64_t val) {
    memcpy(*buf, &val, 8); *buf += 8;
}

__attribute__((unused)) static void write_uint32(uint8_t** buf, uint32_t val) {
    memcpy(*buf, &val, 4); *buf += 4;
}

__attribute__((unused)) static int32_t read_int32(const uint8_t** pp) {
    int32_t val; memcpy(&val, *pp, 4); *pp += 4; return val;
}

__attribute__((unused)) static int64_t read_int64(const uint8_t** pp) {
    int64_t val; memcpy(&val, *pp, 8); *pp += 8; return val;
}

__attribute__((unused)) static void write_int32_array(uint8_t** buf, const int32_t* arr, int32_t len) {
    write_int32(buf, len);
    for (int32_t i = 0; i < len; i++) write_int32(buf, arr[i]);
}

__attribute__((unused)) static void write_int64_array(uint8_t** buf, const int64_t* arr, int32_t len) {
    write_int32(buf, len);
    for (int32_t i = 0; i < len; i++) write_int64(buf, arr[i]);
}

static void write_int32_array_fill(uint8_t** buf, int32_t val, int32_t len) {
    write_int32(buf, len);
    for (int32_t i = 0; i < len; i++) write_int32(buf, val);
}

static void write_int64_array_fill(uint8_t** buf, int64_t val, int32_t len) {
    write_int32(buf, len);
    for (int32_t i = 0; i < len; i++) write_int64(buf, val);
}

/* ============================================================
 * Build StatsResult Parcel
 * Format (AIDL): exception + nullable StatsResult(4 x int64)
 * ============================================================ */
static size_t build_stats_result_reply(uint8_t* buf, size_t buf_size,
                                       uint64_t rxBytes, uint64_t rxPackets,
                                       uint64_t txBytes, uint64_t txPackets) {
    (void)buf_size;
    uint8_t* p = buf;
    write_int32(&p, 0);          /* exception = 0 (writeNoException) */
    write_int32(&p, 1);          /* non-null parcelable */
    write_int32(&p, 36);         /* StatsResult size (4 longs = 32 bytes + 4 byte header) */
    write_int64(&p, rxBytes);
    write_int64(&p, rxPackets);
    write_int64(&p, txBytes);
    write_int64(&p, txPackets);
    log_msg("[REPLY] StatsResult: rxB=%" PRIu64 " rxP=%" PRIu64 " txB=%" PRIu64 " txP=%" PRIu64 " size=%zu",
            rxBytes, rxPackets, txBytes, txPackets, (size_t)(p - buf));
    return (size_t)(p - buf);
}

/* ============================================================
 * Build NetworkStats Parcel with multiple entries (one per interface)
 * ============================================================ */
static size_t build_network_stats_reply_full(uint8_t* buf, size_t buf_size,
                                              uint64_t rxBytes, uint64_t rxPackets,
                                              uint64_t txBytes, uint64_t txPackets) {
    (void)buf_size;
    uint8_t* p = buf;

    /* Get all interfaces */
    struct iface_stat ifaces[MAX_IFACES];
    int iface_count = 0;
    read_all_ifaces(ifaces, &iface_count);

    int entry_count = iface_count > 0 ? iface_count : 1;
    if (entry_count > 16) entry_count = 16; /* Keep reply size reasonable */

    write_int32(&p, 0);  /* exception */

    write_int32(&p, 1);  /* non-null parcelable */
    write_int64(&p, 0);  /* elapsedRealtime */

    /* size, capacity */
    write_int32(&p, entry_count);
    write_int32(&p, entry_count);

    /* Build string arrays for iface */
    write_int32(&p, entry_count);
    for (int i = 0; i < entry_count; i++) {
        if (iface_count > 0 && i < iface_count && ifaces[i].name[0]) {
            write_str16(&p, ifaces[i].name);
        } else {
            write_str16(&p, (i == 0) ? "wlan0" : "rmnet0");
        }
    }

    /* uid array: all -1 (UID_ALL) */
    write_int32_array_fill(&p, -1, entry_count);

    /* set array: all 0 (SET_DEFAULT) */
    write_int32_array_fill(&p, 0, entry_count);

    /* tag array: all 0 (TAG_NONE) */
    write_int32_array_fill(&p, 0, entry_count);

    /* metered array: all -1 (METERED_ALL) */
    write_int32_array_fill(&p, -1, entry_count);

    /* roaming array: all -1 (ROAMING_ALL) */
    write_int32_array_fill(&p, -1, entry_count);

    /* defaultNetwork array: all -1 (DEFAULT_NETWORK_ALL) */
    write_int32_array_fill(&p, -1, entry_count);

    /* rxBytes per interface */
    write_int32(&p, entry_count);
    for (int i = 0; i < entry_count; i++) {
        if (iface_count > 0 && i < iface_count)
            write_int64(&p, (int64_t)ifaces[i].rxBytes);
        else
            write_int64(&p, (int64_t)rxBytes);
    }

    /* rxPackets per interface */
    write_int32(&p, entry_count);
    for (int i = 0; i < entry_count; i++) {
        if (iface_count > 0 && i < iface_count)
            write_int64(&p, (int64_t)ifaces[i].rxPackets);
        else
            write_int64(&p, (int64_t)rxPackets);
    }

    /* txBytes per interface */
    write_int32(&p, entry_count);
    for (int i = 0; i < entry_count; i++) {
        if (iface_count > 0 && i < iface_count)
            write_int64(&p, (int64_t)ifaces[i].txBytes);
        else
            write_int64(&p, (int64_t)txBytes);
    }

    /* txPackets per interface */
    write_int32(&p, entry_count);
    for (int i = 0; i < entry_count; i++) {
        if (iface_count > 0 && i < iface_count)
            write_int64(&p, (int64_t)ifaces[i].txPackets);
        else
            write_int64(&p, (int64_t)txPackets);
    }

    /* operations array: all 0 */
    write_int64_array_fill(&p, 0, entry_count);

    size_t total_sz = (size_t)(p - buf);
    log_msg("[REPLY] NetworkStats: %d ifaces rxB=%" PRIu64 " txB=%" PRIu64 " size=%zu",
            entry_count, rxBytes, txBytes, total_sz);
    log_hex("[REPLY] NETSTATS", buf, (uint32_t)total_sz);
    return total_sz;
}

/* Backward compat: single interface reply */
static size_t build_network_stats_reply(uint8_t* buf, size_t buf_size,
                                        uint64_t rxBytes, uint64_t rxPackets,
                                        uint64_t txBytes, uint64_t txPackets) {
    return build_network_stats_reply_full(buf, buf_size, rxBytes, rxPackets, txBytes, txPackets);
}

/* ============================================================
 * Build simple reply (exception only)
 * ============================================================ */
static size_t build_void_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    return (size_t)(p - buf);
}

/* Build reply with just exception + int32 */
__attribute__((unused)) static size_t build_int32_reply(uint8_t* buf, int32_t val) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int32(&p, val);
    return (size_t)(p - buf);
}

/* Build reply with exception + int64 */
static size_t build_int64_reply(uint8_t* buf, int64_t val) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int64(&p, val);
    return (size_t)(p - buf);
}

/* Build reply with exception + string[] (empty) */
static size_t build_empty_string_array_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int32(&p, 0);
    return (size_t)(p - buf);
}

/* Build reply with exception + null binder */
static size_t build_null_binder_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int32(&p, 0);
    return (size_t)(p - buf);
}

/* Build reply with exception + null parcelable */
static size_t build_null_parcelable_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int32(&p, 0);
    return (size_t)(p - buf);
}

/* Build reply: exception + int32[] (empty) */
static size_t build_empty_int32_array_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int32(&p, 0);
    return (size_t)(p - buf);
}

/* Build NetworkStatsHistory reply: exception + null */
static size_t build_null_history_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);
    write_int32(&p, 0);
    return (size_t)(p - buf);
}

/* ============================================================
 * AIDL ServiceManager communication
 * ============================================================ */
#define SM_AIDL_CHECK_SERVICE 2
#define SM_AIDL_ADD_SERVICE   3

#define SERVICE_NAME_NETSTATS "netstats"
#define SERVICE_NAME_NETSTATS_ALT "netstats_service"
#define SERVICE_NAME_NETSTATS_ALT2 "network_stats"

__attribute__((unused)) static const char* SERVICE_NAMES[] = {
    SERVICE_NAME_NETSTATS,
    SERVICE_NAME_NETSTATS_ALT,
    SERVICE_NAME_NETSTATS_ALT2,
    NULL
};

static int g_registered_service_idx = -1;
static char g_registered_name[64] = "";

static int parse_sm_reply(const uint8_t* rbuf, size_t consumed, int* out_has_binder) {
    const uint8_t* rp = rbuf;
    const uint8_t* rend = rbuf + consumed;
    int result = -1;
    if (out_has_binder) *out_has_binder = -1;

    while (rp < rend) {
        if (rp + 4 > rend) break;
        uint32_t cmd;
        memcpy(&cmd, rp, 4); rp += 4;

        switch (cmd) {
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
            case BR_FINISHED:
                break;

            case BR_SPAWN_LOOPER:
                { uint32_t c = BC_ENTER_LOOPER; send_binder_cmd(&c, sizeof(c)); }
                break;

            case BR_REPLY: {
                if (rp + sizeof(struct binder_transaction_data) > rend) return -1;
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);

                uint64_t buf_ptr = rtr->data.ptr.buffer;
                uint64_t data_sz = rtr->data_size;

                if (data_sz >= 8) {
                    const uint8_t* data = (const uint8_t*)(uintptr_t)buf_ptr;
                    int32_t exc;
                    memcpy(&exc, data, 4);
                    if (exc != 0) {
                        log_msg("  SM reply: exception=%d", exc);
                        result = -1;
                        if (out_has_binder) *out_has_binder = -1;
                    } else {
                        uint64_t binder_val = 0;
                        memcpy(&binder_val, data + 4, 8);
                        if (binder_val != 0) {
                            log_msg("  SM reply: EXISTS binder=0x%" PRIx64, binder_val);
                            result = 0;
                            if (out_has_binder) *out_has_binder = 1;
                        } else {
                            log_msg("  SM reply: not found");
                            result = 0;
                            if (out_has_binder) *out_has_binder = 0;
                        }
                    }
                } else {
                    log_msg("  SM reply: empty (data_sz=%" PRIu64 ")", data_sz);
                    result = 0;
                    if (out_has_binder) *out_has_binder = 0;
                }

                uint8_t fcmd[4 + 8];
                *(uint32_t*)fcmd = BC_FREE_BUFFER;
                memcpy(fcmd + 4, &buf_ptr, 8);
                send_binder_cmd(fcmd, sizeof(fcmd));
                return result;
            }

            case BR_ACQUIRE:
            case BR_INCREFS: {
                if (rp + 16 <= rend) {
                    rp += 16;
                    uint8_t ack[4 + 16];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memset(ack + 4, 0, 16);
                    send_binder_cmd(ack, sizeof(ack));
                }
                break;
            }

            case BR_RELEASE:
            case BR_DECREFS:
                if (rp + 16 <= rend) rp += 16;
                break;

            case BR_DEAD_BINDER:
            case BR_CLEAR_DEATH_NOTIFICATION_DONE:
                if (rp + 8 <= rend) rp += 8;
                break;

            case BR_FAILED_REPLY:
                log_msg("SM BR_FAILED_REPLY");
                return -1;

            case BR_DEAD_REPLY:
                log_msg("SM BR_DEAD_REPLY");
                return -1;

            case BR_ERROR: {
                int32_t err = 0;
                if (rp + 4 <= rend) memcpy(&err, rp, 4);
                log_msg("SM BR_ERROR=%d", err);
                return -1;
            }

            default:
                log_msg("SM unknown BR cmd 0x%x", cmd);
                return -1;
        }
    }
    return result;
}

static int aidl_check_service(const char* name) {
    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;
    write_str16(&p, name);
    size_t psize = (size_t)(p - pbuf);

    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;
    uint8_t* wp = wbuf;

    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr)); wp += sizeof(*tr);
    tr->target.handle = SM_HANDLE;
    tr->code          = SM_AIDL_CHECK_SERVICE;
    tr->data_size     = psize;
    tr->data.ptr.buffer = (uint64_t)(uintptr_t)wp;
    memcpy(wp, pbuf, psize);
    size_t total = (size_t)(wp + psize - wbuf);

    uint8_t rbuf[1024];
    size_t consumed = 0;
    int ret = send_bc_with_reply(wbuf, total, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);
    if (ret < 0) return -1;

    int has_binder = -1;
    parse_sm_reply(rbuf, consumed, &has_binder);
    return has_binder;
}

static int aidl_add_service(const char* name, uint64_t binder_ptr, uint64_t cookie) {
    uint8_t pbuf[2048];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;

    write_str16(&p, name);
    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - pbuf);

    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr_type = BINDER_TYPE_BINDER;
    fbo.flags    = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    fbo.binder   = binder_ptr;
    fbo.cookie   = cookie;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    size_t   psize   = (size_t)(p - pbuf);
    uint32_t offsets[1] = { fbo_offset };
    size_t offsets_bytes = sizeof(offsets);

    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + offsets_bytes + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;
    uint8_t* wp = wbuf;

    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr)); wp += sizeof(*tr);
    tr->target.handle = SM_HANDLE;
    tr->code          = SM_AIDL_ADD_SERVICE;
    tr->data_size     = psize;
    tr->offsets_size  = offsets_bytes;
    memcpy(wp, pbuf, psize);
    memcpy(wp + psize, offsets, offsets_bytes);
    tr->data.ptr.buffer  = (uint64_t)(uintptr_t)wp;
    tr->data.ptr.offsets = (uint64_t)(uintptr_t)(wp + psize);
    size_t total = (size_t)(wp + psize + offsets_bytes - wbuf);

    uint8_t rbuf[1024];
    size_t consumed = 0;
    int ret = send_bc_with_reply(wbuf, total, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);
    if (ret < 0) return -1;

    int result = parse_sm_reply(rbuf, consumed, NULL);
    log_msg("addService('%s'): %s (ret=%d)", name, result >= 0 ? "SUCCESS" : "FAILED", result);
    return result;
}

/* ============================================================
 * Session management
 * ============================================================ */
static int session_count = 0;
static uint64_t session_ptrs[MAX_SESSIONS];
static uint64_t session_cookies[MAX_SESSIONS];

static uint64_t create_session(void) {
    if (session_count >= MAX_SESSIONS) {
        log_msg("WARNING: max sessions reached (%d), wrapping to 0", MAX_SESSIONS);
        session_count = 0;
    }
    /* Use a unique ptr that doesn't conflict with existing sessions */
    uint64_t ptr_base = (uint64_t)(uintptr_t)(binder_map + SESSION_BASE);
    uint64_t ptr = ptr_base + (uint64_t)session_count * 0x10000 + (uint64_t)(session_count + 1) * 0x100;
    session_ptrs[session_count] = ptr;
    session_cookies[session_count] = ptr;
    log_msg("[SESS] create #%d: ptr=0x%" PRIx64 " (total_open=%d active=%d)",
            session_count, ptr, session_count + 1, session_count + 1);
    session_count++;
    return ptr;
}

static int is_session_ptr(uint64_t ptr) {
    for (int i = 0; i < session_count; i++) {
        if (session_ptrs[i] == ptr) {
            return i;
        }
    }
    return -1;
}

static void destroy_session(int idx) {
    if (idx < 0 || idx >= session_count) {
        log_msg("[SESS] destroy: idx=%d INVALID (count=%d)", idx, session_count);
        return;
    }
    uint64_t ptr = session_ptrs[idx];
    session_ptrs[idx] = session_ptrs[session_count - 1];
    session_cookies[idx] = session_cookies[session_count - 1];
    session_count--;
    log_msg("[SESS] destroy idx=%d ptr=0x%" PRIx64 " -> active=%d", idx, ptr, session_count);
}

/* ============================================================
 * Reply with a session flat_binder_object
 * ============================================================ */
static size_t build_session_reply(uint8_t* buf, uint64_t session_ptr,
                                  uint32_t* binder_off) {
    uint8_t* p = buf;
    write_int32(&p, 0);  /* exception */

    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - buf);

    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr_type = BINDER_TYPE_BINDER;
    fbo.flags    = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    fbo.binder   = session_ptr;
    fbo.cookie   = session_ptr;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    if (binder_off) *binder_off = fbo_offset;
    return (size_t)(p - buf);
}

/* ============================================================
 * Debug counters
 * ============================================================ */
static int g_br_transaction_count = 0;
static int g_br_reply_count = 0;
static int g_br_error_count = 0;
static int g_br_dead_count = 0;
static int g_br_other_count = 0;
__attribute__((unused)) static int g_session_open_count = 0;
__attribute__((unused)) static int g_session_close_count = 0;
static int g_unknown_code_count = 0;
static int g_total_txns = 0;
__attribute__((unused)) static time_t g_last_summary = 0;

static const char* iface_hash = "e8d9c0b7a6f5e4d3c2b1a0f9e8d7c6b5";

/* ============================================================
 * Transaction handler
 * ============================================================ */
static uint64_t main_service_ptr = 0;
static uint64_t main_service_cookie = 0;

static void handle_transaction(const struct binder_transaction_data* tr) {
    uint8_t reply_data[16384];
    int session_idx = -1;
    int is_session = 0;
    int32_t binder_offset = -1;
    uint32_t code = tr->code;
    struct net_stats s;
    read_all_stats(&s);

    g_br_transaction_count++;
    g_total_txns++;

    if (main_service_ptr != 0 && tr->target.ptr == main_service_ptr) {
        is_session = 0;
    } else {
        session_idx = is_session_ptr(tr->target.ptr);
        if (session_idx >= 0) {
            is_session = 1;
        }
    }

    const uint8_t* raw_data = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    uint64_t raw_size = tr->data_size;

    log_msg("[TX#%d] >>> code=%u(0x%x) %s flags=0x%x data_sz=%" PRIu64 " pid=%d euid=%u tgt_ptr=0x%" PRIx64,
            g_br_transaction_count, code, code, is_session ? "[SESSION]" : "[SERVICE]",
            tr->flags, raw_size, tr->sender_pid, tr->sender_euid,
            tr->target.ptr);

    if (raw_size > 0 && raw_data) {
        if (g_br_transaction_count <= 10 || g_br_transaction_count % 50 == 0) {
            log_hex("[TX-DATA]", raw_data, (uint32_t)(raw_size > 256 ? 256 : raw_size));
        }

        /* Log the sender process name */
        char comm_path[64];
        char comm[64] = "?";
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", tr->sender_pid);
        FILE* cf = fopen(comm_path, "r");
        if (cf) {
            if (fgets(comm, sizeof(comm), cf)) {
                char* nl = strchr(comm, '\n');
                if (nl) *nl = '\0';
            }
            fclose(cf);
        }
        log_msg("[TX#%d]  sender=%s uid=%d pid=%d", g_br_transaction_count, comm, tr->sender_euid, tr->sender_pid);

        /* Log first 4 bytes as int32 (usually exception code or method arg) */
        if (raw_size >= 4) {
            int32_t first_val;
            memcpy(&first_val, raw_data, 4);
            log_msg("[TX#%d]  first_int32=%d (0x%x)", g_br_transaction_count, first_val, first_val);
        }

        /* Dump interface descriptor string if this looks like a method call */
        if (raw_size >= 8) {
            uint32_t str_len;
            memcpy(&str_len, raw_data, 4);
            if (str_len > 0 && str_len < 200 && raw_size > (uint64_t)(4 + str_len * 2)) {
                char ifdesc[256];
                uint32_t copy_len = str_len < 120 ? str_len : 120;
                for (uint32_t i = 0; i < copy_len; i++) {
                    uint16_t c;
                    memcpy(&c, raw_data + 4 + i * 2, 2);
                    ifdesc[i] = (char)c;
                }
                ifdesc[copy_len] = '\0';
                log_msg("[TX#%d]  interface_desc='%s'", g_br_transaction_count, ifdesc);
            }
        }
    } else {
        log_msg("[TX#%d]  no data", g_br_transaction_count);
    }

    log_msg("[TX#%d]  stats: rx=%" PRIu64 " tx=%" PRIu64 " rxp=%" PRIu64 " txp=%" PRIu64,
            g_br_transaction_count, s.rxBytes, s.txBytes, s.rxPackets, s.txPackets);

    size_t reply_size = 0;

    if (is_session) {
        switch (code) {
            case SESS_getDeviceSummaryForNetwork:
            case SESS_getSummaryForNetwork:
            case SESS_getDeviceSummaryForNetworkWithMetered:
            case SESS_getSummaryForNetworkWithMetered: {
                log_msg("[TX#%d]  session getDeviceSummary/getSummary", g_br_transaction_count);
                reply_size = build_network_stats_reply(reply_data, sizeof(reply_data),
                                                       s.rxBytes, s.rxPackets,
                                                       s.txBytes, s.txPackets);
                break;
            }

            case SESS_getSummaryForAllUid:
            case SESS_getTaggedSummaryForAllUid: {
                log_msg("[TX#%d]  session getSummaryForAllUid/getTaggedSummary", g_br_transaction_count);
                reply_size = build_network_stats_reply(reply_data, sizeof(reply_data),
                                                       s.rxBytes, s.rxPackets,
                                                       s.txBytes, s.txPackets);
                break;
            }

            case SESS_getHistoryForNetwork:
            case SESS_getHistoryIntervalForNetwork:
            case SESS_getHistoryForUid:
            case SESS_getHistoryIntervalForUid: {
                log_msg("[TX#%d]  session getHistory* -> return null", g_br_transaction_count);
                reply_size = build_null_history_reply(reply_data);
                break;
            }

            case SESS_getRelevantUids: {
                log_msg("[TX#%d]  session getRelevantUids -> []", g_br_transaction_count);
                reply_size = build_empty_int32_array_reply(reply_data);
                break;
            }

            case SESS_close: {
                log_msg("[TX#%d]  session close idx=%d", g_br_transaction_count, session_idx);
                if (session_idx >= 0) destroy_session(session_idx);
                reply_size = build_void_reply(reply_data);
                break;
            }

            default: {
                log_msg("[TX#%d]  UNKNOWN session code %u (0x%x)", g_br_transaction_count, code, code);
                reply_size = build_void_reply(reply_data);
                break;
            }
        }
    } else {
        switch (code) {
            case TX_openSession:
            case TX_openSessionForUsageStats: {
                log_msg("[TX#%d]  openSession/openSessionForUsageStats", g_br_transaction_count);
                uint64_t sess_ptr = create_session();
                uint32_t bo = 0;
                reply_size = build_session_reply(reply_data, sess_ptr, &bo);
                binder_offset = (int32_t)bo;
                break;
            }

            case TX_getTotalStats: {
                log_msg("[TX#%d]  getTotalStats", g_br_transaction_count);
                reply_size = build_stats_result_reply(reply_data, sizeof(reply_data),
                                                      s.rxBytes, s.rxPackets,
                                                      s.txBytes, s.txPackets);
                break;
            }

            case TX_getIfaceStats: {
                log_msg("[TX#%d]  getIfaceStats", g_br_transaction_count);
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                char iface[64] = "wlan0";
                uint64_t data_remaining = raw_size;
                if (data_remaining > 4) {
                    /* Skip interface descriptor / header */
                    skip_str16(&pp);
                    data_remaining = raw_size - (size_t)(pp - raw_data);
                    /* Parse iface string */
                    if (data_remaining >= 4) {
                        uint32_t nlen; memcpy(&nlen, pp, 4); pp += 4;
                        if (nlen > 0 && nlen < 60 && data_remaining >= (uint64_t)(4 + nlen * 2 + 2)) {
                            for (uint32_t i = 0; i < nlen; i++) {
                                uint16_t c; memcpy(&c, pp, 2); pp += 2;
                                iface[i] = (char)c;
                            }
                            iface[nlen] = '\0';
                        }
                    }
                }
                struct net_stats is;
                if (read_iface_stats(iface, &is) != 0) {
                    log_msg("[TX#%d]  iface '%s' not found in /proc/net/dev, using total", g_br_transaction_count, iface);
                    is = s;
                }
                log_msg("[TX#%d]  getIfaceStats iface=%s rx=%" PRIu64 " tx=%" PRIu64,
                        g_br_transaction_count, iface, is.rxBytes, is.txBytes);
                reply_size = build_stats_result_reply(reply_data, sizeof(reply_data),
                                                      is.rxBytes, is.rxPackets,
                                                      is.txBytes, is.txPackets);
                break;
            }

            case TX_getUidStats: {
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                int uid = -1;
                if (raw_size >= 4) memcpy(&uid, pp, 4);
                struct net_stats us;
                us.rxBytes = get_uid_rx(uid);
                us.txBytes = get_uid_tx(uid);
                us.rxPackets = us.rxBytes / 1500;
                us.txPackets = us.txBytes / 1500;
                log_msg("[TX#%d]  getUidStats uid=%d -> rx=%" PRIu64 " tx=%" PRIu64,
                        g_br_transaction_count, uid, us.rxBytes, us.txBytes);
                reply_size = build_stats_result_reply(reply_data, sizeof(reply_data),
                                                      us.rxBytes, us.rxPackets,
                                                      us.txBytes, us.txPackets);
                break;
            }

            case TX_getMobileIfaces: {
                log_msg("[TX#%d]  getMobileIfaces -> []", g_br_transaction_count);
                reply_size = build_empty_string_array_reply(reply_data);
                break;
            }

            case TX_forceUpdate: {
                write_all_stats_sources();
                log_msg("[TX#%d]  forceUpdate", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_getUidStatsForTransport:
            case TX_getDataLayerSnapshotForUid: {
                log_msg("[TX#%d]  getUidStatsForTransport/getDataLayerSnapshotForUid", g_br_transaction_count);
                reply_size = build_network_stats_reply(reply_data, sizeof(reply_data),
                                                       s.rxBytes, s.rxPackets,
                                                       s.txBytes, s.txPackets);
                break;
            }

            case TX_registerNetworkStatsProvider: {
                log_msg("[TX#%d]  registerNetworkStatsProvider -> null", g_br_transaction_count);
                reply_size = build_null_binder_reply(reply_data);
                break;
            }

            case TX_incrementOperationCount: {
                log_msg("[TX#%d]  incrementOperationCount", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_notifyNetworkStatus: {
                log_msg("[TX#%d]  notifyNetworkStatus", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_registerUsageCallback: {
                log_msg("[TX#%d]  registerUsageCallback -> null", g_br_transaction_count);
                reply_size = build_null_parcelable_reply(reply_data);
                break;
            }

            case TX_unregisterUsageRequest: {
                log_msg("[TX#%d]  unregisterUsageRequest", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_noteUidForeground: {
                log_msg("[TX#%d]  noteUidForeground", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_advisePersistThreshold: {
                log_msg("[TX#%d]  advisePersistThreshold", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_setStatsProviderWarningAndLimitAsync: {
                log_msg("[TX#%d]  setStatsProviderWarningAndLimitAsync", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_getRateLimitCacheConfig: {
                log_msg("[TX#%d]  getRateLimitCacheConfig -> null", g_br_transaction_count);
                reply_size = build_null_parcelable_reply(reply_data);
                break;
            }

            case TX_GET_INTERFACE_VERSION: {
                uint32_t version = 5;
                uint8_t* p = reply_data;
                write_int32(&p, 0);
                memcpy(p, &version, 4); p += 4;
                reply_size = (size_t)(p - reply_data);
                log_msg("[TX#%d]  getInterfaceVersion -> %u", g_br_transaction_count, version);
                break;
            }

            case TX_GET_INTERFACE_HASH: {
                uint8_t* p = reply_data;
                write_int32(&p, 0);
                write_str16(&p, iface_hash);
                reply_size = (size_t)(p - reply_data);
                log_msg("[TX#%d]  getInterfaceHash -> %s", g_br_transaction_count, iface_hash);
                break;
            }

            case TX_LEGACY_GET_TOTAL_STATS: {
                uint64_t val = s.rxBytes + s.txBytes;
                log_msg("[TX#%d]  LEGACY getTotalStats -> %" PRIu64, g_br_transaction_count, val);
                reply_size = build_int64_reply(reply_data, (int64_t)val);
                break;
            }

            case TX_LEGACY_GET_IFACE_STATS: {
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                char iface[64] = "wlan0";
                if (raw_size > 4) {
                    uint32_t nlen; memcpy(&nlen, pp, 4); pp += 4;
                    if (nlen > 0 && nlen < 60) {
                        for (uint32_t i = 0; i < nlen; i++) {
                            uint16_t c; memcpy(&c, pp, 2); pp += 2;
                            iface[i] = (char)c;
                        }
                        iface[nlen] = '\0';
                    }
                }
                int type = 0;
                if ((uint64_t)(pp + 4 - raw_data) <= raw_size) memcpy(&type, pp, 4);
                struct net_stats is;
                if (read_iface_stats(iface, &is) != 0) is = s;
                uint64_t val = 0;
                switch (type) {
                    case 0: val = is.rxBytes; break;
                    case 1: val = is.txBytes; break;
                    case 2: val = is.rxPackets; break;
                    case 3: val = is.txPackets; break;
                    default: val = is.rxBytes + is.txBytes; break;
                }
                log_msg("[TX#%d]  LEGACY getIfaceStats iface=%s type=%d -> %" PRIu64,
                        g_br_transaction_count, iface, type, val);
                reply_size = build_int64_reply(reply_data, (int64_t)val);
                break;
            }

            case TX_LEGACY_FORCE_UPDATE: {
                write_all_stats_sources();
                log_msg("[TX#%d]  LEGACY forceUpdate", g_br_transaction_count);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_LEGACY_GET_UID_STATS: {
                log_msg("[TX#%d]  LEGACY getUidStats -> 0", g_br_transaction_count);
                reply_size = build_int64_reply(reply_data, 0);
                break;
            }

            default: {
                g_unknown_code_count++;
                log_msg("[TX#%d]  UNKNOWN service code %u (0x%x) #%d total", g_br_transaction_count, code, code, g_unknown_code_count);
                reply_size = build_void_reply(reply_data);
                break;
            }
        }
    }

    /* Build and send BC_REPLY */
    uint32_t offsets_arr[4];
    uint32_t offsets_bytes = 0;
    if (binder_offset >= 0) {
        offsets_arr[0] = (uint32_t)binder_offset;
        offsets_bytes = sizeof(uint32_t);
    }

    size_t rwbuf_size = 4 + sizeof(struct binder_transaction_data) + reply_size + offsets_bytes + 256;
    uint8_t* rwbuf = (uint8_t*)calloc(1, rwbuf_size);
    if (!rwbuf) return;
    uint8_t* rwp = rwbuf;
    *(uint32_t*)rwp = BC_REPLY; rwp += 4;
    struct binder_transaction_data* rtr = (struct binder_transaction_data*)rwp;
    memset(rtr, 0, sizeof(*rtr)); rwp += sizeof(*rtr);
    rtr->cookie    = tr->cookie;
    rtr->code      = 0;
    rtr->flags     = TF_ACCEPT_FDS;
    rtr->data_size = reply_size;
    rtr->data.ptr.buffer = (uint64_t)(uintptr_t)rwp;
    memcpy(rwp, reply_data, reply_size);
    if (offsets_bytes > 0) {
        rtr->offsets_size = offsets_bytes;
        rtr->data.ptr.offsets = (uint64_t)(uintptr_t)(rwp + reply_size);
        memcpy(rwp + reply_size, offsets_arr, offsets_bytes);
    }
    size_t write_len = (size_t)(rwp + reply_size + offsets_bytes - rwbuf);
    uint8_t discard[8192];
    size_t consumed = 0;
    int ret = send_bc_with_reply(rwbuf, write_len, discard, sizeof(discard), &consumed);
    if (ret < 0) {
        log_errno("send BC_REPLY");
        log_msg("[TX#%d] <<< REPLY FAILED (errno=%d)", g_br_transaction_count, errno);
    } else {
        log_msg("[TX#%d] <<< REPLY SENT: code=%u reply_sz=%zu offsets=%u consumed=%zu ret=%d",
                g_br_transaction_count, code, reply_size, offsets_bytes, consumed, ret);
    }
    free(rwbuf);
    write_all_stats_sources();
}

/* ============================================================
 * BPF map manager.
 *
 * libnetworkstats.so (JNI behind NetworkStatsService) reads
 * per-UID / per-interface stats straight from the pinned BPF
 * maps under /sys/fs/bpf/netd_shared/.  When the GSI's
 * bpfloader is a stub (typical for PHH-patched GSIs) those
 * maps never exist, so every native lookup returns null and the
 * traffic indicator reads 0.
 *
 * We fix it by CREATING + PINNING the maps ourselves with the
 * exact layouts the native code expects (verified against the
 * BTF of netd.o shipped in the tethering APEX):
 *
 *   map_netd_app_uid_stats_map      HASH  key 4  (uid)        val 32 Stats
 *   map_netd_stats_map_A            HASH  key 16 (uid/tag/..) val 32 Stats
 *   map_netd_stats_map_B            HASH  key 16              val 32 Stats
 *   map_netd_iface_stats_map        HASH  key 4  (ifindex)    val 32 Stats
 *   map_netd_iface_index_name_map   HASH  key 4  (ifindex)    val 16 name
 *   map_netd_configuration_map      HASH  key 4               val 4
 *   map_netd_uid_owner_map          HASH  key 4               val 8
 *   map_netd_cookie_tag_map         HASH  key 8               val 8
 *   map_netd_uid_counterset_map     HASH  key 4               val 4
 *
 * Stats value layout (packets BEFORE bytes - matches BTF):
 *   { uint64 rxPackets; uint64 rxBytes; uint64 txPackets; uint64 txBytes; }
 *
 * Only maps that WE created (i.e. that did not exist before) are
 * populated with estimates from /proc/net/dev - maps that were
 * already present are left untouched so real eBPF accounting
 * keeps working on devices where bpfloader is functional.
 * ============================================================ */
static int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr) {
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

#define BPF_NETD_DIR "/sys/fs/bpf/netd_shared"

struct bpf_stats_value {           /* Stats from netd.o BTF: packets first */
    uint64_t rxPackets;
    uint64_t rxBytes;
    uint64_t txPackets;
    uint64_t txBytes;
} __attribute__((packed));

struct bpf_stats_key {             /* StatsKey from netd.o BTF */
    int32_t  uid;
    uint32_t tag;
    uint32_t counter_set;
    int32_t  iface_index;
} __attribute__((packed));

struct bpf_owner_value {           /* uid_owner_map value */
    int32_t  iif;
    int32_t  rule;
} __attribute__((packed));

struct bpf_iface_name_value {
    char name[16];
} __attribute__((packed));

enum {
    BPF_MAP_IDX_APP_UID_STATS = 0,
    BPF_MAP_IDX_STATS_A,
    BPF_MAP_IDX_STATS_B,
    BPF_MAP_IDX_IFACE_STATS,
    BPF_MAP_IDX_IFACE_INDEX_NAME,
    BPF_MAP_IDX_CONFIGURATION,
    BPF_MAP_IDX_UID_OWNER,
    BPF_MAP_IDX_COOKIE_TAG,
    BPF_MAP_IDX_UID_COUNTERSET,
    BPF_MAP_IDX_COUNT
};

struct bpf_map_def {
    const char* basename;      /* map_netd_... */
    uint32_t    type;          /* BPF_MAP_TYPE_HASH */
    uint32_t    key_size;
    uint32_t    value_size;
    uint32_t    max_entries;
};

static const struct bpf_map_def g_bpf_map_defs[BPF_MAP_IDX_COUNT] = {
    [BPF_MAP_IDX_APP_UID_STATS]     = { "map_netd_app_uid_stats_map",     BPF_MAP_TYPE_HASH, 4,  sizeof(struct bpf_stats_value), 16384 },
    [BPF_MAP_IDX_STATS_A]           = { "map_netd_stats_map_A",           BPF_MAP_TYPE_HASH, 16, sizeof(struct bpf_stats_value), 65536 },
    [BPF_MAP_IDX_STATS_B]           = { "map_netd_stats_map_B",           BPF_MAP_TYPE_HASH, 16, sizeof(struct bpf_stats_value), 65536 },
    [BPF_MAP_IDX_IFACE_STATS]       = { "map_netd_iface_stats_map",       BPF_MAP_TYPE_HASH, 4,  sizeof(struct bpf_stats_value), 512 },
    [BPF_MAP_IDX_IFACE_INDEX_NAME]  = { "map_netd_iface_index_name_map",  BPF_MAP_TYPE_HASH, 4,  16, 512 },
    [BPF_MAP_IDX_CONFIGURATION]     = { "map_netd_configuration_map",     BPF_MAP_TYPE_HASH, 4,  4,  32 },
    [BPF_MAP_IDX_UID_OWNER]         = { "map_netd_uid_owner_map",         BPF_MAP_TYPE_HASH, 4,  sizeof(struct bpf_owner_value), 8192 },
    [BPF_MAP_IDX_COOKIE_TAG]        = { "map_netd_cookie_tag_map",        BPF_MAP_TYPE_HASH, 8,  8,  32768 },
    [BPF_MAP_IDX_UID_COUNTERSET]    = { "map_netd_uid_counterset_map",    BPF_MAP_TYPE_HASH, 4,  4,  8192 },
};

static int g_bpf_fds[BPF_MAP_IDX_COUNT] = { [0 ... BPF_MAP_IDX_COUNT - 1] = -1 };
static int g_bpf_created[BPF_MAP_IDX_COUNT];
static int g_bpf_map_state_logged = 0;

static int ensure_bpffs(void) {
    struct stat st;
    if (stat("/sys/fs/bpf", &st) != 0) {
        if (mkdir("/sys/fs/bpf", 0755) != 0 && errno != EEXIST)
            log_msg("[BPF] mkdir /sys/fs/bpf failed errno=%d", errno);
    }
    if (stat(BPF_NETD_DIR, &st) != 0) {
        if (mkdir(BPF_NETD_DIR, 0700) != 0 && errno != EEXIST) {
            log_msg("[BPF] mkdir %s failed errno=%d", BPF_NETD_DIR, errno);
            return -1;
        }
        log_msg("[BPF] created dir %s", BPF_NETD_DIR);
    }
    chmod(BPF_NETD_DIR, 0700);
    return (stat(BPF_NETD_DIR, &st) == 0) ? 0 : -1;
}

static int bpf_create_map(const struct bpf_map_def* def) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type    = def->type;
    attr.key_size    = def->key_size;
    attr.value_size  = def->value_size;
    attr.max_entries = def->max_entries;
    return bpf_syscall(BPF_MAP_CREATE, &attr);
}

static int bpf_obj_get(const char* path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    return bpf_syscall(BPF_OBJ_GET, &attr);
}

static int bpf_obj_pin(int fd, const char* path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    attr.bpf_fd   = (uint32_t)fd;
    return bpf_syscall(BPF_OBJ_PIN, &attr);
}

static int bpf_update_elem(int fd, const void* key, const void* value) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = (uint64_t)(uintptr_t)key;
    attr.value  = (uint64_t)(uintptr_t)value;
    attr.flags  = BPF_ANY;
    return bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr);
}

static int bpf_delete_elem(int fd, const void* key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key    = (uint64_t)(uintptr_t)key;
    return bpf_syscall(BPF_MAP_DELETE_ELEM, &attr);
}

static int bpf_map_get_next_key(int fd, const void* key, void* next_key) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd    = (uint32_t)fd;
    attr.key       = (uint64_t)(uintptr_t)key;
    attr.next_key  = (uint64_t)(uintptr_t)next_key;
    return bpf_syscall(BPF_MAP_GET_NEXT_KEY, &attr);
}

static int bpf_map_has_entries(int fd) {
    if (fd < 0) return 0;
    uint64_t k = 0;
    return bpf_map_get_next_key(fd, NULL, &k) == 0;
}

/* Only fill a map that we created, or one that is completely empty
 * (native accounting on this GSI is dead anyway, so an empty map is ours
 * to seed; a non-empty map is left untouched to avoid corrupting real data). */
static int should_populate_map(int idx) {
    int fd = g_bpf_fds[idx];
    if (fd < 0) return 0;
    if (g_bpf_created[idx]) return 1;
    return !bpf_map_has_entries(fd);
}

static int open_or_create_bpf_map(int idx) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", BPF_NETD_DIR, g_bpf_map_defs[idx].basename);

    if (g_bpf_fds[idx] >= 0) {
        if (access(path, F_OK) == 0)
            return g_bpf_fds[idx];
        log_msg("[BPF] %s pin vanished, recreating", g_bpf_map_defs[idx].basename);
        close(g_bpf_fds[idx]);
        g_bpf_fds[idx] = -1;
        g_bpf_created[idx] = 0;
    }

    int fd;
    if (access(path, F_OK) == 0) {
        fd = bpf_obj_get(path);
        if (fd >= 0) {
            g_bpf_fds[idx] = fd;
            g_bpf_created[idx] = 0;
            if (!g_bpf_map_state_logged)
                log_msg("[BPF] existing %s (fd=%d) - native accounting, NOT faking", g_bpf_map_defs[idx].basename, fd);
            return fd;
        }
        log_msg("[BPF] obj_get %s failed (errno=%d) - recreating", g_bpf_map_defs[idx].basename, errno);
    }

    fd = bpf_create_map(&g_bpf_map_defs[idx]);
    if (fd < 0) {
        log_msg("[BPF] MAP_CREATE %s failed: errno=%d (%s)",
                g_bpf_map_defs[idx].basename, errno, strerror(errno));
        return -1;
    }

    if (bpf_obj_pin(fd, path) == 0) {
        g_bpf_fds[idx] = fd;
        g_bpf_created[idx] = 1;
        log_msg("[BPF] created+pinned %s (fd=%d key=%u val=%u max=%u)",
                g_bpf_map_defs[idx].basename, fd,
                g_bpf_map_defs[idx].key_size, g_bpf_map_defs[idx].value_size,
                g_bpf_map_defs[idx].max_entries);
        return fd;
    }

    int perr = errno;
    log_msg("[BPF] PIN %s failed: errno=%d (%s)", g_bpf_map_defs[idx].basename, perr, strerror(perr));
    close(fd);
    if (perr == EEXIST) {
        fd = bpf_obj_get(path);
        if (fd >= 0) {
            g_bpf_fds[idx] = fd;
            g_bpf_created[idx] = 0;
            log_msg("[BPF] recovered %s (fd=%d)", g_bpf_map_defs[idx].basename, fd);
            return fd;
        }
    }
    return -1;
}

static int open_all_bpf_maps(void) {
    if (ensure_bpffs() != 0) return -1;
    int ok = 0;
    for (int i = 0; i < BPF_MAP_IDX_COUNT; i++) {
        if (open_or_create_bpf_map(i) >= 0) ok++;
    }
    if (ok != BPF_MAP_IDX_COUNT && !g_bpf_map_state_logged) {
        log_msg("[BPF] created/opened %d/%d maps (some may be native-locked)",
                ok, BPF_MAP_IDX_COUNT);
    }
    g_bpf_map_state_logged = 1;
    return (g_bpf_fds[BPF_MAP_IDX_APP_UID_STATS] >= 0) ? 0 : -1;
}

static int iface_index(const char* ifname) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    int r = ioctl(s, SIOCGIFINDEX, &ifr);
    close(s);
    return (r == 0) ? ifr.ifr_ifindex : 0;
}

static void bpf_fill_stats_value(struct bpf_stats_value* v, const struct net_stats* n) {
    v->rxPackets = n->rxPackets;
    v->rxBytes   = n->rxBytes;
    v->txPackets = n->txPackets;
    v->txBytes   = n->txBytes;
}

static void populate_bpf_maps(void) {
    if (open_all_bpf_maps() != 0) return;

    struct iface_stat ifaces[MAX_IFACES];
    int count = 0;
    read_all_ifaces(ifaces, &count);

    struct net_stats total;
    read_all_stats(&total);

    int have_iface = (g_bpf_fds[BPF_MAP_IDX_IFACE_STATS] >= 0 || g_bpf_fds[BPF_MAP_IDX_IFACE_INDEX_NAME] >= 0);
    if (have_iface) {
        for (int i = 0; i < count; i++) {
            int idx = iface_index(ifaces[i].name);
            if (idx <= 0) continue;

            if (should_populate_map(BPF_MAP_IDX_IFACE_INDEX_NAME)) {
                struct bpf_iface_name_value nv;
                memset(&nv, 0, sizeof(nv));
                strncpy(nv.name, ifaces[i].name, sizeof(nv.name) - 1);
                int ret = bpf_update_elem(g_bpf_fds[BPF_MAP_IDX_IFACE_INDEX_NAME], &idx, &nv);
                if (ret != 0)
                    log_msg("[BPF] iface_index_name %s(%d) failed: errno=%d", ifaces[i].name, idx, errno);
            }

            if (should_populate_map(BPF_MAP_IDX_IFACE_STATS)) {
                struct bpf_stats_value v;
                struct net_stats n;
                memset(&n, 0, sizeof(n));
                n.rxBytes = ifaces[i].rxBytes;   n.rxPackets = ifaces[i].rxPackets;
                n.txBytes = ifaces[i].txBytes;   n.txPackets = ifaces[i].txPackets;
                bpf_fill_stats_value(&v, &n);
                if (bpf_update_elem(g_bpf_fds[BPF_MAP_IDX_IFACE_STATS], &idx, &v) != 0)
                    log_msg("[BPF] iface_stats %s(%d) failed: errno=%d", ifaces[i].name, idx, errno);
            }
        }
    }

    /* Collect UIDs: system UIDs + running app UIDs from /proc */
    int uids[256];
    int uidc = 0;
    int base_uids[] = {1000, 1001, 10027, 1013, 1021, 1023, 1027, 1028, 1029, 1037,
                       1038, 1039, 1041, 1044, 1045, 1046, 1047, 2000, 2001, 9999};
    for (int i = 0; i < (int)(sizeof(base_uids)/sizeof(base_uids[0])) && uidc < 250; i++)
        uids[uidc++] = base_uids[i];

    DIR* proc = opendir("/proc");
    if (proc) {
        struct dirent* entry;
        while ((entry = readdir(proc)) && uidc < 250) {
            int pid = atoi(entry->d_name);
            if (pid <= 0) continue;
            char path[256];
            snprintf(path, sizeof(path), "/proc/%d/status", pid);
            FILE* sf = fopen(path, "r");
            if (!sf) continue;
            char sl[256];
            while (fgets(sl, sizeof(sl), sf)) {
                if (strncmp(sl, "Uid:", 4) == 0) {
                    int ruid;
                    sscanf(sl, "Uid:\t%d", &ruid);
                    if (ruid >= 10000) {
                        int dup = 0;
                        for (int j = 0; j < uidc; j++)
                            if (uids[j] == ruid) { dup = 1; break; }
                        if (!dup) uids[uidc++] = ruid;
                    }
                    break;
                }
            }
            fclose(sf);
        }
        closedir(proc);
    }

    int have_uid = (g_bpf_fds[BPF_MAP_IDX_APP_UID_STATS] >= 0 || g_bpf_fds[BPF_MAP_IDX_STATS_A] >= 0);
    if (!have_uid || uidc == 0) return;

    uint64_t per_uid_rx = total.rxBytes / (uint64_t)uidc;
    uint64_t per_uid_tx = total.txBytes / (uint64_t)uidc;
    uint64_t per_uid_rxp = total.rxPackets / (uint64_t)uidc;
    uint64_t per_uid_txp = total.txPackets / (uint64_t)uidc;

    struct bpf_stats_value v;
    struct net_stats n;
    n.rxBytes = per_uid_rx; n.rxPackets = per_uid_rxp;
    n.txBytes = per_uid_tx; n.txPackets = per_uid_txp;
    bpf_fill_stats_value(&v, &n);

    for (int i = 0; i < uidc; i++) {
        uint32_t uid = (uint32_t)uids[i];

        if (should_populate_map(BPF_MAP_IDX_APP_UID_STATS)) {
            if (bpf_update_elem(g_bpf_fds[BPF_MAP_IDX_APP_UID_STATS], &uid, &v) != 0)
                log_msg("[BPF] app_uid_stats uid=%u failed: errno=%d", uid, errno);
        }

        if (should_populate_map(BPF_MAP_IDX_STATS_A)) {
            struct bpf_stats_key k;
            memset(&k, 0, sizeof(k));
            k.uid = (int32_t)uid;
            k.tag = 0;
            k.counter_set = 0;
            k.iface_index = 0;
            if (bpf_update_elem(g_bpf_fds[BPF_MAP_IDX_STATS_A], &k, &v) != 0)
                log_msg("[BPF] stats_map_A uid=%u failed: errno=%d", uid, errno);
        }

        /* stats_map_B intentionally left empty: the reader sums A+B,
         * writing both would double-count. */

        if (should_populate_map(BPF_MAP_IDX_UID_OWNER)) {
            struct bpf_owner_value ov;
            memset(&ov, 0, sizeof(ov));
            ov.iif = 0;
            ov.rule = 1;
            if (bpf_update_elem(g_bpf_fds[BPF_MAP_IDX_UID_OWNER], &uid, &ov) != 0 &&
                errno != EEXIST)
                log_msg("[BPF] uid_owner uid=%u failed: errno=%d", uid, errno);
        }
    }

    static time_t last_log = 0;
    time_t now = time(NULL);
    if (now - last_log >= 60) {
        log_msg("[BPF] fake stats: %d UIDs rx=%" PRIu64 " tx=%" PRIu64 " (per-uid rx=%" PRIu64 " tx=%" PRIu64 ")",
                uidc, total.rxBytes, total.txBytes, per_uid_rx, per_uid_tx);
        last_log = now;
    }
}

/* ============================================================
 * Improved /proc/uid_stat/ writer
 * Uses multiple strategies to create the directory:
 * 1. mount tmpfs directly
 * 2. write to /data/local/tmp/uid_stat and symlink
 * 3. mkdir + chmod
 * ============================================================ */
static int setup_proc_uid_stat(void) {
    /* Strategy 1: mount tmpfs on /proc/uid_stat */
    mkdir("/proc/uid_stat", 0755);
    int ret = mount("tmpfs", "/proc/uid_stat", "tmpfs", 0, NULL);
    if (ret == 0) {
        log_msg("[UID_STAT] Mounted tmpfs on /proc/uid_stat");
        chmod("/proc/uid_stat", 0755);
        /* Update owner to system (UID 1000) */
        chown("/proc/uid_stat", 1000, 1000);
        return 1;
    }
    log_msg("[UID_STAT] tmpfs mount failed (errno=%d), trying bind mount...", errno);
    /* Strategy 2: try bind mount from a tmp dir */
    mkdir("/data/local/tmp/uid_stat", 0755);
    mount("tmpfs", "/data/local/tmp/uid_stat", "tmpfs", 0, NULL);
    chmod("/data/local/tmp/uid_stat", 0755);
    chown("/data/local/tmp/uid_stat", 1000, 1000);
    ret = mount("/data/local/tmp/uid_stat", "/proc/uid_stat", NULL, MS_BIND, NULL);
    if (ret == 0) {
        log_msg("[UID_STAT] Bind mount succeeded");
        return 2;
    }
    log_msg("[UID_STAT] Bind mount failed (errno=%d), using direct mkdir", errno);
    /* Strategy 3: just mkdir (won't persist but worth trying) */
    mkdir("/proc/uid_stat", 0755);
    chmod("/proc/uid_stat", 0755);
    chown("/proc/uid_stat", 1000, 1000);
    return 0;
}

static void write_uid_stat_entry(int uid, uint64_t rx, uint64_t tx) {
    char dir_path[128];
    snprintf(dir_path, sizeof(dir_path), "/proc/uid_stat/%d", uid);
    mkdir(dir_path, 0755);
    chmod(dir_path, 0755);
    chown(dir_path, 1000, 1000);

    char path[256];
    snprintf(path, sizeof(path), "%s/tcp_rcv", dir_path);
    FILE* f = fopen(path, "w");
    if (f) {
        fprintf(f, "%" PRIu64 "\n", rx);
        fclose(f);
        chmod(path, 0644);
    } else {
        /* Fallback: write to /data/local/tmp/uid_stat */
        char alt[256];
        snprintf(alt, sizeof(alt), "/data/local/tmp/uid_stat/%d/tcp_rcv", uid);
        mkdir("/data/local/tmp/uid_stat", 0755);
        char alt_dir[256];
        snprintf(alt_dir, sizeof(alt_dir), "/data/local/tmp/uid_stat/%d", uid);
        mkdir(alt_dir, 0755);
        f = fopen(alt, "w");
        if (f) { fprintf(f, "%" PRIu64 "\n", rx); fclose(f); }
    }

    snprintf(path, sizeof(path), "%s/tcp_snd", dir_path);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "%" PRIu64 "\n", tx);
        fclose(f);
        chmod(path, 0644);
    } else {
        char alt[256];
        snprintf(alt, sizeof(alt), "/data/local/tmp/uid_stat/%d/tcp_snd", uid);
        f = fopen(alt, "w");
        if (f) { fprintf(f, "%" PRIu64 "\n", tx); fclose(f); }
    }
}

static void populate_uid_stat_all(void) {
    /* Ensure /proc/uid_stat is set up */
    struct stat st;
    if (stat("/proc/uid_stat", &st) != 0 || !S_ISDIR(st.st_mode)) {
        int ret = setup_proc_uid_stat();
        if (ret == 0) {
            /* Check again after setup */
            if (stat("/proc/uid_stat", &st) != 0 || !S_ISDIR(st.st_mode)) {
                log_msg("[UID_STAT] Could not create /proc/uid_stat at all");
                return;
            }
        }
    }

    struct net_stats total;
    if (read_all_stats(&total) != 0) return;

    /* Common system UIDs */
    int base_uids[] = {1000, 1001, 10027, 1013, 1021, 1023, 1027, 1028, 1029, 1037,
                       1038, 1039, 1041, 1044, 1045, 1046, 1047, 2000, 2001, 9999};
    int uid_count = (int)(sizeof(base_uids)/sizeof(base_uids[0]));

    uint64_t per_uid_rx = total.rxBytes / (uint64_t)(uid_count > 0 ? uid_count : 1);
    uint64_t per_uid_tx = total.txBytes / (uint64_t)(uid_count > 0 ? uid_count : 1);

    for (int i = 0; i < uid_count; i++) {
        write_uid_stat_entry(base_uids[i], per_uid_rx, per_uid_tx);
    }

    log_msg("[UID_STAT] Wrote %d entries (rx=%" PRIu64 " tx=%" PRIu64 " per_uid)",
            uid_count, per_uid_rx, per_uid_tx);
}

/* ============================================================
 * xt_qtaguid loader - try loading the kernel module on old kernels
 * ============================================================ */
static void try_load_xt_qtaguid(void) {
    struct stat st;
    if (stat("/proc/net/xt_qtaguid/stats", &st) == 0) {
        log_msg("[XT_QTAGUID] Already available");
        chmod("/proc/net/xt_qtaguid/stats", 0644);
        return;
    }

    const char* modules[] = {
        "/vendor/lib/modules/xt_qtaguid.ko",
        "/system/lib/modules/xt_qtaguid.ko",
        "/vendor_dlkm/lib/modules/xt_qtaguid.ko",
        "/system_dlkm/lib/modules/xt_qtaguid.ko",
        NULL
    };

    for (int i = 0; modules[i]; i++) {
        if (stat(modules[i], &st) == 0) {
            log_msg("[XT_QTAGUID] Trying insmod %s", modules[i]);
            int ret = (int)syscall(__NR_init_module, modules[i],
                                   (unsigned long)st.st_size, "");
            if (ret == 0) {
                log_msg("[XT_QTAGUID] Loaded %s successfully", modules[i]);
                /* Create device node if needed */
                if (stat("/dev/xt_qtaguid", &st) != 0) {
                    mknod("/dev/xt_qtaguid", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
                          makedev(10, 229));
                    chmod("/dev/xt_qtaguid", 0666);
                }
                chmod("/proc/net/xt_qtaguid/stats", 0644);
                return;
            } else {
                log_msg("[XT_QTAGUID] insmod %s failed: errno=%d", modules[i], errno);
            }
        }
    }
    log_msg("[XT_QTAGUID] No xt_qtaguid module found");
}

/* ============================================================
 * Write all stats sources at once
 * ============================================================ */
static void write_all_stats_sources(void) {
    write_stats_file();
    update_uid_stats();
    populate_bpf_maps();
    populate_uid_stat_all();
    write_netstats_xml();
    try_load_xt_qtaguid();
}

/* ============================================================
 * Main event loop
 * ============================================================ */
static void run_event_loop(void) {
    uint8_t* rbuf = (uint8_t*)malloc(BINDER_BUF_SIZE);
    if (!rbuf) { log_msg("FATAL: malloc failed for read buffer"); return; }
    log_msg("Entering main event loop...");
    int consecutive_errors = 0;
    int loop_count = 0;
    time_t last_stats_update = 0;
    time_t last_uid_update __attribute__((unused)) = 0;
    int no_txn_count = 0;

    while (1) {
        size_t consumed = 0;
        int ret = send_bc_with_reply(NULL, 0, rbuf, BINDER_BUF_SIZE, &consumed);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) { usleep(10000); continue; }
            consecutive_errors++;
            log_errno("main loop read");
            if (consecutive_errors > 10) {
                log_msg("Too many consecutive errors (%d), re-opening binder...", consecutive_errors);
                if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
                if (binder_fd >= 0) close(binder_fd);
                binder_fd = -1; binder_map = NULL;
                sleep(5);
                if (open_binder() == 0) {
                    uint32_t c = BC_ENTER_LOOPER;
                    send_binder_cmd(&c, sizeof(c));
                    log_msg("Binder re-opened successfully");
                    consecutive_errors = 0;
                } else {
                    log_msg("Binder re-open FAILED, will retry later");
                    sleep(10);
                }
            }
            usleep(500000); continue;
        }
        consecutive_errors = 0;

        if (consumed == 0) {
            loop_count++;
            time_t now_t = time(NULL);

            if (now_t - last_stats_update >= 15) {
                write_all_stats_sources();
                last_stats_update = now_t;
            }

            no_txn_count++;
            if (no_txn_count == 60) {
                log_msg("[EVENT-LOOP] NO_TRANSACTIONS for ~60s - SystemUI may not be using netproxy");
                log_msg("[EVENT-LOOP] Check if SystemUI was restarted after registration");
                FILE* sf = fopen("/data/local/tmp/netproxy_no_txns", "w");
                if (sf) {
                    fprintf(sf, "no_transactions_since=%ld\nservicename=%s\nversion=%s\n",
                            (long)now_t, g_registered_name, NETPROXY_VERSION);
                    fclose(sf);
                }
            }
            if (no_txn_count % 600 == 0) {
                log_msg("[EVENT-LOOP] alive: loops=%d txns=%d sessions=%d no_txn_cycles=%d",
                        loop_count, g_total_txns, session_count, no_txn_count);
                log_msg("[EVENT-LOOP]  proc_net_dev: rx=%" PRIu64 " tx=%" PRIu64,
                        g_prev_stats.rxBytes, g_prev_stats.txBytes);
            }

            usleep(50000);
            continue;
        }

        no_txn_count = 0;
        const uint8_t* rp = rbuf;
        const uint8_t* rend = rbuf + consumed;
        while (rp < rend) {
            if (rp + 4 > rend) break;
            uint32_t cmd; memcpy(&cmd, rp, 4); rp += 4;

            switch (cmd) {
                case BR_TRANSACTION: {
                    if (rp + sizeof(struct binder_transaction_data) > rend) goto loop_end;
                    const struct binder_transaction_data* trp =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*trp);
                    handle_transaction(trp);
                    break;
                }
                case BR_REPLY: {
                    g_br_reply_count++;
                    if (rp + sizeof(struct binder_transaction_data) > rend) goto loop_end;
                    const struct binder_transaction_data* trp =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*trp);
                    uint8_t fcmd[4+8];
                    *(uint32_t*)fcmd = BC_FREE_BUFFER;
                    memcpy(fcmd+4, &trp->data.ptr.buffer, 8);
                    send_binder_cmd(fcmd, sizeof(fcmd));
                    break;
                }
                case BR_ACQUIRE:
                case BR_INCREFS: {
                    if (rp + 16 > rend) goto loop_end;
                    rp += 16;
                    uint8_t ack[4+16];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memset(ack+4, 0, 16);
                    send_binder_cmd(ack, sizeof(ack));
                    break;
                }
                case BR_RELEASE:
                case BR_DECREFS:
                    if (rp + 16 <= rend) rp += 16;
                    break;
                case BR_SPAWN_LOOPER:
                    { uint32_t c = BC_ENTER_LOOPER; send_binder_cmd(&c, sizeof(c)); }
                    break;
                case BR_TRANSACTION_COMPLETE:
                case BR_NOOP:
                case BR_FINISHED:
                    break;
                case BR_DEAD_BINDER:
                case BR_CLEAR_DEATH_NOTIFICATION_DONE:
                    if (rp + 8 <= rend) rp += 8;
                    break;
                case BR_FAILED_REPLY:
                    g_br_error_count++;
                    log_msg("[BR] FAILED_REPLY #%d (total=%d)", g_br_error_count, g_br_error_count);
                    break;
                case BR_DEAD_REPLY:
                    g_br_dead_count++;
                    log_msg("[BR] DEAD_REPLY #%d (total=%d)", g_br_dead_count, g_br_dead_count);
                    break;
                case BR_ERROR: {
                    g_br_error_count++;
                    int32_t berr = 0;
                    if (rp + 4 <= rend) memcpy(&berr, rp, 4);
                    log_msg("[BR] ERROR=%d #%d", berr, g_br_error_count);
                    if (rp + 4 <= rend) rp += 4;
                    break;
                }
                default:
                    g_br_other_count++;
                    log_msg("[BR] unknown cmd 0x%x (total=%d)", cmd, g_br_other_count);
                    goto loop_end;
            }
        }
        loop_end:;
    }
    free(rbuf);
}

static void sig_handler(int sig) {
    log_msg("Signal %d received, exiting", sig);
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    _exit(0);
}

/* ============================================================
 * Write netstats XML to /data/misc/netstats/
 * This feeds NetworkStatsService on next boot/reload
 * ============================================================ */
static void write_netstats_xml(void) {
    struct iface_stat ifaces[MAX_IFACES];
    int count = 0;
    if (read_all_ifaces(ifaces, &count) != 0) return;
    struct net_stats total;
    read_all_stats(&total);

    const char* dir = "/data/misc/netstats";
    mkdir(dir, 0770);
    chown(dir, 1000, 1000);
    chmod(dir, 0770);

    /* Write dev stats XML */
    char path[256];
    snprintf(path, sizeof(path), "%s/netstats_dev.xml", dir);
    FILE* f = fopen(path, "w");
    if (!f) { log_msg("Cannot write %s: errno=%d", path, errno); return; }

    fprintf(f, "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n");
    fprintf(f, "<stats devDetail=\"true\">\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "<st if=\"%s\" dev=\"%s\" uid=\"-1\" tag=\"0x0\" set=\"default\" "
                "rb=\"%" PRIu64 "\" rp=\"%" PRIu64 "\" tb=\"%" PRIu64 "\" tp=\"%" PRIu64 "\" />\n",
                ifaces[i].name, ifaces[i].name,
                ifaces[i].rxBytes, ifaces[i].rxPackets,
                ifaces[i].txBytes, ifaces[i].txPackets);
    }
    fprintf(f, "</stats>\n");
    fclose(f);
    chmod(path, 0644);
    chown(path, 1000, 1000);

    /* Write UID stats XML */
    snprintf(path, sizeof(path), "%s/netstats_uid.xml", dir);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n");
        fprintf(f, "<stats uidStats=\"true\">\n");
        for (int i = 0; i < g_uid_count && i < MAX_UID_STATS; i++) {
            if (g_uid_stats[i].uid == 0) continue;
            fprintf(f, "<st uid=\"%d\" tag=\"0x0\" set=\"0\" "
                    "rxBytes=\"%" PRIu64 "\" txBytes=\"%" PRIu64 "\" "
                    "rxPackets=\"%" PRIu64 "\" txPackets=\"%" PRIu64 "\" />\n",
                    g_uid_stats[i].uid, g_uid_stats[i].rxBytes, g_uid_stats[i].txBytes,
                    g_uid_stats[i].rxBytes / 1500, g_uid_stats[i].txBytes / 1500);
        }
        fprintf(f, "</stats>\n");
        fclose(f);
        chmod(path, 0644);
        chown(path, 1000, 1000);
    }

    log_msg("Wrote netstats XML: %d ifaces, %d uids", count, g_uid_count);
}

/* ============================================================
 * main
 * ============================================================ */
int main(int argc, char* argv[]) {
    g_start_time = time(NULL);

    /* Special mode: create + pin + prime the netd BPF maps once, then exit.
     * Used from post-fs-data.sh so the maps exist before system_server
     * (and therefore libnetworkstats.so) starts. */
    if (argc > 1 && strcmp(argv[1], "--maps") == 0) {
        log_msg("netproxy --maps mode: creating netd BPF maps");
        int r = open_all_bpf_maps();
        if (r == 0) {
            populate_bpf_maps();
            int missing = 0;
            for (int i = 0; i < BPF_MAP_IDX_COUNT; i++) {
                char path[256];
                snprintf(path, sizeof(path), "%s/%s", BPF_NETD_DIR, g_bpf_map_defs[i].basename);
                int ok = (access(path, F_OK) == 0);
                if (!ok) missing++;
                log_msg("[BPF] verify %s: %s", g_bpf_map_defs[i].basename,
                        ok ? "present" : "MISSING");
            }
            log_msg("netproxy --maps done: %d/%d maps present", BPF_MAP_IDX_COUNT - missing,
                    BPF_MAP_IDX_COUNT);
            return missing == 0 ? 0 : 2;
        } else {
            log_msg("netproxy --maps FAILED to create BPF maps (errno=%d %s)",
                    errno, strerror(errno));
            return 3;
        }
    }

    log_msg("==============================================");
    log_msg("  Native netproxy v%s starting", NETPROXY_VERSION);
    log_msg("==============================================");

    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sig_handler);
    signal(SIGINT,  sig_handler);
    signal(SIGPIPE, SIG_IGN);

    log_msg("PID=%d UID=%d GID=%d", getpid(), getuid(), getgid());
    const char* ctx = getenv("SELINUX_CONTEXT");
    log_msg("SELinux context: %s", ctx ? ctx : "unknown");
    log_msg("SELinux mode: %s", ctx && strstr(ctx, "permissive") ? "permissive" : "enforcing (or unknown)");

    struct net_stats s;
    if (read_all_stats(&s) == 0) {
        g_prev_stats = s;
        log_msg("Initial /proc/net/dev: rx=%" PRIu64 " tx=%" PRIu64 " rxp=%" PRIu64 " txp=%" PRIu64,
                s.rxBytes, s.txBytes, s.rxPackets, s.txPackets);

        struct iface_stat ifaces[MAX_IFACES];
        int count = 0;
        if (read_all_ifaces(ifaces, &count) == 0) {
            log_msg("Active interfaces (%d):", count);
            for (int i = 0; i < count && i < 20; i++) {
                log_msg("  %s: rx=%" PRIu64 " tx=%" PRIu64,
                        ifaces[i].name, ifaces[i].rxBytes, ifaces[i].txBytes);
            }
        }
    } else {
        log_msg("WARNING: cannot read /proc/net/dev (errno=%d)", errno);
    }

    /* Check existing services */
    log_msg("Checking existing services...");
    const char* check_list[] = {"netstats", "netstats_service", "connectivity", "network_management", NULL};
    for (int i = 0; check_list[i]; i++) {
        int ret = aidl_check_service(check_list[i]);
        log_msg("Service '%s': %s", check_list[i],
                ret > 0 ? "EXISTS" : (ret == 0 ? "not found" : "error"));
    }

    /* Setup proc uid stat and write all stats sources early */
    setup_proc_uid_stat();
    populate_uid_stat_all();
    try_load_xt_qtaguid();

    /* Open binder */
    if (open_binder() < 0) {
        log_msg("Cannot open binder, running in passive mode (file/BPF/uid_stat stats)");
        while (1) {
            write_all_stats_sources();
            sleep(15);
        }
        return 1;
    }

    {
        uint32_t c = BC_ENTER_LOOPER;
        int r = send_binder_cmd(&c, sizeof(c));
        if (r < 0) {
            log_msg("enter_looper failed (errno=%d), trying again...", errno);
            sleep(1);
            send_binder_cmd(&c, sizeof(c));
        }
    }
    log_msg("Looper entered");

    log_msg("Binder initialized, writing all stats...");
    write_all_stats_sources();

    /* Try to register with ServiceManager */
    main_service_ptr = (uint64_t)(uintptr_t)(binder_map + 512);
    main_service_cookie = main_service_ptr;

    log_msg("Using main service binder ptr: 0x%" PRIx64, main_service_ptr);

    /* Write all stats sources immediately - don't wait for registration */
    write_all_stats_sources();

    int registered = 0;
    /* Only try to register as 'netstats' - the real service name */
    const char* TARGET_SERVICE = "netstats";
    for (int round = 0; round < 10 && !registered; round++) {
        log_msg("--- Registration round %d/10 (target='%s') ---", round + 1, TARGET_SERVICE);

        int exists = aidl_check_service(TARGET_SERVICE);
        if (exists > 0) {
            log_msg("[REG] '%s' ALREADY EXISTS, trying to override", TARGET_SERVICE);
        } else if (exists == 0) {
            log_msg("[REG] '%s' not found - good, we will add it", TARGET_SERVICE);
        }

        int ret = aidl_add_service(TARGET_SERVICE, main_service_ptr, main_service_cookie);
        if (ret >= 0) {
            log_msg("*** REGISTERED as '%s'! (round %d) ***", TARGET_SERVICE, round + 1);
            registered = 1;
            g_registered_service_idx = 0;
            strncpy(g_registered_name, TARGET_SERVICE, sizeof(g_registered_name) - 1);

            FILE* rf = fopen(REGFILE, "w");
            if (rf) {
                fprintf(rf, "registered=1\nservice=%s\nversion=%s\npid=%d\n"
                        "timestamp=%ld\n",
                        TARGET_SERVICE, NETPROXY_VERSION, getpid(), (long)time(NULL));
                fclose(rf);
            }
            chmod(REGFILE, 0644);
            break;
        }

        if (!registered) {
            int wait_sec = 3 + round * 2;
            log_msg("[REG] Round %d FAILED for '%s', waiting %ds before retry...",
                    round + 1, TARGET_SERVICE, wait_sec);
            sleep(wait_sec);

            /* Log SELinux denials */
            FILE* dp = popen("dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|netstats|binder' | tail -20", "r");
            if (dp) {
                char line[512];
                while (fgets(line, sizeof(line), dp)) {
                    line[strcspn(line, "\n")] = 0;
                    log_msg("  SELINUX: %s", line);
                }
                pclose(dp);
            }

            /* Log ServiceManager state */
            FILE* sp = popen("dmesg 2>/dev/null | grep -i 'service_manager' | tail -10", "r");
            if (sp) {
                char line[512];
                while (fgets(line, sizeof(line), sp)) {
                    line[strcspn(line, "\n")] = 0;
                    log_msg("  SM: %s", line);
                }
                pclose(sp);
            }

            /* Retry stats writing between rounds */
            write_all_stats_sources();
        }
    }

    if (!registered) {
        log_msg("WARNING: could not register with ServiceManager after 10 rounds");
        log_msg("Falling back to passive file/BPF/uid_stat mode");
        unlink(REGFILE);
        while (1) {
            write_all_stats_sources();
            sleep(15);
        }
    }

    log_msg("=== Entering main event loop ===");
    log_msg("registered=%d sessions=%d name=%s",
            registered, session_count, g_registered_name);
    run_event_loop();

    log_msg("Exiting main");
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    return 0;
}
