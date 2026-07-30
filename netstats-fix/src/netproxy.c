#define _GNU_SOURCE
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

#define LOGFILE "/data/local/tmp/netproxy.log"
#define STATSFILE "/data/local/tmp/netproxy_stats"
#define REGFILE "/data/local/tmp/netproxy_registered"
#define NETPROXY_VERSION "8.0"
#define SESSION_BASE 0x10000
#define MAX_SESSIONS 32
#define MAX_IFACES 32
#define BINDER_MMAP_SIZE (4 * 1024 * 1024)
#define BINDER_BUF_SIZE  (256 * 1024)

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
#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100

#define SM_HANDLE 0

/* ============================================================
 * REAL INetworkStatsService AIDL transaction codes (Android 14+)
 * ============================================================ */
#define TX_openSession                  1
#define TX_openSessionForUsageStats     2
#define TX_getDataLayerSnapshotForUid   3
#define TX_getUidStatsForTransport      4
#define TX_getMobileIfaces              5
#define TX_incrementOperationCount      6
#define TX_notifyNetworkStatus          7
#define TX_forceUpdate                  8
#define TX_registerUsageCallback        9
#define TX_unregisterUsageRequest       10
#define TX_getUidStats                  11
#define TX_getIfaceStats                12
#define TX_getTotalStats                13
#define TX_registerNetworkStatsProvider 14
#define TX_noteUidForeground            15
#define TX_advisePersistThreshold       16
#define TX_setStatsProviderWarningAndLimitAsync 17
#define TX_getRateLimitCacheConfig      18

/* ============================================================
 * INetworkStatsSession transaction codes
 * ============================================================ */
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

/* Standard AIDL codes */
#define TX_GET_INTERFACE_VERSION 16777215
#define TX_GET_INTERFACE_HASH    16777216

/* Legacy/fallback codes for patched GSIs (use high values to avoid collision) */
#define TX_LEGACY_GET_TOTAL_STATS   10001
#define TX_LEGACY_GET_IFACE_STATS   10002
#define TX_LEGACY_FORCE_UPDATE      10003
#define TX_LEGACY_GET_UID_STATS     10004

#define TYPE_RX_BYTES   0
#define TYPE_TX_BYTES   1
#define TYPE_RX_PACKETS 2
#define TYPE_TX_PACKETS 3

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

struct binder_ptr_cookie {
    uint64_t ptr;
    uint64_t cookie;
};

struct binder_pri_ptr_cookie {
    int32_t priority;
    uint64_t ptr;
    uint64_t cookie;
};

#define BINDER_WRITE_READ        0xC0306201
#define BINDER_VERSION           0xC0186209
#define BINDER_SET_MAX_THREADS   0x40086205

/* ============================================================
 * Logging
 * ============================================================ */
static FILE* log_fp = NULL;
static int log_line_count = 0;

static void log_open(void) {
    if (!log_fp) {
        log_fp = fopen(LOGFILE, "a");
        if (log_fp) setbuf(log_fp, NULL);
    }
}

static void log_msg(const char* msg) {
    log_open();
    if (!log_fp) return;
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    if (tm_info) {
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(log_fp, "%s [NETPROXY-v8] %s\n", ts, msg);
    } else {
        fprintf(log_fp, "[NETPROXY-v8] %s\n", msg);
    }
    log_line_count++;
}

static void log_errno(const char* ctx) {
    char buf[256];
    snprintf(buf, sizeof(buf), "ERROR %s: errno=%d (%s)", ctx, errno, strerror(errno));
    log_msg(buf);
}

__attribute__((format(printf,1,2)))
static void log_fmt(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_msg(buf);
}

/* ============================================================
 * /proc/net/dev reader
 * ============================================================ */
struct net_stats { uint64_t rxBytes, rxPackets, txBytes, txPackets; };
struct iface_stat { char name[64]; uint64_t rxBytes, rxPackets, txBytes, txPackets; };

static int read_iface_stats(const char* iface, struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char* p = line; while (*p == ' ' || *p == '\t') p++;
        size_t ilen = strlen(iface);
        if (strncmp(p, iface, ilen) == 0 && p[ilen] == ':') {
            char* vals = p + ilen + 1;
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
    char line[512];
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
    char line[512];
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
        char* vals = colon + 1; int col = 0; char* saveptr;
        char* tok = strtok_r(vals, " \t\n\r", &saveptr);
        while (tok && col <= 9) {
            uint64_t v = strtoull(tok, NULL, 10);
            if      (col == 0) ifaces[*count].rxBytes   = v;
            else if (col == 1) ifaces[*count].rxPackets  = v;
            else if (col == 8) ifaces[*count].txBytes    = v;
            else if (col == 9) ifaces[*count].txPackets  = v;
            col++; tok = strtok_r(NULL, " \t\n\r", &saveptr);
        }
        (*count)++;
    }
    fclose(f); return 0;
}

static void update_stats_file_detailed(void) {
    struct iface_stat ifaces[MAX_IFACES];
    int count = 0;
    if (read_all_ifaces(ifaces, &count) != 0) return;
    FILE* f = fopen(STATSFILE, "w");
    if (!f) return;
    uint64_t trx = 0, ttx = 0, trxp = 0, ttxp = 0;
    for (int i = 0; i < count; i++) {
        trx += ifaces[i].rxBytes; trxp += ifaces[i].rxPackets;
        ttx += ifaces[i].txBytes; ttxp += ifaces[i].txPackets;
        fprintf(f, "iface_%s_rx=%llu\niface_%s_tx=%llu\niface_%s_rxp=%llu\niface_%s_txp=%llu\n",
                ifaces[i].name, (unsigned long long)ifaces[i].rxBytes,
                ifaces[i].name, (unsigned long long)ifaces[i].txBytes,
                ifaces[i].name, (unsigned long long)ifaces[i].rxPackets,
                ifaces[i].name, (unsigned long long)ifaces[i].txPackets);
    }
    fprintf(f, "rx_bytes=%llu\ntx_bytes=%llu\nrx_packets=%llu\ntx_packets=%llu\niface_count=%d\ntimestamp=%lu\n",
            (unsigned long long)trx, (unsigned long long)ttx,
            (unsigned long long)trxp, (unsigned long long)ttxp, count,
            (unsigned long)time(NULL));
    fclose(f); chmod(STATSFILE, 0644);
}

/* ============================================================
 * Binder IPC
 * ============================================================ */
static int binder_fd = -1;
static uint8_t* binder_map = NULL;

static int do_ioctl(int fd, unsigned long cmd, void* arg) {
    int ret = ioctl(fd, cmd, arg);
    if (ret < 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "ioctl 0x%lx failed: errno=%d (%s)", cmd, errno, strerror(errno));
        log_msg(buf);
    }
    return ret;
}

static int open_binder(void) {
    const char* paths[] = { "/dev/binder", "/dev/vndbinder", "/dev/hwbinder", NULL };
    for (int i = 0; i < 10 && paths[i]; i++) {  /* Retry up to 10 times */
        binder_fd = open(paths[i], O_RDWR | O_CLOEXEC);
        if (binder_fd >= 0) { log_fmt("opened %s (attempt %d)", paths[i], i+1); break; }
        if (i < 9) usleep(500000);
    }
    if (binder_fd < 0) { log_errno("open binder device"); return -1; }

    struct binder_version ver;
    memset(&ver, 0, sizeof(ver));
    if (do_ioctl(binder_fd, BINDER_VERSION, &ver) < 0) {
        close(binder_fd); binder_fd = -1; return -1;
    }
    log_fmt("binder protocol version %d", ver.protocol_version);

    uint32_t max_threads = 32;
    do_ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    binder_map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                MAP_PRIVATE | MAP_NORESERVE, binder_fd, 0);
    if (binder_map == MAP_FAILED) {
        binder_map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                    MAP_PRIVATE, binder_fd, 0);
        if (binder_map == MAP_FAILED) {
            log_errno("mmap binder");
            close(binder_fd); binder_fd = -1; return -1;
        }
    }
    log_fmt("binder opened, mmap %d bytes at %p", BINDER_MMAP_SIZE, (void*)binder_map);
    return 0;
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
    if (ret < 0) return ret;
    if (read_consumed) *read_consumed = (size_t)bwr.read_consumed;
    return 0;
}

static int enter_looper(void) {
    uint32_t cmd = BC_ENTER_LOOPER;
    return send_binder_cmd(&cmd, sizeof(cmd));
}

/* ============================================================
 * Parcel helpers
 * ============================================================ */
static void write_str16(uint8_t** buf, const char* s) {
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

static void write_int32_array(uint8_t** buf, const int32_t* arr, int32_t len) {
    write_int32(buf, len);
    for (int32_t i = 0; i < len; i++) write_int32(buf, arr[i]);
}

static void write_int64_array(uint8_t** buf, const int64_t* arr, int32_t len) {
    write_int32(buf, len);
    for (int32_t i = 0; i < len; i++) write_int64(buf, arr[i]);
}

/* ============================================================
 * Build StatsResult Parcel (for codes 11, 12, 13)
 * Parcel format:
 *   int32_t(0)       - exception (writeNoException)
 *   int32_t(1)       - non-null (writeTypedObject)
 *   int32_t(36)      - StatsResult size
 *   int64_t(rxBytes)
 *   int64_t(rxPackets)
 *   int64_t(txBytes)
 *   int64_t(txPackets)
 * ============================================================ */
static size_t build_stats_result_reply(uint8_t* buf, size_t buf_size,
                                       uint64_t rxBytes, uint64_t rxPackets,
                                       uint64_t txBytes, uint64_t txPackets) {
    uint8_t* p = buf;
    write_int32(&p, 0);          /* exception = 0 */
    write_int32(&p, 1);          /* non-null parcelable */
    write_int32(&p, 36);         /* StatsResult size (4 longs = 32 bytes + 4 byte header) */
    write_int64(&p, rxBytes);
    write_int64(&p, rxPackets);
    write_int64(&p, txBytes);
    write_int64(&p, txPackets);
    return (size_t)(p - buf);
}

/* ============================================================
 * Build NetworkStats Parcel with single entry (for session methods)
 * Format:
 *   int32_t(0) - exception
 *   int32_t(1) - non-null parcelable
 *   NetworkStats data:
 *     int64_t(elapsedRealtime=0)
 *     int32_t(size=1)
 *     int32_t(capacity=1)
 *     String[] iface: int32_t(1), str16("wlan0")
 *     int32_t[] uid: [UID_ALL=-1]
 *     int32_t[] set: [SET_DEFAULT=0]
 *     int32_t[] tag: [TAG_NONE=0]
 *     int32_t[] metered: [METERED_ALL=-1]
 *     int32_t[] roaming: [ROAMING_ALL=-1]
 *     int32_t[] defaultNetwork: [DEFAULT_NETWORK_ALL=-1]
 *     int64_t[] rxBytes: [rxBytes]
 *     int64_t[] rxPackets: [rxPackets]
 *     int64_t[] txBytes: [txBytes]
 *     int64_t[] txPackets: [txPackets]
 *     int64_t[] operations: [0]
 * ============================================================ */
static size_t build_network_stats_reply(uint8_t* buf, size_t buf_size,
                                         uint64_t rxBytes, uint64_t rxPackets,
                                         uint64_t txBytes, uint64_t txPackets) {
    uint8_t* p = buf;
    write_int32(&p, 0);  /* exception */

    /* Start of NetworkStats Parcelable */
    uint8_t* netstats_start = p;
    write_int32(&p, 1);  /* non-null */

    /* elapsedRealtime */
    write_int64(&p, 0);

    /* size, capacity */
    write_int32(&p, 1);
    write_int32(&p, 1);

    /* iface array: ["wlan0"] */
    write_int32(&p, 1);
    write_str16(&p, "wlan0");

    /* uid array: [-1] */
    { int32_t val[] = {-1}; write_int32_array(&p, val, 1); }

    /* set array: [0] */
    { int32_t val[] = {0}; write_int32_array(&p, val, 1); }

    /* tag array: [0] */
    { int32_t val[] = {0}; write_int32_array(&p, val, 1); }

    /* metered array: [-1] */
    { int32_t val[] = {-1}; write_int32_array(&p, val, 1); }

    /* roaming array: [-1] */
    { int32_t val[] = {-1}; write_int32_array(&p, val, 1); }

    /* defaultNetwork array: [-1] */
    { int32_t val[] = {-1}; write_int32_array(&p, val, 1); }

    /* rxBytes array */
    { int64_t val[] = {(int64_t)rxBytes}; write_int64_array(&p, val, 1); }

    /* rxPackets array */
    { int64_t val[] = {(int64_t)rxPackets}; write_int64_array(&p, val, 1); }

    /* txBytes array */
    { int64_t val[] = {(int64_t)txBytes}; write_int64_array(&p, val, 1); }

    /* txPackets array */
    { int64_t val[] = {(int64_t)txPackets}; write_int64_array(&p, val, 1); }

    /* operations array */
    { int64_t val[] = {0}; write_int64_array(&p, val, 1); }

    log_fmt("  built NetworkStats reply: %zu bytes, rx=%llu tx=%llu",
            (size_t)(p - buf), (unsigned long long)rxBytes, (unsigned long long)txBytes);
    return (size_t)(p - buf);
}

/* ============================================================
 * Build simple reply for codes that just need exception + status
 * ============================================================ */
static size_t build_void_reply(uint8_t* buf) {
    uint8_t* p = buf;
    write_int32(&p, 0);  /* exception */
    return (size_t)(p - buf);
}

static size_t build_int_reply(uint8_t* buf, int32_t val) {
    uint8_t* p = buf;
    write_int32(&p, 0);  /* exception */
    write_int32(&p, val);
    return (size_t)(p - buf);
}

/* ============================================================
 * AIDL ServiceManager communication
 * ============================================================ */
#define SM_AIDL_CHECK_SERVICE 2
#define SM_AIDL_ADD_SERVICE   3
#define SM_AIDL_GET_DECLARED_INSTANCES 4

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

                log_fmt("BR_REPLY: code=%u flags=0x%x data_size=%llu",
                        rtr->code, rtr->flags, (unsigned long long)rtr->data_size);

                if (data_sz >= 8) {
                    const uint8_t* data = (const uint8_t*)(uintptr_t)buf_ptr;
                    int32_t exc;
                    memcpy(&exc, data, 4);
                    if (exc != 0) {
                        log_fmt("  exception=%d", exc);
                        result = -1;
                        if (out_has_binder) *out_has_binder = -1;
                    } else {
                        uint64_t binder_val = 0;
                        memcpy(&binder_val, data + 4, 8);
                        if (binder_val != 0) {
                            log_fmt("  exists: binder=0x%llx", (unsigned long long)binder_val);
                            result = 0;
                            if (out_has_binder) *out_has_binder = 1;
                        } else {
                            log_fmt("  not found");
                            result = 0;
                            if (out_has_binder) *out_has_binder = 0;
                        }
                    }
                } else {
                    log_fmt("  empty reply (data_size=%llu)", (unsigned long long)data_sz);
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
                log_fmt("BR_FAILED_REPLY");
                return -1;

            case BR_DEAD_REPLY:
                log_fmt("BR_DEAD_REPLY");
                return -1;

            case BR_ERROR: {
                int32_t err = 0;
                if (rp + 4 <= rend) memcpy(&err, rp, 4);
                log_fmt("BR_ERROR=%d", err);
                return -1;
            }

            default:
                log_fmt("UNKNOWN BR cmd 0x%x", cmd);
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
    log_fmt("AIDL_addService('%s'): sending %zu bytes, ptr=0x%llx cookie=0x%llx",
            name, total, (unsigned long long)binder_ptr, (unsigned long long)cookie);
    int ret = send_bc_with_reply(wbuf, total, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);
    if (ret < 0) return -1;

    int result = parse_sm_reply(rbuf, consumed, NULL);
    if (result >= 0) log_fmt("addService('%s'): SUCCESS", name);
    else log_fmt("addService('%s'): FAILED", name);
    return result;
}

static const char* SERVICE_NAMES[] = {
    "netstats",
    "netstats_service",
    "network_stats",
    NULL
};

static const char* IFACE_HASH = "b8b0a23cf15c0b9fc3b5e5b0b6a4f3a2c1d0e9f8";

static uint64_t pick_stat(const struct net_stats* s, int type) {
    switch (type) {
        case TYPE_RX_BYTES:   return s->rxBytes;
        case TYPE_TX_BYTES:   return s->txBytes;
        case TYPE_RX_PACKETS: return s->rxPackets;
        case TYPE_TX_PACKETS: return s->txPackets;
        default:              return s->rxBytes + s->txBytes;
    }
}

/* ============================================================
 * Session management
 * ============================================================ */
static int session_count = 0;
static uint64_t session_ptrs[MAX_SESSIONS];
static uint64_t session_cookies[MAX_SESSIONS];

static uint64_t create_session(void) {
    if (session_count >= MAX_SESSIONS) {
        log_fmt("WARNING: max sessions reached (%d)", MAX_SESSIONS);
        session_count = 0;
    }
    uint64_t ptr = (uint64_t)(uintptr_t)(binder_map + SESSION_BASE + session_count * 0x1000);
    session_ptrs[session_count] = ptr;
    session_cookies[session_count] = ptr;
    session_count++;
    log_fmt("Created session %d: ptr=0x%llx", session_count - 1, (unsigned long long)ptr);
    return ptr;
}

static int is_session_ptr(uint64_t ptr) {
    for (int i = 0; i < session_count; i++) {
        if (session_ptrs[i] == ptr) return i;
    }
    return -1;
}

static void destroy_session(int idx) {
    if (idx < 0 || idx >= session_count) return;
    session_ptrs[idx] = session_ptrs[session_count - 1];
    session_cookies[idx] = session_cookies[session_count - 1];
    session_count--;
}

/* ============================================================
 * Reply with a session flat_binder_object.
 * Returns total reply size. Sets *binder_off to the offset
 * of the flat_binder_object within buf (for BC_REPLY offsets).
 * ============================================================ */
static size_t build_session_reply(uint8_t* buf, uint64_t session_ptr,
                                  uint32_t* binder_off) {
    uint8_t* p = buf;
    write_int32(&p, 0);  /* exception */

    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - buf);

    /* FlatBinderObject for the session */
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
 * Transaction handler
 * ============================================================ */
static uint64_t main_service_ptr = 0;
static uint64_t main_service_cookie = 0;

static void handle_transaction(const struct binder_transaction_data* tr) {
    uint8_t reply_data[8192];
    uint8_t* rp = reply_data;
    int session_idx = -1;
    int is_session = 0;
    int32_t binder_offset = -1;  /* offset of flat_binder_object in reply, -1 = none */

    if (main_service_ptr != 0 && tr->target.ptr == main_service_ptr) {
        is_session = 0;  /* Main service */
    } else {
        session_idx = is_session_ptr(tr->target.ptr);
        if (session_idx >= 0) {
            is_session = 1;  /* Session */
        }
    }

    uint32_t code = tr->code;
    struct net_stats s;
    read_all_stats(&s);

    log_fmt(">>> TX: code=%u(0x%x) %s flags=0x%x data_size=%llu pid=%d uid=%u",
            code, code, is_session ? "[SESSION]" : "[SERVICE]",
            tr->flags, (unsigned long long)tr->data_size,
            tr->sender_pid, tr->sender_euid);

    size_t reply_size = 0;

    if (is_session) {
        /* ============================================================
         * INetworkStatsSession methods
         * ============================================================ */
        switch (code) {
            case SESS_getDeviceSummaryForNetwork:
            case SESS_getSummaryForNetwork: {
                /* Read NetworkTemplate, startTime, endTime from input */
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                /* Skip the NetworkTemplate (complex parcelable) - we don't need it */
                /* Just skip to the end of the data */
                /* Actually, we need to skip carefully */
                log_fmt("  getDeviceSummaryForNetwork/getSummaryForNetwork");
                reply_size = build_network_stats_reply(reply_data, sizeof(reply_data),
                                                       s.rxBytes, s.rxPackets,
                                                       s.txBytes, s.txPackets);
                break;
            }

            case SESS_getSummaryForAllUid:
            case SESS_getTaggedSummaryForAllUid: {
                /* Returns NetworkStats */
                log_fmt("  getSummaryForAllUid/getTaggedSummaryForAllUid");
                reply_size = build_network_stats_reply(reply_data, sizeof(reply_data),
                                                       s.rxBytes, s.rxPackets,
                                                       s.txBytes, s.txPackets);
                break;
            }

            case SESS_getHistoryForNetwork:
            case SESS_getHistoryIntervalForNetwork:
            case SESS_getHistoryForUid:
            case SESS_getHistoryIntervalForUid: {
                /* Returns NetworkStatsHistory - return empty */
                log_fmt("  getHistory* - returning empty");
                /* writeNoException + writeTypedObject(null, 1) = 0 + 0 */
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_int32(&p, 0); /* null */
                reply_size = (size_t)(p - reply_data);
                break;
            }

            case SESS_getRelevantUids: {
                /* Returns int[] - return empty array */
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_int32(&p, 0); /* empty array length */
                reply_size = (size_t)(p - reply_data);
                break;
            }

            case SESS_close: {
                log_fmt("  close session %d", session_idx);
                if (session_idx >= 0) destroy_session(session_idx);
                reply_size = build_void_reply(reply_data);
                break;
            }

            default: {
                log_fmt("  UNKNOWN session code %u (0x%x)", code, code);
                reply_size = build_void_reply(reply_data);
                break;
            }
        }
    } else {
        /* ============================================================
         * INetworkStatsService methods
         * ============================================================ */
        switch (code) {
            case TX_openSession:
            case TX_openSessionForUsageStats: {
                log_fmt("  openSession/openSessionForUsageStats");
                uint64_t sess_ptr = create_session();
                uint32_t bo = 0;
                reply_size = build_session_reply(reply_data, sess_ptr, &bo);
                binder_offset = (int32_t)bo;
                break;
            }

            case TX_getTotalStats: {
                log_fmt("  getTotalStats");
                reply_size = build_stats_result_reply(reply_data, sizeof(reply_data),
                                                      s.rxBytes, s.rxPackets,
                                                      s.txBytes, s.txPackets);
                break;
            }

            case TX_getIfaceStats: {
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                char iface[64] = "wlan0";
                /* Skip first string (interface descriptor) if present */
                if (tr->data_size > 4) {
                    skip_str16(&pp);
                    /* Parse the iface string */
                    if (pp + 4 <= (const uint8_t*)(uintptr_t)(tr->data.ptr.buffer + tr->data_size)) {
                        uint32_t nlen; memcpy(&nlen, pp, 4); pp += 4;
                        if (nlen > 0 && nlen < 60) {
                            for (uint32_t i = 0; i < nlen; i++) {
                                uint16_t c; memcpy(&c, pp, 2); pp += 2;
                                iface[i] = (char)c;
                            }
                            iface[nlen] = '\0';
                        }
                    }
                }
                struct net_stats is;
                if (read_iface_stats(iface, &is) != 0) is = s;
                log_fmt("  getIfaceStats iface=%s rx=%llu tx=%llu",
                        iface, (unsigned long long)is.rxBytes, (unsigned long long)is.txBytes);
                reply_size = build_stats_result_reply(reply_data, sizeof(reply_data),
                                                      is.rxBytes, is.rxPackets,
                                                      is.txBytes, is.txPackets);
                break;
            }

            case TX_getUidStats: {
                /* Returns StatsResult - we return 0 for per-UID */
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                int uid = -1;
                if (tr->data_size >= 4) memcpy(&uid, pp, 4);
                log_fmt("  getUidStats uid=%d -> 0 (no per-UID data)", uid);
                reply_size = build_stats_result_reply(reply_data, sizeof(reply_data),
                                                      0, 0, 0, 0);
                break;
            }

            case TX_getMobileIfaces: {
                /* Returns String[] */
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_int32(&p, 0); /* empty array */
                reply_size = (size_t)(p - reply_data);
                log_fmt("  getMobileIfaces -> []");
                break;
            }

            case TX_forceUpdate: {
                update_stats_file_detailed();
                log_fmt("  forceUpdate");
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_getUidStatsForTransport:
            case TX_getDataLayerSnapshotForUid: {
                /* Returns NetworkStats - return empty with total */
                log_fmt("  getUidStatsForTransport/getDataLayerSnapshotForUid");
                reply_size = build_network_stats_reply(reply_data, sizeof(reply_data),
                                                       s.rxBytes, s.rxPackets,
                                                       s.txBytes, s.txPackets);
                break;
            }

            case TX_registerNetworkStatsProvider: {
                /* Returns INetworkStatsProviderCallback */
                /* Return null - provider registration not supported */
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_int32(&p, 0); /* null binder */
                reply_size = (size_t)(p - reply_data);
                log_fmt("  registerNetworkStatsProvider -> null (not supported)");
                break;
            }

            case TX_noteUidForeground:
            case TX_incrementOperationCount:
            case TX_notifyNetworkStatus:
            case TX_unregisterUsageRequest:
            case TX_advisePersistThreshold:
            case TX_setStatsProviderWarningAndLimitAsync: {
                log_fmt("  code %u: void return", code);
                reply_size = build_void_reply(reply_data);
                break;
            }

            case TX_registerUsageCallback: {
                /* Returns DataUsageRequest - return null */
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_int32(&p, 0); /* null parcelable */
                reply_size = (size_t)(p - reply_data);
                log_fmt("  registerUsageCallback -> null");
                break;
            }

            case TX_getRateLimitCacheConfig: {
                /* Returns TrafficStatsRateLimitCacheConfig - return null */
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_int32(&p, 0); /* null */
                reply_size = (size_t)(p - reply_data);
                log_fmt("  getRateLimitCacheConfig -> null");
                break;
            }

            case TX_GET_INTERFACE_VERSION: {
                uint32_t version = 2;
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                memcpy(p, &version, 4); p += 4;
                reply_size = (size_t)(p - reply_data);
                log_fmt("  getInterfaceVersion -> %u", version);
                break;
            }

            case TX_GET_INTERFACE_HASH: {
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* exception */
                write_str16(&p, IFACE_HASH);
                reply_size = (size_t)(p - reply_data);
                log_fmt("  getInterfaceHash -> %s", IFACE_HASH);
                break;
            }

            /* Legacy/fallback codes (patched GSIs may use these) */
            case TX_LEGACY_GET_TOTAL_STATS: {
                uint64_t val = s.rxBytes + s.txBytes;
                uint8_t* p = reply_data;
                write_int32(&p, 0); /* status = 0 */
                write_int64(&p, val);
                reply_size = (size_t)(p - reply_data);
                log_fmt("  LEGACY getTotalStats -> %llu", (unsigned long long)val);
                break;
            }

            case TX_LEGACY_GET_IFACE_STATS: {
                const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                char iface[64] = "wlan0";
                if (tr->data_size > 4) {
                    uint32_t nlen; memcpy(&nlen, pp, 4); pp += 4;
                    if (nlen > 0 && nlen < 60) {
                        for (uint32_t i = 0; i < nlen; i++) {
                            uint16_t c; memcpy(&c, pp, 2); pp += 2;
                            iface[i] = (char)c;
                        }
                        iface[nlen] = '\0';
                    }
                }
                int type = TYPE_RX_BYTES;
                if (pp + 4 <= (const uint8_t*)(uintptr_t)(tr->data.ptr.buffer + tr->data_size)) {
                    memcpy(&type, pp, 4);
                }
                struct net_stats is;
                if (read_iface_stats(iface, &is) != 0) is = s;
                uint64_t val = pick_stat(&is, type);
                uint8_t* p = reply_data;
                write_int32(&p, 0);
                write_int64(&p, val);
                reply_size = (size_t)(p - reply_data);
                log_fmt("  LEGACY getIfaceStats iface=%s type=%d -> %llu",
                        iface, type, (unsigned long long)val);
                break;
            }

            case TX_LEGACY_FORCE_UPDATE: {
                update_stats_file_detailed();
                uint8_t* p = reply_data;
                write_int32(&p, 0);
                reply_size = (size_t)(p - reply_data);
                log_fmt("  LEGACY forceUpdate");
                break;
            }

            case TX_LEGACY_GET_UID_STATS: {
                uint8_t* p = reply_data;
                write_int32(&p, 0);
                write_int64(&p, 0);
                reply_size = (size_t)(p - reply_data);
                log_fmt("  LEGACY getUidStats -> 0");
                break;
            }

            default: {
                log_fmt("  UNKNOWN service code %u (0x%x), returning void", code, code);
                reply_size = build_void_reply(reply_data);
                break;
            }
        }
    }

    /* Build and send BC_REPLY */
    uint32_t offsets_arr[1];
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
    uint8_t discard[4096];
    size_t consumed = 0;
    int ret = send_bc_with_reply(rwbuf, write_len, discard, sizeof(discard), &consumed);
    if (ret < 0) log_errno("send BC_REPLY");
    free(rwbuf);
}

static void run_event_loop(void) {
    uint8_t* rbuf = (uint8_t*)malloc(BINDER_BUF_SIZE);
    if (!rbuf) { log_msg("FATAL: malloc failed"); return; }
    log_msg("Entering main event loop...");
    int consecutive_errors = 0;
    int loop_count = 0;

    while (1) {
        size_t consumed = 0;
        int ret = send_bc_with_reply(NULL, 0, rbuf, BINDER_BUF_SIZE, &consumed);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) { usleep(10000); continue; }
            consecutive_errors++;
            log_errno("main loop read");
            if (consecutive_errors > 5) {
                log_msg("Too many errors, re-opening binder...");
                if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
                if (binder_fd >= 0) close(binder_fd);
                binder_fd = -1; binder_map = NULL;
                sleep(3);
                if (open_binder() == 0) {
                    enter_looper();
                    log_msg("Binder re-opened");
                    consecutive_errors = 0;
                }
            }
            usleep(500000); continue;
        }
        consecutive_errors = 0;

        if (consumed == 0) {
            loop_count++;
            if (loop_count % 60 == 0) update_stats_file_detailed();
            usleep(50000);
            continue;
        }

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
                case BR_DEAD_REPLY:
                    break;
                case BR_ERROR:
                    if (rp + 4 <= rend) rp += 4;
                    break;
                default:
                    log_fmt("event loop: unknown cmd 0x%x", cmd);
                    goto loop_end;
            }
        }
        loop_end:;
    }
    free(rbuf);
}

static void sig_handler(int sig) {
    log_fmt("Signal %d received, exiting", sig);
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    _exit(0);
}

/* Try to kill existing netstats service if possible */
static void try_kill_netstats(void) {
    /* Check if real NetworkStatsService is registered */
    int exists = aidl_check_service("netstats");
    if (exists == 0) {
        log_msg("netstats service not found - netproxy will be primary");
        return;
    }
    if (exists > 0) {
        log_msg("netstats service EXISTS - attempting to override");
        /* On some GSIs, the real service is from APEX and can't be killed.
         * We'll try to register anyway and let ServiceManager decide. */
    }
}

int main(void) {
    log_fmt("==============================================");
    log_fmt("  Native netproxy v%s starting", NETPROXY_VERSION);
    log_fmt("==============================================");

    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sig_handler);
    signal(SIGINT,  sig_handler);

    log_fmt("PID=%d UID=%d GID=%d", getpid(), getuid(), getgid());
    const char* ctx = getenv("SELINUX_CONTEXT");
    log_fmt("SELinux context: %s", ctx ? ctx : "unknown");
    log_fmt("SELinux mode: %s", ctx && strstr(ctx, "permissive") ? "permissive" : "enforcing (or unknown)");

    struct net_stats s;
    if (read_all_stats(&s) == 0) {
        log_fmt("Initial /proc/net/dev: rx=%llu tx=%llu rxp=%llu txp=%llu",
                (unsigned long long)s.rxBytes, (unsigned long long)s.txBytes,
                (unsigned long long)s.rxPackets, (unsigned long long)s.txPackets);

        /* Log all interfaces */
        struct iface_stat ifaces[MAX_IFACES];
        int count = 0;
        if (read_all_ifaces(ifaces, &count) == 0) {
            log_fmt("Active interfaces (%d):", count);
            for (int i = 0; i < count && i < 10; i++) {
                log_fmt("  %s: rx=%llu tx=%llu",
                        ifaces[i].name,
                        (unsigned long long)ifaces[i].rxBytes,
                        (unsigned long long)ifaces[i].txBytes);
            }
        }
    } else {
        log_msg("WARNING: cannot read /proc/net/dev");
    }

    /* Log existing services */
    log_msg("Checking existing services...");
    const char* check_services[] = {"netstats", "netstats_service", "connectivity", NULL};
    for (int i = 0; check_services[i]; i++) {
        int ret = aidl_check_service(check_services[i]);
        log_fmt("Service '%s': %s", check_services[i],
                ret > 0 ? "EXISTS" : (ret == 0 ? "not found" : "error"));
    }

    /* Open binder */
    if (open_binder() < 0) {
        log_msg("Cannot open binder, running in passive mode");
        log_msg("Stats will be written to files only");
        while (1) {
            update_stats_file_detailed();
            sleep(15);
        }
        return 1;
    }

    if (enter_looper() < 0) {
        log_msg("enter_looper failed");
        return 1;
    }

    log_msg("Binder initialized, updating stats file...");
    update_stats_file_detailed();

    /* Try to register with ServiceManager */
    main_service_ptr = (uint64_t)(uintptr_t)(binder_map + 512);
    main_service_cookie = main_service_ptr;

    log_fmt("Using main service binder ptr: 0x%llx", (unsigned long long)main_service_ptr);

    int registered = 0;
    for (int round = 0; round < 5 && !registered; round++) {
        log_fmt("--- Registration round %d/5 ---", round + 1);
        for (int i = 0; SERVICE_NAMES[i]; i++) {
            log_fmt("Trying '%s'...", SERVICE_NAMES[i]);

            int exists = aidl_check_service(SERVICE_NAMES[i]);
            if (exists > 0) {
                log_fmt("'%s' already registered (exists=%d), trying to override anyway", SERVICE_NAMES[i], exists);
            }

            int ret = aidl_add_service(SERVICE_NAMES[i], main_service_ptr, main_service_cookie);
            if (ret >= 0) {
                log_fmt("*** REGISTERED as '%s'! ***", SERVICE_NAMES[i]);
                registered = 1;

                /* Write registration marker */
                FILE* rf = fopen(REGFILE, "w");
                if (rf) {
                    fprintf(rf, "registered=1\nservice=%s\nversion=%s\n", SERVICE_NAMES[i], NETPROXY_VERSION);
                    fclose(rf);
                }
                chmod(REGFILE, 0644);
                break;
            }
        }

        if (!registered && round < 4) {
            log_fmt("Registration round %d failed, waiting %ds before retry...", round + 1, 5 + round * 2);
            sleep(5 + round * 2);

            /* Log any SELinux denials between rounds */
            FILE* dmesg_p = popen("dmesg 2>/dev/null | grep 'avc:.*denied' | grep -iE 'service_manager|servicemanager|netstats' | tail -10", "r");
            if (dmesg_p) {
                char line[256];
                while (fgets(line, sizeof(line), dmesg_p)) {
                    line[strcspn(line, "\n")] = 0;
                    log_fmt("  SELINUX: %s", line);
                }
                pclose(dmesg_p);
            }
        }
    }

    if (!registered) {
        log_msg("WARNING: could not register with ServiceManager");
        log_msg("Falling back to passive mode - stats via files");
        unlink(REGFILE);
        while (1) {
            update_stats_file_detailed();
            sleep(15);
        }
    }

    log_msg("=== Entering main event loop ===");
    log_fmt("Registered=%d sessions=%d", registered, session_count);
    run_event_loop();

    log_msg("Exiting");
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    return 0;
}
