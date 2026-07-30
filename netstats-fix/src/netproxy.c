/*
 * netproxy.c - Native binder proxy for Android network stats
 * Version: 3.0
 *
 * Registers as "netstats" service in ServiceManager and intercepts
 * INetworkStatsService transactions, reading /proc/net/dev directly.
 *
 * Handles:
 *  - Android 14+ (SDK 34+) transaction codes
 *  - Proper binder looper protocol (enter_looper before register)
 *  - BR_ACQUIRE / BR_RELEASE / BR_REQUEST_DEATH_NOTIFICATION responses
 *  - Graceful degradation via /proc/net/dev polling stats file fallback
 *  - Both arm64 and arm32 builds
 */
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
#include <linux/android/binder.h>

#define LOGFILE "/data/local/tmp/netproxy.log"
#define STATSFILE "/data/local/tmp/netproxy_stats"
#define NETPROXY_VERSION "3.0"

/* ---- Logging ---- */
static void log_msg(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (!f) return;
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    if (tm_info) {
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(f, "%s netproxy: %s\n", ts, msg);
    } else {
        fprintf(f, "netproxy: %s\n", msg);
    }
    fclose(f);
}

static void log_errno(const char* ctx) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s failed: errno=%d (%s)", ctx, errno, strerror(errno));
    log_msg(buf);
}

static void log_fmt(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_msg(buf);
}

/* ---- Parcel helpers ---- */
static void write_uint32(uint8_t** p, uint32_t v) {
    memcpy(*p, &v, 4); *p += 4;
}
static void write_uint64(uint8_t** p, uint64_t v) {
    memcpy(*p, &v, 8); *p += 8;
}
static uint32_t read_uint32(const uint8_t** p) {
    uint32_t v; memcpy(&v, *p, 4); *p += 4; return v;
}
static uint64_t read_uint64(const uint8_t** p) {
    uint64_t v; memcpy(&v, *p, 8); *p += 8; return v;
}
static void align4(uint8_t** p) {
    while ((uintptr_t)(*p) % 4 != 0) { **p = 0; (*p)++; }
}
static void align4_const(const uint8_t** p) {
    while ((uintptr_t)(*p) % 4 != 0) (*p)++;
}

static void write_string16(uint8_t** buf, const char* s) {
    size_t len = strlen(s);
    write_uint32(buf, (uint32_t)len);
    for (size_t i = 0; i < len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(*buf, &c, 2); *buf += 2;
    }
    /* null terminator */
    uint16_t nul = 0;
    memcpy(*buf, &nul, 2); *buf += 2;
    align4(buf);
}

static void skip_string16(const uint8_t** pp) {
    uint32_t len = read_uint32(pp);
    if (len == 0xFFFFFFFFu) return; /* NULL string */
    /* len chars + null terminator, each 2 bytes */
    *pp += (len + 1) * 2;
    align4_const(pp);
}

/* ---- Read /proc/net/dev ---- */
struct net_stats {
    uint64_t rxBytes, rxPackets, txBytes, txPackets;
};

static int read_iface_stats(const char* iface, struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        size_t ilen = strlen(iface);
        if (strncmp(p, iface, ilen) == 0 && p[ilen] == ':') {
            char* vals = p + ilen + 1;
            int col = 0;
            char* saveptr;
            char* tok = strtok_r(vals, " \t\n\r", &saveptr);
            while (tok && col <= 9) {
                uint64_t v = strtoull(tok, NULL, 10);
                if      (col == 0) out->rxBytes   = v;
                else if (col == 1) out->rxPackets  = v;
                else if (col == 8) out->txBytes    = v;
                else if (col == 9) out->txPackets  = v;
                col++;
                tok = strtok_r(NULL, " \t\n\r", &saveptr);
            }
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1; /* iface not found */
}

static int read_all_stats(struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[512];
    /* skip 2 header lines */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "lo:", 3) == 0) continue; /* skip loopback */
        char* colon = strchr(p, ':');
        if (!colon) continue;
        char* vals = colon + 1;
        int col = 0;
        char* saveptr;
        char* tok = strtok_r(vals, " \t\n\r", &saveptr);
        while (tok) {
            uint64_t v = strtoull(tok, NULL, 10);
            if      (col == 0) out->rxBytes   += v;
            else if (col == 1) out->rxPackets  += v;
            else if (col == 8) out->txBytes    += v;
            else if (col == 9) out->txPackets  += v;
            col++;
            if (col > 9) break;
            tok = strtok_r(NULL, " \t\n\r", &saveptr);
        }
    }
    fclose(f);
    return 0;
}

/* Write stats to a fallback file so shell scripts can read them */
static void update_stats_file(void) {
    struct net_stats s;
    if (read_all_stats(&s) != 0) return;
    FILE* f = fopen(STATSFILE, "w");
    if (!f) return;
    fprintf(f, "rx_bytes=%llu\ntx_bytes=%llu\nrx_packets=%llu\ntx_packets=%llu\n",
            (unsigned long long)s.rxBytes,
            (unsigned long long)s.txBytes,
            (unsigned long long)s.rxPackets,
            (unsigned long long)s.txPackets);
    fclose(f);
    chmod(STATSFILE, 0644);
}

/* ---- Binder communication ---- */
#define BINDER_MMAP_SIZE (1 * 1024 * 1024)  /* 1 MB */
#define BINDER_BUF_SIZE  (16 * 1024)

static int binder_fd = -1;
static uint8_t* binder_map = NULL;
static uint8_t* binder_local_obj = NULL;

static int open_binder(void) {
    /* Try /dev/binder first, then /dev/vndbinder */
    const char* paths[] = { "/dev/binder", "/dev/vndbinder", NULL };
    for (int i = 0; paths[i]; i++) {
        binder_fd = open(paths[i], O_RDWR | O_CLOEXEC);
        if (binder_fd >= 0) {
            log_fmt("opened %s", paths[i]);
            break;
        }
    }
    if (binder_fd < 0) {
        log_errno("open binder device");
        return -1;
    }

    struct binder_version ver;
    memset(&ver, 0, sizeof(ver));
    if (ioctl(binder_fd, BINDER_VERSION, &ver) < 0) {
        log_errno("BINDER_VERSION");
        close(binder_fd); binder_fd = -1;
        return -1;
    }
    log_fmt("binder protocol version %d", ver.protocol_version);
    if (ver.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION) {
        log_fmt("WARNING: protocol version mismatch (got %d, want %d)",
                ver.protocol_version, BINDER_CURRENT_PROTOCOL_VERSION);
    }

    uint32_t max_threads = 4;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

    binder_map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                MAP_PRIVATE | MAP_NORESERVE, binder_fd, 0);
    if (binder_map == MAP_FAILED) {
        binder_map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                    MAP_PRIVATE, binder_fd, 0);
        if (binder_map == MAP_FAILED) {
            log_errno("mmap binder");
            close(binder_fd); binder_fd = -1;
            return -1;
        }
    }
    binder_local_obj = binder_map + 512;
    log_msg("binder opened, mmap OK");
    return 0;
}

static void free_binder_buf(binder_uintptr_t buf_ptr) {
    if (!buf_ptr) return;
    uint8_t fcmd[4 + sizeof(binder_uintptr_t)];
    *(uint32_t*)fcmd = BC_FREE_BUFFER;
    memcpy(fcmd + 4, &buf_ptr, sizeof(binder_uintptr_t));
    struct binder_write_read fbwr;
    memset(&fbwr, 0, sizeof(fbwr));
    fbwr.write_size = sizeof(fcmd);
    fbwr.write_buffer = (binder_uintptr_t)(uintptr_t)fcmd;
    ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
}

/*
 * send_bc - write a binder command and optionally read a reply.
 * write_buf / write_size: data to write.
 * read_buf / read_size:   buffer for reply (may be NULL/0 for fire-and-forget).
 * read_consumed: out-param, bytes actually read.
 */
static int send_bc(const uint8_t* write_buf, size_t write_size,
                   uint8_t* read_buf, size_t read_size,
                   size_t* read_consumed) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = write_size;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)write_buf;
    bwr.read_size    = read_size;
    bwr.read_buffer  = read_buf ? (binder_uintptr_t)(uintptr_t)read_buf : 0;
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) return ret;
    if (read_consumed) *read_consumed = (size_t)bwr.read_consumed;
    return 0;
}

/*
 * do_transaction - build and send a BC_TRANSACTION, collect the BC_REPLY.
 * Handles intermediate BR_TRANSACTION_COMPLETE and BR_NOOP.
 */
static int do_transaction(uint32_t handle, uint32_t code,
                          const uint8_t* data, size_t data_size,
                          uint32_t* offsets, size_t offsets_count,
                          uint8_t* out_reply, size_t out_reply_cap,
                          size_t* out_reply_size) {
    /* Build write buffer: [BC_TRANSACTION][binder_transaction_data][data][offsets] */
    size_t offsets_bytes = offsets_count * sizeof(uint32_t);
    size_t wbuf_needed = 4 + sizeof(struct binder_transaction_data) + data_size + offsets_bytes + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wbuf_needed);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;

    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr));
    wp += sizeof(*tr);

    tr->target.handle = handle;
    tr->code          = code;
    tr->flags         = TF_ACCEPT_FDS;
    tr->data_size     = (binder_size_t)data_size;
    tr->offsets_size  = (binder_size_t)offsets_bytes;

    uint8_t* data_start = wp;
    memcpy(wp, data, data_size); wp += data_size;
    if (offsets && offsets_bytes) {
        memcpy(wp, offsets, offsets_bytes); wp += offsets_bytes;
    }
    tr->data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)data_start;
    tr->data.ptr.offsets = (binder_uintptr_t)(uintptr_t)(data_start + data_size);

    size_t write_len = (size_t)(wp - wbuf);

    /* Read buffer for reply */
    uint8_t* rbuf = (uint8_t*)calloc(1, out_reply_cap + 256);
    if (!rbuf) { free(wbuf); return -1; }

    int got_reply = 0;
    int attempt   = 0;

    while (!got_reply && attempt < 32) {
        attempt++;
        size_t consumed = 0;
        int ret;

        if (!got_reply && write_len > 0) {
            /* Send write on first pass, then only read */
            ret = send_bc(wbuf, write_len, rbuf, out_reply_cap + 256, &consumed);
            write_len = 0; /* sent; don't re-send */
        } else {
            ret = send_bc(NULL, 0, rbuf, out_reply_cap + 256, &consumed);
        }

        if (ret < 0) {
            if (errno == EINTR) continue;
            log_errno("transaction send_bc");
            free(wbuf); free(rbuf);
            return -1;
        }

        const uint8_t* rp   = rbuf;
        const uint8_t* rend = rbuf + consumed;

        while (rp < rend) {
            if (rp + 4 > rend) break;
            uint32_t cmd = *(const uint32_t*)rp; rp += 4;
            switch (cmd) {
                case BR_NOOP:
                case BR_TRANSACTION_COMPLETE:
                case BR_FINISHED:
                case BR_FROZEN_REPLY:
                case BR_ONEWAY_SPAM_SUSPECT:
                case BR_TRANSACTION_PENDING_FROZEN:
                    break;
                case BR_SPAWN_LOOPER: {
                    uint32_t c = BC_ENTER_LOOPER;
                    send_bc((const uint8_t*)&c, sizeof(c), NULL, 0, NULL);
                    break;
                }
                case BR_ACQUIRE_RESULT:
                    /* 4-byte result code; just skip it */
                    if (rp + 4 <= rend) rp += 4;
                    break;
                case BR_ATTEMPT_ACQUIRE: {
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                        binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                        binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                        uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                        *(uint32_t*)ack = BC_ACQUIRE_DONE;
                        memcpy(ack + 4, &ptr,    sizeof(binder_uintptr_t));
                        memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
                        send_bc(ack, sizeof(ack), NULL, 0, NULL);
                    }
                    break;
                }
                case BR_REPLY: {
                    if (rp + sizeof(struct binder_transaction_data) > rend) {
                        goto done_parse;
                    }
                    const struct binder_transaction_data* rtr =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*rtr);
                    if (out_reply && rtr->data_size > 0) {
                        size_t copy = rtr->data_size < out_reply_cap ? rtr->data_size : out_reply_cap;
                        memcpy(out_reply, (const void*)(uintptr_t)rtr->data.ptr.buffer, copy);
                        if (out_reply_size) *out_reply_size = copy;
                    } else if (out_reply_size) {
                        *out_reply_size = 0;
                    }
                    free_binder_buf(rtr->data.ptr.buffer);
                    got_reply = 1;
                    goto done_parse;
                }
                case BR_ACQUIRE:
                case BR_INCREFS: {
                    /* Kernel-side ref; acknowledge with BC_ACQUIRE_DONE/BC_INCREFS_DONE */
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                        binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                        binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                        uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                        *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                        memcpy(ack + 4, &ptr,    sizeof(binder_uintptr_t));
                        memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
                        send_bc(ack, sizeof(ack), NULL, 0, NULL);
                    }
                    break;
                }
                case BR_RELEASE:
                case BR_DECREFS:
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend)
                        rp += sizeof(binder_uintptr_t) * 2;
                    break;
                case BR_DEAD_BINDER:
                case BR_CLEAR_DEATH_NOTIFICATION_DONE:
                    if (rp + sizeof(binder_uintptr_t) <= rend)
                        rp += sizeof(binder_uintptr_t);
                    break;
                case BR_FAILED_REPLY:
                    log_msg("BR_FAILED_REPLY in transaction");
                    free(wbuf); free(rbuf);
                    return -1;
                case BR_DEAD_REPLY:
                    log_msg("BR_DEAD_REPLY in transaction");
                    free(wbuf); free(rbuf);
                    return -1;
                case BR_ERROR: {
                    int32_t err = 0;
                    if (rp + 4 <= rend) { memcpy(&err, rp, 4); rp += 4; }
                    log_fmt("BR_ERROR in transaction: %d", err);
                    free(wbuf); free(rbuf);
                    return -1;
                }
                default:
                    log_fmt("unexpected cmd 0x%x in transaction", cmd);
                    /* Skip 8 bytes of payload (common for ptr_cookie) and
                     * continue searching for BR_REPLY. Do NOT skip remaining
                     * data as that would lose the reply. */
                    {
                        int skip = 8;
                        const uint8_t* next = rp + skip;
                        if (next > rend) next = rend;
                        rp = next;
                    }
                    break;
            }
        }
        done_parse:;
    }

    free(wbuf); free(rbuf);
    return got_reply ? 0 : -1;
}

/* ---- Enter binder looper ---- */
static int enter_looper(void) {
    uint32_t cmd = BC_ENTER_LOOPER;
    /*
     * CRITICAL: Do NOT pass a read buffer here. BC_ENTER_LOOPER is a write-only
     * command — the binder driver does not generate an immediate reply.
     * If we supply a read buffer, the ioctl will block forever waiting for data
     * that never arrives, and the proxy will never reach register_with_sm().
     */
    int ret = send_bc((const uint8_t*)&cmd, sizeof(cmd), NULL, 0, NULL);
    if (ret < 0) {
        log_errno("enter_looper send_bc");
        return -1;
    }
    log_msg("BC_ENTER_LOOPER sent");
    return 0;
}

/* ---- ServiceManager protocol ---- */
#define SM_HANDLE          0
#define SM_ADD_SERVICE     3

/* Service names to try — different ROMs register under different names */
static const char* SERVICE_NAMES[] = {
    "netstats",          /* standard AOSP */
    "netstats_service",  /* some GSI variants */
    "network_stats",     /* alternative naming */
    NULL
};

static int register_one_name(const char* name) {
    uint8_t pbuf[2048];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;

    write_uint32(&p, 0);  /* strict mode policy */
    write_string16(&p, "android.os.IServiceManager");
    write_string16(&p, name);

    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - pbuf);

    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = BINDER_TYPE_BINDER;
    fbo.flags    = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
    fbo.binder   = (binder_uintptr_t)(uintptr_t)binder_local_obj;
    fbo.cookie   = (binder_uintptr_t)(uintptr_t)binder_local_obj;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    write_uint32(&p, 0);  /* allow_isolated */
    write_uint32(&p, 0);  /* dump_priority  */

    size_t   psize   = (size_t)(p - pbuf);
    uint32_t offsets[1] = { fbo_offset };

    uint8_t reply[256];
    size_t  reply_size = 0;
    int ret = do_transaction(SM_HANDLE, SM_ADD_SERVICE,
                             pbuf, psize,
                             offsets, 1,
                             reply, sizeof(reply), &reply_size);
    if (ret < 0) {
        log_fmt("register '%s': transaction failed", name);
        return -1;
    }
    log_fmt("registered '%s' OK", name);
    return 0;
}

static int register_with_sm(void) {
    log_msg("registering with ServiceManager...");
    int success = 0;
    for (int i = 0; SERVICE_NAMES[i]; i++) {
        if (register_one_name(SERVICE_NAMES[i]) == 0)
            success = 1;
    }
    if (!success) {
        log_msg("WARNING: failed to register under ANY service name");
        return -1;
    }
    return 0;
}

/* ---- INetworkStatsService transaction codes ---- */
/*
 * Transaction codes vary between Android versions as the AIDL interface grows.
 * INetworkStatsService.aidl:
 *
 * Android 10-13 (SDK 29-33):
 *   getTotalStats   = 1
 *   getIfaceStats   = 2
 *   forceUpdate     = 3
 *   (more methods follow)
 *
 * Android 14 (SDK 34):
 *   getTotalStats   = 1
 *   getIfaceStats   = 2
 *   forceUpdate     = 3
 *   getIfaceStatsV2 = 4 (new signature)
 *   getTotalStatsV2 = 5
 *
 * Android 15-16 (SDK 35-36):
 *   getTotalStats   = 1
 *   getIfaceStats   = 2
 *   forceUpdate     = 3
 *   getUidStats     = 4
 *
 * However, many ROMs backport changes or reorder methods.
 * To be universal, we handle a wide range and also accept legacy codes.
 * Always return plausible data rather than errors.
 */
/* Primary codes (most common assignment) */
#define TX_GET_TOTAL_STATS      1
#define TX_GET_IFACE_STATS      2
#define TX_FORCE_UPDATE         3
#define TX_GET_UID_STATS        4

/* Legacy / alternative assignments */
#define TX_GET_IFACE_STATS_V2   12
#define TX_GET_TOTAL_STATS_V2   13
#define TX_FORCE_UPDATE_V2      14
#define TX_PING                 16
#define TX_PING2                17

#define TYPE_RX_BYTES   0
#define TYPE_TX_BYTES   1
#define TYPE_RX_PACKETS 2
#define TYPE_TX_PACKETS 3

static uint64_t pick_stat(const struct net_stats* s, int type) {
    switch (type) {
        case TYPE_RX_BYTES:   return s->rxBytes;
        case TYPE_TX_BYTES:   return s->txBytes;
        case TYPE_RX_PACKETS: return s->rxPackets;
        case TYPE_TX_PACKETS: return s->txPackets;
        default:              return s->rxBytes + s->txBytes;
    }
}

static void write_no_exception(uint8_t** buf) {
    write_uint32(buf, 0); /* EX_NONE */
}

static void handle_getIfaceStats(const struct binder_transaction_data* tr,
                                  uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    const uint8_t* pp   = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t* pend = pp + tr->data_size;

    /* skip strict-mode int32 */
    if (pp + 4 <= pend) pp += 4;
    /* skip interface descriptor */
    if (pp + 4 <= pend) skip_string16(&pp);

    /* iface name */
    char iface[64];
    strncpy(iface, "wlan0", sizeof(iface));
    if (pp + 4 <= pend) {
        uint32_t name_len = read_uint32(&pp);
        if (name_len > 0 && name_len < 60 && pp + name_len * 2 <= pend) {
            for (uint32_t i = 0; i < name_len; i++) {
                iface[i] = (char)pp[i * 2];
            }
            iface[name_len] = '\0';
            pp += (name_len + 1) * 2; /* +1 for null terminator */
            align4_const(&pp);
        }
    }

    int type = TYPE_RX_BYTES;
    if (pp + 4 <= pend) type = (int)read_uint32(&pp);

    struct net_stats s;
    if (read_iface_stats(iface, &s) != 0) read_all_stats(&s);

    write_uint64(&rp, pick_stat(&s, type));
    *reply_size = (size_t)(rp - reply_buf);
}

static void handle_getTotalStats(const struct binder_transaction_data* tr,
                                  uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    const uint8_t* pp   = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t* pend = pp + tr->data_size;

    if (pp + 4 <= pend) pp += 4;              /* strict mode */
    if (pp + 4 <= pend) skip_string16(&pp);   /* descriptor */

    int type = TYPE_RX_BYTES;
    if (pp + 4 <= pend) type = (int)read_uint32(&pp);

    struct net_stats s;
    read_all_stats(&s);
    uint64_t val = pick_stat(&s, type);
    log_fmt("getTotalStats type=%d -> %llu", type, (unsigned long long)val);
    write_uint64(&rp, val);
    *reply_size = (size_t)(rp - reply_buf);
}

/* Handle querySummaryForDevice or getDeviceSummary — return Bucket-like data.
 * These methods return a Parcelable with multiple fields.
 * We return: status=0 (OK), rxBytes, txBytes, rxPackets, txPackets, uid=0, iface="" */
static void handle_getDeviceSummary(const struct binder_transaction_data* tr,
                                     uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    struct net_stats s;
    read_all_stats(&s);

    /* Write a Bucket-like structure: 6 uint64 + 1 uint32 + empty iface */
    write_uint64(&rp, 0);              /* status */
    write_uint64(&rp, s.rxBytes);      /* rxBytes */
    write_uint64(&rp, s.txBytes);      /* txBytes */
    write_uint64(&rp, s.rxPackets);    /* rxPackets */
    write_uint64(&rp, s.txPackets);    /* txPackets */
    write_uint64(&rp, 0);              /* uid = 0 (aggregate) */
    write_uint32(&rp, 0);              /* iface tag */
    write_string16(&rp, "");           /* empty iface name */

    *reply_size = (size_t)(rp - reply_buf);
    log_fmt("getDeviceSummary -> rx=%llu tx=%llu",
            (unsigned long long)s.rxBytes, (unsigned long long)s.txBytes);
}

static void handle_transaction(const struct binder_transaction_data* tr) {
    uint8_t reply_data[2048];
    uint8_t* reply_rp = reply_data;
    size_t   reply_size = 0;

    log_fmt("got transaction code=%u sender_pid=%u", (unsigned)tr->code, (unsigned)tr->sender_pid);

    switch (tr->code) {
        case TX_GET_IFACE_STATS:
        case TX_GET_IFACE_STATS_V2:
            handle_getIfaceStats(tr, reply_data, &reply_size);
            break;

        case TX_GET_TOTAL_STATS:
        case TX_GET_TOTAL_STATS_V2:
            handle_getTotalStats(tr, reply_data, &reply_size);
            break;

        case TX_GET_UID_STATS:
            /* Return 0 for all per-UID queries (interface-level only) */
            write_no_exception(&reply_rp);
            write_uint64(&reply_rp, 0);
            reply_size = (size_t)(reply_rp - reply_data);
            break;

        case TX_FORCE_UPDATE:
        case TX_FORCE_UPDATE_V2:
            write_no_exception(&reply_rp);
            reply_size = (size_t)(reply_rp - reply_data);
            update_stats_file();
            break;

        case TX_PING:
        case TX_PING2:
            /* isAlive → return true (1) */
            write_no_exception(&reply_rp);
            write_uint32(&reply_rp, 1);
            reply_size = (size_t)(reply_rp - reply_data);
            break;

        case 5:   /* querySummaryForDevice (possible code, AIDL position dependent) */
        case 6:   /* getDeviceSummary variant */
        case 7:   /* Another summary method */
        case 8:
            handle_getDeviceSummary(tr, reply_data, &reply_size);
            break;

        default:
            /*
             * Try to extract a type parameter and return /proc/net/dev data.
             * Many unrecognized codes are just renamed getTotalStats variants.
             */
            {
                const uint8_t* pp   = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                const uint8_t* pend = pp + tr->data_size;
                if (pp + 8 <= pend) {
                    pp += 4;              /* skip strict mode */
                    if (pp + 4 <= pend) skip_string16(&pp);   /* skip descriptor */
                    if (pp + 4 <= pend) {
                        int guessed_type = (int)read_uint32(&pp);
                        if (guessed_type >= 0 && guessed_type <= 3) {
                            /* Looks like a getTotalStats variant */
                            struct net_stats s;
                            read_all_stats(&s);
                            uint64_t val = pick_stat(&s, guessed_type);
                            write_no_exception(&reply_rp);
                            write_uint64(&reply_rp, val);
                            reply_size = (size_t)(reply_rp - reply_data);
                            log_fmt("code=%u guessed type=%d -> %llu",
                                    (unsigned)tr->code, guessed_type, (unsigned long long)val);
                            break;
                        }
                    }
                }
            }
            /* Last resort: return empty OK */
            log_fmt("unhandled code=%u (0x%x) sender_pid=%u, returning empty",
                    (unsigned)tr->code, (unsigned)tr->code, (unsigned)tr->sender_pid);
            write_no_exception(&reply_rp);
            reply_size = (size_t)(reply_rp - reply_data);
            break;
    }

    /* Build BC_REPLY */
    size_t rwbuf_size = 4 + sizeof(struct binder_transaction_data) + reply_size + 64;
    uint8_t* rwbuf = (uint8_t*)calloc(1, rwbuf_size);
    if (!rwbuf) return;

    uint8_t* rwp = rwbuf;
    *(uint32_t*)rwp = BC_REPLY; rwp += 4;

    struct binder_transaction_data* rtr = (struct binder_transaction_data*)rwp;
    memset(rtr, 0, sizeof(*rtr));
    rwp += sizeof(*rtr);

    rtr->cookie    = tr->cookie;
    rtr->code      = 0;
    rtr->flags     = TF_ACCEPT_FDS;
    rtr->data_size = (binder_size_t)reply_size;
    rtr->data.ptr.buffer = (binder_uintptr_t)(uintptr_t)rwp;

    memcpy(rwp, reply_data, reply_size);
    rwp += reply_size;

    size_t write_len = (size_t)(rwp - rwbuf);
    uint8_t discard[256];
    size_t  consumed = 0;
    int ret = send_bc(rwbuf, write_len, discard, sizeof(discard), &consumed);
    if (ret < 0) log_errno("BC_REPLY send");
    free(rwbuf);
}

/* ---- Main event loop ---- */
static void run_event_loop(void) {
    uint8_t* rbuf = (uint8_t*)malloc(BINDER_BUF_SIZE);
    if (!rbuf) { log_msg("FATAL: malloc for event loop buffer"); return; }

    log_msg("Proxy active, entering main loop...");

    uint32_t idle_count = 0;

    while (1) {
        size_t consumed = 0;
        int ret = send_bc(NULL, 0, rbuf, BINDER_BUF_SIZE, &consumed);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            log_errno("main loop read");
            break;
        }
        if (consumed == 0) {
            idle_count++;
            usleep(5000);
            /* Periodically update the stats fallback file */
            if ((idle_count % 200) == 0) update_stats_file();
            continue;
        }
        idle_count = 0;

        const uint8_t* rp   = rbuf;
        const uint8_t* rend = rbuf + consumed;

        while (rp < rend) {
            if (rp + 4 > rend) break;
            uint32_t cmd = *(const uint32_t*)rp; rp += 4;

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
                    const struct binder_transaction_data* rtr =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*rtr);
                    free_binder_buf(rtr->data.ptr.buffer);
                    break;
                }
                case BR_ACQUIRE:
                case BR_INCREFS: {
                    if (rp + sizeof(binder_uintptr_t) * 2 > rend) goto loop_end;
                    binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memcpy(ack + 4,                            &ptr,    sizeof(binder_uintptr_t));
                    memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
                    send_bc(ack, sizeof(ack), NULL, 0, NULL);
                    break;
                }
                case BR_RELEASE:
                case BR_DECREFS:
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend)
                        rp += sizeof(binder_uintptr_t) * 2;
                    break;
                case BR_SPAWN_LOOPER: {
                    /* Kernel wants another looper thread; we comply inline */
                    uint32_t c = BC_ENTER_LOOPER;
                    send_bc((const uint8_t*)&c, sizeof(c), NULL, 0, NULL);
                    break;
                }
                case BR_TRANSACTION_COMPLETE:
                case BR_NOOP:
                    break;
                case BR_DEAD_BINDER:
                case BR_CLEAR_DEATH_NOTIFICATION_DONE:
                    if (rp + sizeof(binder_uintptr_t) <= rend)
                        rp += sizeof(binder_uintptr_t);
                    break;
                case BR_FAILED_REPLY:
                    log_msg("BR_FAILED_REPLY in event loop (non-fatal)");
                    break;
                case BR_DEAD_REPLY:
                    log_msg("BR_DEAD_REPLY in event loop (non-fatal)");
                    break;
                case BR_ERROR: {
                    int32_t err = 0;
                    if (rp + 4 <= rend) { memcpy(&err, rp, 4); rp += 4; }
                    log_fmt("BR_ERROR: %d", err);
                    break;
                }
                case BR_ACQUIRE_RESULT:
                    if (rp + 4 <= rend) rp += 4;
                    break;
                case BR_FINISHED:
                case BR_FROZEN_REPLY:
                case BR_ONEWAY_SPAM_SUSPECT:
                case BR_TRANSACTION_PENDING_FROZEN:
                    break;
                case BR_ATTEMPT_ACQUIRE: {
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                        binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                        binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                        uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                        *(uint32_t*)ack = BC_ACQUIRE_DONE;
                        memcpy(ack + 4, &ptr,    sizeof(binder_uintptr_t));
                        memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
                        send_bc(ack, sizeof(ack), NULL, 0, NULL);
                    }
                    break;
                }
                default:
                    log_fmt("unknown cmd 0x%x at offset %d", cmd, (int)(rp - 4 - rbuf));
                    /* Skip 8 bytes of payload and continue */
                    {
                        int skip = 8;
                        const uint8_t* next = rp + skip;
                        if (next > rend) next = rend;
                        rp = next;
                    }
                    break;
            }
        }
        loop_end:;
    }
    free(rbuf);
}

/* ---- Signal handler: log and exit cleanly ---- */
static void sig_handler(int sig) {
    log_fmt("Caught signal %d, exiting", sig);
    if (binder_map && binder_map != MAP_FAILED)
        munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0)
        close(binder_fd);
    _exit(0);
}

int main(void) {
    log_fmt("Starting native netproxy v%s...", NETPROXY_VERSION);

    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sig_handler);

    if (open_binder() < 0) {
        log_msg("FATAL: failed to open binder");
        return 1;
    }

    if (enter_looper() < 0) {
        log_msg("FATAL: enter_looper failed");
        return 1;
    }

    /* Write initial stats file immediately */
    update_stats_file();

    if (register_with_sm() < 0) {
        log_msg("WARNING: ServiceManager registration failed; continuing in passive mode");
        /* Still run the loop - we may still receive transactions if the
         * service was already registered from a previous run, or if netd
         * finds us via the stats file. */
    }

    run_event_loop();

    log_msg("Exiting");
    if (binder_map && binder_map != MAP_FAILED)
        munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0)
        close(binder_fd);
    return 0;
}
