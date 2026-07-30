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
#include <linux/android/binder.h>

#define LOGFILE "/data/local/tmp/netproxy.log"
#define STATSFILE "/data/local/tmp/netproxy_stats"
#define REGFILE "/data/local/tmp/netproxy_registered"
#define NETPROXY_VERSION "5.1"

static FILE* log_fp = NULL;

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
        fprintf(log_fp, "%s netproxy: %s\n", ts, msg);
    } else {
        fprintf(log_fp, "netproxy: %s\n", msg);
    }
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

static void log_hex(const char* label, const uint8_t* data, size_t len) {
    log_open();
    if (!log_fp) return;
    fprintf(log_fp, "netproxy: %s [%zu bytes]: ", label, len);
    for (size_t i = 0; i < len && i < 128; i++) {
        fprintf(log_fp, "%02x ", data[i]);
    }
    if (len > 128) fprintf(log_fp, "...");
    fprintf(log_fp, "\n");
}

struct net_stats {
    uint64_t rxBytes, rxPackets, txBytes, txPackets;
};

static int read_all_stats(struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "lo:", 3) == 0) continue;
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
    return -1;
}

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

/* ============================================================
 * Binder IPC
 * ============================================================ */

#define BINDER_MMAP_SIZE (1 * 1024 * 1024)
#define BINDER_BUF_SIZE  (16 * 1024)

static int binder_fd = -1;
static uint8_t* binder_map = NULL;
static uint8_t* binder_local_obj = NULL;
static int use_new_fbo = 1;

static int open_binder(void) {
    const char* paths[] = { "/dev/binder", "/dev/vndbinder", NULL };
    for (int i = 0; paths[i]; i++) {
        binder_fd = open(paths[i], O_RDWR | O_CLOEXEC);
        if (binder_fd >= 0) { log_fmt("opened %s", paths[i]); break; }
    }
    if (binder_fd < 0) { log_errno("open binder device"); return -1; }

    struct binder_version ver;
    memset(&ver, 0, sizeof(ver));
    if (ioctl(binder_fd, BINDER_VERSION, &ver) < 0) {
        log_errno("BINDER_VERSION");
        close(binder_fd); binder_fd = -1; return -1;
    }
    log_fmt("binder protocol version %d", ver.protocol_version);
    use_new_fbo = (ver.protocol_version >= 8);

    uint32_t max_threads = 8;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);

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
    binder_local_obj = binder_map + 512;
    log_msg("binder opened, mmap OK");
    return 0;
}

static void free_binder_buf(binder_uintptr_t buf_ptr) {
    if (!buf_ptr) return;
    uint8_t fcmd[4 + sizeof(binder_uintptr_t)];
    *(uint32_t*)fcmd = BC_FREE_BUFFER;
    memcpy(fcmd + 4, &buf_ptr, sizeof(binder_uintptr_t));
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(fcmd);
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)fcmd;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
}

static int send_binder_cmd(const uint8_t* cmd, size_t cmd_size) {
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size   = cmd_size;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)cmd;
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    return ret;
}

static int send_bc_with_reply(const uint8_t* write_buf, size_t write_size,
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

static int enter_looper(void) {
    uint32_t cmd = BC_ENTER_LOOPER;
    int ret = send_binder_cmd((const uint8_t*)&cmd, sizeof(cmd));
    if (ret < 0) { log_errno("enter_looper"); return -1; }
    log_msg("BC_ENTER_LOOPER sent");
    return 0;
}

static void write_parcel_string16(uint8_t** buf, const char* s) {
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

static void skip_parcel_string16(const uint8_t** pp) {
    uint32_t len;
    memcpy(&len, *pp, 4); *pp += 4;
    if (len == 0xFFFFFFFFu) return;
    *pp += (len + 1) * 2;
    while ((uintptr_t)(*pp) % 4 != 0) (*pp)++;
}

/* ============================================================
 * ServiceManager - try multiple strategies
 * ============================================================ */

#define SM_HANDLE          0
#define SM_CHECK_SERVICE   1
#define SM_ADD_SERVICE     3

/* Parse a binder reply and extract exception + has_binder.
   Returns: 1 = service exists, 0 = not found, -1 = error */
static int parse_sm_reply(uint8_t* rbuf, size_t consumed, const char* name, const char* strategy) {
    const uint8_t* rp = rbuf;
    const uint8_t* rend = rbuf + consumed;
    while (rp < rend) {
        if (rp + 4 > rend) break;
        uint32_t cmd;
        memcpy(&cmd, rp, 4); rp += 4;
        switch (cmd) {
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
            case BR_FINISHED:
                break;
            case BR_SPAWN_LOOPER: {
                uint32_t c = BC_ENTER_LOOPER;
                send_binder_cmd((const uint8_t*)&c, sizeof(c));
                break;
            }
            case BR_REPLY: {
                if (rp + sizeof(struct binder_transaction_data) > rend) return -1;
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);
                if (rtr->data_size >= 8) {
                    const uint8_t* data = (const uint8_t*)(uintptr_t)rtr->data.ptr.buffer;
                    uint32_t exc;
                    memcpy(&exc, data, 4);
                    if (exc == 0) {
                        uint32_t has;
                        memcpy(&has, data + 4, 4);
                        free_binder_buf(rtr->data.ptr.buffer);
                        if (has != 0) {
                            log_fmt("%s '%s': service EXISTS", strategy, name);
                            return 1;
                        }
                        log_fmt("%s '%s': not found (exc=0 has=0)", strategy, name);
                        return 0;
                    }
                    free_binder_buf(rtr->data.ptr.buffer);
                    log_fmt("%s '%s': exception %u (0x%x)", strategy, name, exc, exc);
                    return -1;
                }
                free_binder_buf(rtr->data.ptr.buffer);
                return -1;
            }
            case BR_ACQUIRE:
            case BR_INCREFS: {
                if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                    rp += sizeof(binder_uintptr_t) * 2;
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memset(ack + 4, 0, sizeof(binder_uintptr_t) * 2);
                    send_binder_cmd(ack, sizeof(ack));
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
                log_fmt("%s '%s': BR_FAILED_REPLY", strategy, name);
                return -1;
            case BR_DEAD_REPLY:
                log_fmt("%s '%s': BR_DEAD_REPLY", strategy, name);
                return -1;
            case BR_ERROR: {
                int32_t err = 0;
                if (rp + 4 <= rend) memcpy(&err, rp, 4);
                log_fmt("%s '%s': BR_ERROR %d", strategy, name, err);
                return -1;
            }
            default:
                return -1;
        }
    }
    return -1;
}

/* Strategy 1: With exception prefix (standard AIDL check) */
static int check_service_sm1(const char* name) {
    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;
    *(uint32_t*)p = 0; p += 4;  /* exception = 0 */
    write_parcel_string16(&p, "android.os.IServiceManager");
    write_parcel_string16(&p, name);
    size_t psize = (size_t)(p - pbuf);

    log_fmt("SM1 check '%s': psize=%zu, sending...", name, psize);

    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr)); wp += sizeof(*tr);
    tr->target.handle = SM_HANDLE;
    tr->code          = SM_CHECK_SERVICE;
    tr->flags         = TF_ACCEPT_FDS;
    tr->data_size     = (binder_size_t)psize;
    tr->offsets_size  = 0;
    uint8_t* data_buf = wp;
    memcpy(data_buf, pbuf, psize);
    tr->data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)data_buf;
    tr->data.ptr.offsets = 0;

    size_t total = (size_t)(data_buf + psize - wbuf);
    log_hex("SM1 wbuf", wbuf, total > 128 ? 128 : total);

    uint8_t rbuf[512];
    size_t consumed = 0;
    int ret = send_bc_with_reply(wbuf, total, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);

    if (ret < 0) {
        log_fmt("SM1 check '%s': ioctl FAILED errno=%d (%s)", name, errno, strerror(errno));
        return -1;
    }
    log_fmt("SM1 check '%s': consumed=%zu", name, consumed);
    if (consumed > 0) log_hex("SM1 rbuf", rbuf, consumed > 128 ? 128 : consumed);

    return parse_sm_reply(rbuf, consumed, name, "SM1");
}

/* Strategy 2: No exception prefix */
static int check_service_sm2(const char* name) {
    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;
    write_parcel_string16(&p, "android.os.IServiceManager");
    write_parcel_string16(&p, name);
    size_t psize = (size_t)(p - pbuf);

    log_fmt("SM2 check '%s': psize=%zu, sending...", name, psize);

    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr)); wp += sizeof(*tr);
    tr->target.handle = SM_HANDLE;
    tr->code          = SM_CHECK_SERVICE;
    tr->flags         = TF_ACCEPT_FDS;
    tr->data_size     = (binder_size_t)psize;
    tr->offsets_size  = 0;
    uint8_t* data_buf = wp;
    memcpy(data_buf, pbuf, psize);
    tr->data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)data_buf;
    tr->data.ptr.offsets = 0;

    size_t total = (size_t)(data_buf + psize - wbuf);

    uint8_t rbuf[512];
    size_t consumed = 0;
    int ret = send_bc_with_reply(wbuf, total, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);

    if (ret < 0) {
        log_fmt("SM2 check '%s': ioctl FAILED errno=%d (%s)", name, errno, strerror(errno));
        return -1;
    }
    log_fmt("SM2 check '%s': consumed=%zu", name, consumed);
    if (consumed > 0) log_hex("SM2 rbuf", rbuf, consumed > 128 ? 128 : consumed);

    return parse_sm_reply(rbuf, consumed, name, "SM2");
}

/* Strategy 3: Try via /dev/vndbinder if available */
static int check_service_vnd(const char* name) {
    int saved_fd = binder_fd;
    int vnd_fd = open("/dev/vndbinder", O_RDWR | O_CLOEXEC);
    if (vnd_fd < 0) return -1;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));

    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;
    write_parcel_string16(&p, "android.os.IServiceManager");
    write_parcel_string16(&p, name);
    size_t psize = (size_t)(p - pbuf);

    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) { close(vnd_fd); return -1; }

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr)); wp += sizeof(*tr);
    tr->target.handle = 0;
    tr->code          = 1;
    tr->flags         = TF_ACCEPT_FDS;
    tr->data_size     = (binder_size_t)psize;
    tr->offsets_size  = 0;
    uint8_t* data_buf = wp;
    memcpy(data_buf, pbuf, psize);
    tr->data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)data_buf;

    size_t total = (size_t)(data_buf + psize - wbuf);

    uint8_t rbuf[512];
    memset(rbuf, 0, sizeof(rbuf));
    size_t consumed = 0;
    bwr.write_size = total;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;
    int ret = ioctl(vnd_fd, BINDER_WRITE_READ, &bwr);
    consumed = (size_t)bwr.read_consumed;
    free(wbuf);
    close(vnd_fd);

    if (ret < 0) return -1;
    if (consumed == 0) return -1;
    return parse_sm_reply(rbuf, consumed, name, "VND");
}

static int check_service_exists(const char* name) {
    int r = check_service_sm1(name);
    if (r >= 0) return r;
    r = check_service_sm2(name);
    if (r >= 0) return r;
    return check_service_vnd(name);
}

static int register_one_name(const char* name) {
    int exists = check_service_exists(name);
    if (exists > 0) {
        log_fmt("'%s' already registered, skipping", name);
        return 0;
    }

    uint8_t pbuf[2048];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;
    *(uint32_t*)p = 0; p += 4;
    write_parcel_string16(&p, "android.os.IServiceManager");
    write_parcel_string16(&p, name);

    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - pbuf);

    if (use_new_fbo) {
        struct flat_binder_object fbo;
        memset(&fbo, 0, sizeof(fbo));
        fbo.hdr.type = BINDER_TYPE_BINDER;
        fbo.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
        fbo.binder = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        fbo.cookie = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);
    } else {
        struct { uint32_t type; uint32_t flags; uint32_t __reserved;
                 binder_uintptr_t binder; binder_uintptr_t cookie; } fbo_legacy;
        memset(&fbo_legacy, 0, sizeof(fbo_legacy));
        fbo_legacy.type   = 1;
        fbo_legacy.flags  = 0x7f | 0x100;
        fbo_legacy.binder = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        fbo_legacy.cookie = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        memcpy(p, &fbo_legacy, sizeof(fbo_legacy)); p += sizeof(fbo_legacy);
    }

    *(uint32_t*)p = 0; p += 4; /* uid */
    *(uint32_t*)p = 0; p += 4; /* flags */

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
    tr->code          = SM_ADD_SERVICE;
    tr->flags         = TF_ACCEPT_FDS;
    tr->data_size     = (binder_size_t)psize;
    tr->offsets_size  = (binder_size_t)offsets_bytes;

    uint8_t* data_start = wp;
    memcpy(data_start, pbuf, psize);
    memcpy(data_start + psize, offsets, offsets_bytes);
    tr->data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)data_start;
    tr->data.ptr.offsets = (binder_uintptr_t)(uintptr_t)(data_start + psize);

    size_t write_len = (size_t)(data_start + psize + offsets_bytes - wbuf);
    log_fmt("register '%s': psize=%zu offsets=%zu total=%zu", name, psize, offsets_bytes, write_len);
    log_hex("reg wbuf", wbuf, write_len > 128 ? 128 : write_len);

    uint8_t rbuf[512];
    size_t consumed = 0;
    int ret = send_bc_with_reply(wbuf, write_len, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);

    if (ret < 0) {
        log_fmt("register '%s': ioctl FAILED errno=%d (%s)", name, errno, strerror(errno));
        return -1;
    }
    log_fmt("register '%s': consumed=%zu", name, consumed);
    if (consumed > 0) log_hex("reg rbuf", rbuf, consumed > 128 ? 128 : consumed);

    return parse_sm_reply(rbuf, consumed, name, "register");
}

static const char* SERVICE_NAMES[] = {
    "netstats",
    "netstats_service",
    "network_stats",
    "network_management",
    "NetworkStatsService",
    "netstatsmanager",
    NULL
};

static int register_with_sm(void) {
    log_msg("registering with ServiceManager...");

    /* Log diagnostic info */
    struct net_stats s;
    read_all_stats(&s);
    log_fmt("Current stats: rx=%llu tx=%llu",
            (unsigned long long)s.rxBytes, (unsigned long long)s.txBytes);

    int success = 0;
    for (int retry = 0; retry < 5 && !success; retry++) {
        log_fmt("--- registration round %d/5 ---", retry + 1);
        for (int i = 0; SERVICE_NAMES[i]; i++) {
            log_fmt("trying '%s'...", SERVICE_NAMES[i]);
            if (register_one_name(SERVICE_NAMES[i]) == 0)
                success = 1;
        }
        if (!success && retry < 4) {
            log_fmt("registration retry %d/4, waiting %ds...", retry + 1, 2 + retry * 2);
            sleep(2 + retry * 2);
        }
    }

    if (!success) {
        log_msg("WARNING: failed to register under ANY service name");
        log_msg("  All tried: netstats, netstats_service, network_stats,");
        log_msg("  network_management, NetworkStatsService, netstatsmanager");
        log_msg("  Continuing in passive mode (stats from /proc/net/dev)");
        unlink(REGFILE);
        return -1;
    }

    FILE* rf = fopen(REGFILE, "w");
    if (rf) { fprintf(rf, "registered=1\n"); fclose(rf); }
    return 0;
}

/* ============================================================
 * Binder event loop
 * ============================================================ */

#define TX_GET_TOTAL_STATS      1
#define TX_GET_IFACE_STATS      2
#define TX_FORCE_UPDATE         3
#define TX_GET_UID_STATS        4
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

static void handle_transaction(const struct binder_transaction_data* tr) {
    uint8_t reply_data[2048];
    uint8_t* rp = reply_data;
    size_t reply_size = 0;

    /* exception = 0 */
    *(uint32_t*)rp = 0; rp += 4;

    struct net_stats s;
    read_all_stats(&s);

    switch (tr->code) {
        case TX_GET_TOTAL_STATS:
        case TX_GET_TOTAL_STATS_V2: {
            const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
            const uint8_t* pend = pp + tr->data_size;
            if (pp + 4 <= pend) pp += 4;
            if (pp + 4 <= pend) skip_parcel_string16(&pp);
            int type = TYPE_RX_BYTES;
            if (pp + 4 <= pend) { memcpy(&type, pp, 4); pp += 4; }
            uint64_t val = pick_stat(&s, type);
            memcpy(rp, &val, 8); rp += 8;
            reply_size = (size_t)(rp - reply_data);
            log_fmt("getTotalStats type=%d -> %llu", type, (unsigned long long)val);
            break;
        }
        case TX_GET_IFACE_STATS:
        case TX_GET_IFACE_STATS_V2: {
            const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
            const uint8_t* pend = pp + tr->data_size;
            if (pp + 4 <= pend) pp += 4;
            if (pp + 4 <= pend) skip_parcel_string16(&pp);
            char iface[64] = "wlan0";
            if (pp + 4 <= pend) {
                uint32_t nlen; memcpy(&nlen, pp, 4); pp += 4;
                if (nlen > 0 && nlen < 60 && pp + nlen * 2 <= pend) {
                    for (uint32_t i = 0; i < nlen; i++) iface[i] = (char)pp[i * 2];
                    iface[nlen] = '\0';
                }
            }
            int type = TYPE_RX_BYTES;
            if (pp + 4 <= pend) { memcpy(&type, pp, 4); pp += 4; }
            struct net_stats is;
            if (read_iface_stats(iface, &is) != 0) is = s;
            uint64_t val = pick_stat(&is, type);
            memcpy(rp, &val, 8); rp += 8;
            reply_size = (size_t)(rp - reply_data);
            break;
        }
        case TX_GET_UID_STATS:
            /* return 0 for per-UID stats (not available without BPF) */
            memcpy(rp, &(uint64_t){0}, 8); rp += 8;
            reply_size = (size_t)(rp - reply_data);
            break;
        case TX_FORCE_UPDATE:
        case TX_FORCE_UPDATE_V2:
            reply_size = 4; /* just exception=0 */
            update_stats_file();
            break;
        case TX_PING:
        case TX_PING2:
            *(uint32_t*)rp = 1; rp += 4;
            reply_size = (size_t)(rp - reply_data);
            break;
        default:
            reply_size = 4; /* just exception=0 */
            break;
    }

    /* Send BC_REPLY */
    size_t rwbuf_size = 4 + sizeof(struct binder_transaction_data) + reply_size + 64;
    uint8_t* rwbuf = (uint8_t*)calloc(1, rwbuf_size);
    if (!rwbuf) return;
    uint8_t* rwp = rwbuf;
    *(uint32_t*)rwp = BC_REPLY; rwp += 4;
    struct binder_transaction_data* rtr = (struct binder_transaction_data*)rwp;
    memset(rtr, 0, sizeof(*rtr)); rwp += sizeof(*rtr);
    rtr->cookie    = tr->cookie;
    rtr->code      = 0;
    rtr->flags     = TF_ACCEPT_FDS;
    rtr->data_size = (binder_size_t)reply_size;
    rtr->data.ptr.buffer = (binder_uintptr_t)(uintptr_t)rwp;
    memcpy(rwp, reply_data, reply_size);
    size_t write_len = (size_t)(rwp + reply_size - rwbuf);
    uint8_t discard[256];
    size_t consumed = 0;
    send_bc_with_reply(rwbuf, write_len, discard, sizeof(discard), &consumed);
    free(rwbuf);
}

static void run_event_loop(void) {
    uint8_t* rbuf = (uint8_t*)malloc(BINDER_BUF_SIZE);
    if (!rbuf) { log_msg("FATAL: malloc for event loop"); return; }
    log_msg("Proxy active, entering main loop...");
    uint32_t idle = 0;
    while (1) {
        size_t consumed = 0;
        int ret = send_bc_with_reply(NULL, 0, rbuf, BINDER_BUF_SIZE, &consumed);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            log_errno("main loop read");
            break;
        }
        if (consumed == 0) { idle++; usleep(5000); if ((idle % 200) == 0) update_stats_file(); continue; }
        idle = 0;
        const uint8_t* rp = rbuf;
        const uint8_t* rend = rbuf + consumed;
        while (rp < rend) {
            if (rp + 4 > rend) break;
            uint32_t cmd; memcpy(&cmd, rp, 4); rp += 4;
            switch (cmd) {
                case BR_TRANSACTION: {
                    if (rp + sizeof(struct binder_transaction_data) > rend) goto loop_end;
                    const struct binder_transaction_data* trp = (const struct binder_transaction_data*)rp;
                    rp += sizeof(*trp);
                    handle_transaction(trp);
                    break;
                }
                case BR_REPLY: {
                    if (rp + sizeof(struct binder_transaction_data) > rend) goto loop_end;
                    const struct binder_transaction_data* rtr = (const struct binder_transaction_data*)rp;
                    rp += sizeof(*rtr);
                    free_binder_buf(rtr->data.ptr.buffer);
                    break;
                }
                case BR_ACQUIRE:
                case BR_INCREFS: {
                    if (rp + sizeof(binder_uintptr_t) * 2 > rend) goto loop_end;
                    rp += sizeof(binder_uintptr_t) * 2;
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memset(ack + 4, 0, sizeof(binder_uintptr_t) * 2);
                    send_binder_cmd(ack, sizeof(ack));
                    break;
                }
                case BR_RELEASE:
                case BR_DECREFS:
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend)
                        rp += sizeof(binder_uintptr_t) * 2;
                    break;
                case BR_SPAWN_LOOPER: {
                    uint32_t c = BC_ENTER_LOOPER;
                    send_binder_cmd((const uint8_t*)&c, sizeof(c));
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
                case BR_DEAD_REPLY:
                    break;
                case BR_ERROR:
                    if (rp + 4 <= rend) rp += 4;
                    break;
                case BR_ACQUIRE_RESULT:
                    if (rp + 4 <= rend) rp += 4;
                    break;
                case BR_FINISHED:
                case BR_FROZEN_REPLY:
                case BR_ONEWAY_SPAM_SUSPECT:
                case BR_TRANSACTION_PENDING_FROZEN:
                    break;
                case BR_ATTEMPT_ACQUIRE:
                    if (rp + sizeof(binder_uintptr_t) * 2 <= rend)
                        rp += sizeof(binder_uintptr_t) * 2;
                    break;
                default:
                    goto loop_end;
            }
        }
        loop_end:;
    }
    free(rbuf);
}

static void sig_handler(int sig) {
    log_fmt("Caught signal %d, exiting", sig);
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    _exit(0);
}

int main(void) {
    log_fmt("Starting native netproxy v%s...", NETPROXY_VERSION);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sig_handler);
    signal(SIGINT,  sig_handler);

    log_fmt("PID=%d UID=%d GID=%d", getpid(), getuid(), getgid());
    log_fmt("SELinux: %s", getenv("SELINUX_CONTEXT") ? getenv("SELINUX_CONTEXT") : "unknown");

    if (open_binder() < 0) { log_msg("FATAL: failed to open binder"); return 1; }
    if (enter_looper() < 0) { log_msg("FATAL: enter_looper failed"); return 1; }

    update_stats_file();
    log_fmt("Stats file updated: %s", STATSFILE);

    if (register_with_sm() < 0) {
        log_msg("WARNING: ServiceManager registration failed; continuing in passive mode");
    }

    run_event_loop();
    log_msg("Exiting");
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    return 0;
}
