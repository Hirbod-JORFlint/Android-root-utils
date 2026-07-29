#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <linux/android/binder.h>

#define LOGFILE "/data/local/tmp/netproxy.log"
static void log_msg(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) {
        time_t t = time(NULL);
        struct tm* tm = localtime(&t);
        if (tm) {
            char ts[64];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
            fprintf(f, "%s netproxy: %s\n", ts, msg);
        } else {
            fprintf(f, "netproxy: %s\n", msg);
        }
        fclose(f);
    }
}
static void log_errno(const char* ctx) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) {
        time_t t = time(NULL);
        struct tm* tm = localtime(&t);
        if (tm) {
            char ts[64];
            strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
            fprintf(f, "%s netproxy: %s failed: errno=%d (%s)\n", ts, ctx, errno, strerror(errno));
        } else {
            fprintf(f, "netproxy: %s failed: errno=%d (%s)\n", ctx, errno, strerror(errno));
        }
        fclose(f);
    }
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

static void write_string16(uint8_t** buf, const char* s) {
    size_t len = strlen(s);
    write_uint32(buf, (uint32_t)(len + 1));
    for (size_t i = 0; i <= len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(*buf, &c, 2); *buf += 2;
    }
    align4(buf);
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
        while (*p == ' ') p++;
        size_t ilen = strlen(iface);
        if (strncmp(p, iface, ilen) == 0 && p[ilen] == ':') {
            char* vals = p + ilen + 1;
            int col = 0;
            char* saveptr;
            char* tok = strtok_r(vals, " \t", &saveptr);
            while (tok && col <= 10) {
                uint64_t v = strtoull(tok, NULL, 10);
                if (col == 0) out->rxBytes = v;
                else if (col == 1) out->rxPackets = v;
                else if (col == 8) out->txBytes = v;
                else if (col == 9) out->txPackets = v;
                col++;
                tok = strtok_r(NULL, " \t", &saveptr);
            }
            break;
        }
    }
    fclose(f);
    return 0;
}

static int read_all_stats(struct net_stats* out) {
    memset(out, 0, sizeof(*out));
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return -1;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ') p++;
        if (strncmp(p, "lo:", 3) == 0) continue;
        char* vals = strchr(p, ':');
        if (!vals) continue;
        vals++;
        int col = 0;
        char* saveptr;
        char* tok = strtok_r(vals, " \t", &saveptr);
        while (tok) {
            uint64_t v = strtoull(tok, NULL, 10);
            if (col == 0) out->rxBytes += v;
            else if (col == 1) out->rxPackets += v;
            else if (col == 8) out->txBytes += v;
            else if (col == 9) out->txPackets += v;
            col++;
            tok = strtok_r(NULL, " \t", &saveptr);
        }
    }
    fclose(f);
    return 0;
}

/* ---- Binder communication ---- */
#define BINDER_MMAP_SIZE (1024 * 1024)
static int binder_fd = -1;
static uint8_t* binder_map = NULL;
static uint8_t* binder_local_obj = NULL;

static int open_binder() {
    binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) {
        binder_fd = open("/dev/binder", O_RDWR);
        if (binder_fd < 0) {
            log_errno("open /dev/binder");
            return -1;
        }
    }

    struct binder_version ver;
    if (ioctl(binder_fd, BINDER_VERSION, &ver) < 0) {
        log_errno("BINDER_VERSION");
        close(binder_fd); binder_fd = -1;
        return -1;
    }
    char verstr[64];
    snprintf(verstr, sizeof(verstr), "binder protocol version %d", ver.protocol_version);
    log_msg(verstr);

    uint32_t max_threads = 4;
    if (ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads) < 0) {
        log_errno("BINDER_SET_MAX_THREADS (non-critical)");
    }

    binder_map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE,
                                binder_fd, 0);
    if (binder_map == MAP_FAILED) {
        log_errno("mmap (POPULATE)");
        binder_map = (uint8_t*)mmap(NULL, BINDER_MMAP_SIZE, PROT_READ,
                                    MAP_PRIVATE, binder_fd, 0);
        if (binder_map == MAP_FAILED) {
            log_errno("mmap (plain)");
            close(binder_fd); binder_fd = -1;
            return -1;
        }
    }

    binder_local_obj = binder_map + 256;
    log_msg("binder opened, mmap OK");
    return 0;
}

static int transact(uint32_t handle, uint32_t code,
                    const uint8_t* data, size_t data_size,
                    uint32_t* offsets, size_t offsets_size,
                    uint8_t* reply_buf, size_t reply_size,
                    size_t* reply_consumed) {
    size_t wbuf_size = 4096;
    uint8_t* wbuf = (uint8_t*)calloc(1, wbuf_size);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;

    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;

    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr)); wp += sizeof(*tr);

    tr->target.handle = handle;
    tr->code = code;
    tr->flags = 0;
    tr->data_size = (uint32_t)data_size;
    tr->offsets_size = (uint32_t)offsets_size;

    uint8_t* data_buf = wp;
    size_t total_data = data_size + offsets_size;
    if (wp + total_data > wbuf + wbuf_size) {
        free(wbuf);
        log_msg("transaction data too large");
        return -1;
    }
    memcpy(wp, data, data_size); wp += data_size;
    if (offsets && offsets_size) {
        memcpy(wp, offsets, offsets_size); wp += offsets_size;
    }

    tr->data.ptr.buffer = (binder_uintptr_t)(uintptr_t)data_buf;
    tr->data.ptr.offsets = (binder_uintptr_t)(uintptr_t)(data_buf + data_size);

    size_t write_len = wp - wbuf;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = write_len;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    bwr.read_size = reply_size;
    bwr.read_buffer = (binder_uintptr_t)(uintptr_t)reply_buf;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(wbuf);

    if (ret < 0) {
        log_errno("transaction ioctl");
        return -1;
    }

    if (reply_consumed) *reply_consumed = bwr.read_consumed;
    return 0;
}

/* ---- ServiceManager protocol ---- */
#define SM_ADD_SERVICE 3

static int register_with_sm() {
    log_msg("registering with ServiceManager...");

    uint8_t pbuf[1024];
    uint8_t* p = pbuf;

    write_string16(&p, "netstats");

    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - pbuf);

    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = BINDER_TYPE_BINDER;
    fbo.flags = 0;
    fbo.binder = (binder_uintptr_t)(uintptr_t)binder_local_obj;
    fbo.cookie = (binder_uintptr_t)(uintptr_t)binder_local_obj;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    write_uint32(&p, 0);

    write_uint32(&p, 0);

    size_t psize = p - pbuf;
    uint32_t offsets[1];
    offsets[0] = fbo_offset;

    uint8_t reply[4096];
    size_t consumed = 0;

    int ret = transact(0, SM_ADD_SERVICE,
                       pbuf, psize,
                       offsets, sizeof(offsets[0]),
                       reply, sizeof(reply), &consumed);
    if (ret < 0) {
        log_msg("register: transaction failed");
        return -1;
    }

    int registered = 0;
    const uint8_t* rp = reply;
    const uint8_t* rend = reply + consumed;

    while (rp < rend) {
        if (rp + 4 > rend) break;
        uint32_t cmd = *(const uint32_t*)rp; rp += 4;
        switch (cmd) {
            case BR_TRANSACTION_COMPLETE:
                break;
            case BR_REPLY:
                registered = 1;
                if (rp + sizeof(struct binder_transaction_data) <= rend) {
                    const struct binder_transaction_data* rtr =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*rtr);
                    uint8_t fcmd[4 + 8];
                    *(uint32_t*)fcmd = BC_FREE_BUFFER;
                    memcpy(fcmd + 4, &rtr->data.ptr.buffer, 8);
                    struct binder_write_read fbwr;
                    memset(&fbwr, 0, sizeof(fbwr));
                    fbwr.write_size = sizeof(fcmd);
                    fbwr.write_buffer = (binder_uintptr_t)(uintptr_t)fcmd;
                    ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
                }
                break;
            case BR_DEAD_BINDER:
                if (rp + 8 <= rend) rp += 8;
                break;
            case BR_NOOP:
                break;
            case BR_SPAWN_LOOPER:
                break;
            default:
                break;
        }
    }

    if (registered) {
        log_msg("registered with ServiceManager OK");
        return 0;
    }
    log_msg("register with ServiceManager FAILED (no BR_REPLY)");
    return -1;
}

/* ---- Transaction codes for INetworkStatsService ---- */
#define TX_getIfaceStats    12
#define TX_getTotalStats    13

/* ---- Stat type constants (INetworkStatsSession) ---- */
#define TYPE_RX_BYTES   0
#define TYPE_TX_BYTES   1
#define TYPE_RX_PACKETS 2
#define TYPE_TX_PACKETS 3

static void skip_string16(const uint8_t** pp) {
    uint32_t len = read_uint32(pp);
    if (len == 0xFFFFFFFF || len == 0) return;
    *pp += len * 2;
    align4((uint8_t**)pp);
}

static uint64_t pick_stat(const struct net_stats* s, int type) {
    switch (type) {
        case TYPE_RX_BYTES:   return s->rxBytes;
        case TYPE_TX_BYTES:   return s->txBytes;
        case TYPE_RX_PACKETS: return s->rxPackets;
        case TYPE_TX_PACKETS: return s->txPackets;
        default:              return s->rxBytes + s->txBytes;
    }
}

/* ---- Parcel exception header ---- */
static void write_exception(uint8_t** buf, int32_t code) {
    write_uint32(buf, 0);
    write_uint32(buf, 0);
    write_uint32(buf, code);
}

static void write_no_exception(uint8_t** buf) {
    write_uint32(buf, 0);
    write_uint32(buf, 0);
    write_uint32(buf, 0);
}

static void handle_getIfaceStats(const struct binder_transaction_data* tr,
                                 uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t* pend = pp + tr->data_size;

    pp += 8;

    if (pp + 4 <= pend) skip_string16(&pp);

    char iface[64] = "wlan0";
    if (pp + 4 <= pend) {
        uint32_t name_len = read_uint32(&pp);
        if (name_len > 0 && name_len < 32 && pp + name_len * 2 <= pend) {
            size_t copy_len = name_len < 32 ? name_len : 31;
            for (size_t i = 0; i < copy_len; i++) {
                if (pp[i*2] >= 32 && pp[i*2] < 127) {
                    iface[i] = (char)pp[i*2];
                } else {
                    iface[i] = '?';
                }
            }
            iface[copy_len] = '\0';
        }
        pp += name_len * 2;
        align4((uint8_t**)&pp);
    }

    int type = TYPE_RX_BYTES;
    if (pp + 4 <= pend) {
        type = (int)read_uint32(&pp);
    }

    struct net_stats s;
    if (read_iface_stats(iface, &s) != 0) {
        read_all_stats(&s);
    }
    uint64_t val = pick_stat(&s, type);
    write_uint64(&rp, val);
    *reply_size = rp - reply_buf;
}

static void handle_getTotalStats(const struct binder_transaction_data* tr,
                                  uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t* pend = pp + tr->data_size;

    pp += 8;

    if (pp + 4 <= pend) skip_string16(&pp);

    int type = TYPE_RX_BYTES;
    if (pp + 4 <= pend) {
        type = (int)read_uint32(&pp);
    }

    struct net_stats s;
    read_all_stats(&s);
    uint64_t val = pick_stat(&s, type);
    write_uint64(&rp, val);
    *reply_size = rp - reply_buf;
}

static void handle_transaction(const struct binder_transaction_data* tr) {
    uint8_t reply_data[2048];
    size_t reply_size = 0;

    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf), "got transaction code=%u", tr->code);
    log_msg(logbuf);

    switch (tr->code) {
        case TX_getIfaceStats:
            handle_getIfaceStats(tr, reply_data, &reply_size);
            break;
        case TX_getTotalStats:
            handle_getTotalStats(tr, reply_data, &reply_size);
            break;
        default:
            log_msg("  unsupported code, returning empty");
            reply_data[0] = 0; reply_data[1] = 0;
            reply_data[2] = 0;
            reply_data[3] = 0;
            write_uint64((uint8_t**)&reply_data + 4, 0);
            reply_size = 12;
            break;
    }

    uint8_t rwbuf[4096];
    uint8_t* rwp = rwbuf;

    *(uint32_t*)rwp = BC_REPLY; rwp += 4;

    struct binder_transaction_data rtr;
    memset(&rtr, 0, sizeof(rtr));
    rtr.target.ptr = 0;
    rtr.cookie = tr->cookie;
    rtr.code = 0;
    rtr.flags = 0;
    rtr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)rwp;
    rtr.data_size = (uint32_t)reply_size;

    memcpy(rwp, reply_data, reply_size);
    rwp += reply_size;

    size_t write_len = 4 + sizeof(rtr) + reply_size;
    *(uint32_t*)(rwbuf + 4 + offsetof(struct binder_transaction_data, data_size)) = (uint32_t)reply_size;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = write_len;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)rwbuf;
    bwr.read_size = 256;
    bwr.read_buffer = (binder_uintptr_t)(uintptr_t)(rwbuf + 4096 - 256);

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_errno("send_reply");
    }
}

uint32_t enter_looper() {
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)&cmd;
    bwr.read_size = 256;
    uint8_t rbuf[256];
    bwr.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_errno("BC_ENTER_LOOPER");
        return 0;
    }
    log_msg("BC_ENTER_LOOPER OK");
    return bwr.read_consumed;
}

int main(void) {
    log_msg("Starting native netproxy v2...");

    if (open_binder() < 0) {
        log_msg("FATAL: failed to open binder");
        return 1;
    }

    if (!enter_looper()) {
        log_msg("FATAL: BC_ENTER_LOOPER failed");
        return 1;
    }

    if (register_with_sm() < 0) {
        log_msg("Failed to register service");
        log_msg("Trying direct alternative approach...");
    }

    log_msg("Proxy active, entering main loop...");

    uint8_t rbuf[16384];

    while (1) {
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;

        int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            log_errno("main loop ioctl");
            if (errno == EINTR || errno == EAGAIN) continue;
            log_msg("Fatal binder error, exiting loop");
            break;
        }
        if (bwr.read_consumed == 0) {
            usleep(10000);
            continue;
        }

        const uint8_t* rp = rbuf;
        const uint8_t* rend = rbuf + bwr.read_consumed;

        while (rp < rend) {
            if (rp + 4 > rend) break;
            uint32_t cmd = *(const uint32_t*)rp; rp += 4;
            switch (cmd) {
                case BR_TRANSACTION: {
                    if (rp + sizeof(struct binder_transaction_data) > rend) break;
                    const struct binder_transaction_data* trp =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*trp);
                    handle_transaction(trp);
                    break;
                }
                case BR_REPLY:
                    if (rp + sizeof(struct binder_transaction_data) <= rend) {
                        const struct binder_transaction_data* rtr =
                            (const struct binder_transaction_data*)rp;
                        rp += sizeof(*rtr);
                        uint8_t fcmd[4 + 8];
                        *(uint32_t*)fcmd = BC_FREE_BUFFER;
                        memcpy(fcmd + 4, &rtr->data.ptr.buffer, 8);
                        struct binder_write_read fbwr;
                        memset(&fbwr, 0, sizeof(fbwr));
                        fbwr.write_size = sizeof(fcmd);
                        fbwr.write_buffer = (binder_uintptr_t)(uintptr_t)fcmd;
                        ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
                    }
                    break;
                case BR_TRANSACTION_COMPLETE:
                    break;
                case BR_NOOP:
                    break;
                case BR_SPAWN_LOOPER: {
                    uint32_t c = BC_ENTER_LOOPER;
                    struct binder_write_read bwr2;
                    memset(&bwr2, 0, sizeof(bwr2));
                    bwr2.write_size = sizeof(c);
                    bwr2.write_buffer = (binder_uintptr_t)(uintptr_t)&c;
                    ioctl(binder_fd, BINDER_WRITE_READ, &bwr2);
                    break;
                }
                case BR_DEAD_BINDER:
                    if (rp + 8 <= rend) rp += 8;
                    break;
                case BR_CLEAR_DEATH_NOTIFICATION_DONE:
                    break;
                default: {
                    char ebuf[128];
                    snprintf(ebuf, sizeof(ebuf), "unknown cmd %u at offset %d", cmd,
                             (int)(rp - 4 - rbuf));
                    log_msg(ebuf);
                    break;
                }
            }
        }
    }

    log_msg("Exiting");
    if (binder_map) munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0) close(binder_fd);
    return 0;
}
