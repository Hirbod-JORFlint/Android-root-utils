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
#include <linux/android/binder.h>

#define LOGFILE "/data/local/tmp/netproxy.log"
static void log_msg(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "netproxy: %s\n", msg); fclose(f); }
}
static void log_errno(const char* ctx) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "netproxy: %s failed: errno=%d (%s)\n", ctx, errno, strerror(errno)); fclose(f); }
}

/* ---- Binder driver structures (from NDK linux/android/binder.h) ---- */

typedef __u64 binder_uintptr_t;
typedef __u64 binder_size_t;

/* ---- ServiceManager protocol ---- */
#define SM_MANAGER_SVC      0
#define ADD_SERVICE_TRANS   3
#define CHECK_SERVICE_TRANS 2
#define GET_SERVICE_TRANS   1

/* ---- INetworkStatsService transaction codes ---- */
#define TX_getIfaceStats  12
#define TX_getTotalStats  13

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

/* Write a String16 in Parcel format: int32(length in chars) + char16_t[length] (4-byte aligned) */
static void write_string16_aligned(uint8_t** buf, const char* s) {
    size_t len = strlen(s);
    uint32_t total_chars = (uint32_t)(len + 1);
    write_uint32(buf, total_chars);
    for (size_t i = 0; i <= len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(*buf, &c, 2);
        *buf += 2;
    }
    while ((uintptr_t)(*buf) % 4 != 0) { **buf = 0; (*buf)++; }
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
            char* tok;
            int col = 0;
            tok = strtok(vals, " \t");
            while (tok && col <= 10) {
                uint64_t v = strtoull(tok, NULL, 10);
                if (col == 0) out->rxBytes = v;
                else if (col == 1) out->rxPackets = v;
                else if (col == 8) out->txBytes = v;
                else if (col == 9) out->txPackets = v;
                col++;
                tok = strtok(NULL, " \t");
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
    fgets(line, sizeof(line), f);
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char* p = line;
        while (*p == ' ') p++;
        if (strncmp(p, "lo:", 3) == 0) continue;
        char* vals = strchr(p, ':');
        if (!vals) continue;
        vals++;
        char* tok = strtok(vals, " \t");
        int col = 0;
        while (tok) {
            uint64_t v = strtoull(tok, NULL, 10);
            if (col == 0) out->rxBytes += v;
            else if (col == 1) out->rxPackets += v;
            else if (col == 8) out->txBytes += v;
            else if (col == 9) out->txPackets += v;
            col++;
            tok = strtok(NULL, " \t");
        }
    }
    fclose(f);
    return 0;
}

/* ---- Binder communication ---- */
static int binder_fd = -1;
static uint8_t* binder_map = NULL;
static size_t binder_map_size = 1024 * 1024;

static int open_binder() {
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        log_errno("open /dev/binder");
        return -1;
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
    if (ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads) < 0)
        log_errno("BINDER_SET_MAX_THREADS");

    binder_map = (uint8_t*)mmap(NULL, binder_map_size, PROT_READ,
                                MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE,
                                binder_fd, 0);
    if (binder_map == MAP_FAILED) {
        log_errno("mmap (POPULATE)");
        binder_map = (uint8_t*)mmap(NULL, binder_map_size, PROT_READ,
                                    MAP_PRIVATE, binder_fd, 0);
        if (binder_map == MAP_FAILED) {
            log_errno("mmap (plain)");
            close(binder_fd); binder_fd = -1;
            return -1;
        }
    }
    log_msg("binder opened, mmap OK");
    return 0;
}

static int send_binder_cmd(uint32_t cmd, const void* data, size_t data_size) {
    size_t total = 4 + data_size;
    uint8_t* wbuf = (uint8_t*)malloc(total);
    if (!wbuf) return -1;
    *(uint32_t*)wbuf = cmd;
    if (data && data_size) memcpy(wbuf + 4, data, data_size);

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = total;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) log_errno("send_binder_cmd");
    free(wbuf);
    return ret;
}

/* ---- Main proxy logic ---- */

static void* local_binder = NULL;

static int send_reply(const struct binder_transaction_data* req,
                      const uint8_t* data, size_t dsize) {
    struct binder_transaction_data tr;
    memset(&tr, 0, sizeof(tr));
    tr.target.ptr = 0;
    tr.cookie = req->cookie;
    tr.code = 0;
    tr.flags = 0;
    tr.data.ptr.buffer = (binder_uintptr_t)(uintptr_t)data;
    tr.data_size = dsize;

    uint8_t wbuf[4096];
    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_REPLY; wp += 4;
    memcpy(wp, &tr, sizeof(tr)); wp += sizeof(tr);
    size_t wsize = wp - wbuf;

    uint8_t rbuf[256];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = wsize;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)wbuf;
    bwr.read_size = sizeof(rbuf);
    bwr.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_errno("send_reply");
        return -1;
    }
    return 0;
}

static int register_with_sm() {
    int ret = 0;
    uint8_t pbuf[512];
    uint8_t* p = pbuf;

    write_string16_aligned(&p, "netstats");

    uint32_t fbo_offset = (uint32_t)(p - pbuf);
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.hdr.type = BINDER_TYPE_BINDER;
    fbo.binder = (binder_uintptr_t)(uintptr_t)local_binder;
    fbo.cookie = 0;
    fbo.flags = 0;
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);

    write_uint32(&p, 0);

    size_t psize = p - pbuf;
    size_t offs_size = sizeof(uint32_t);

    log_msg("registering with ServiceManager...");

    uint8_t* bigbuf = (uint8_t*)malloc(4096);
    if (!bigbuf) return -1;
    uint8_t* bb = bigbuf;

    *(uint32_t*)bb = BC_TRANSACTION; bb += 4;

    struct binder_transaction_data* trp = (struct binder_transaction_data*)bb;
    memset(trp, 0, sizeof(*trp)); bb += sizeof(*trp);

    trp->target.handle = 0;
    trp->code = ADD_SERVICE_TRANS;
    trp->data_size = psize;
    trp->offsets_size = offs_size;
    trp->data.ptr.buffer = (binder_uintptr_t)(uintptr_t)bb;
    trp->data.ptr.offsets = (binder_uintptr_t)((uintptr_t)bb + psize);

    memcpy(bb, pbuf, psize);
    *(uint32_t*)(bb + psize) = fbo_offset;
    bb += psize + offs_size;

    size_t total_size = bb - bigbuf;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = total_size;
    bwr.write_buffer = (binder_uintptr_t)(uintptr_t)bigbuf;
    uint8_t readbuf[4096];
    bwr.read_size = sizeof(readbuf);
    bwr.read_buffer = (binder_uintptr_t)(uintptr_t)readbuf;

    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_errno("ADD_SERVICE");
        free(bigbuf);
        return -1;
    }

    const uint8_t* rp = readbuf;
    const uint8_t* rend = rp + bwr.read_consumed;
    int registered = 0;

    while (rp < rend) {
        uint32_t cmd = *(const uint32_t*)rp; rp += 4;
        switch (cmd) {
            case BR_TRANSACTION_COMPLETE:
                break;
            case BR_REPLY: {
                registered = 1;
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
                break;
            }
            default:
                break;
        }
    }

    free(bigbuf);

    if (registered) {
        log_msg("registered with ServiceManager OK");
        return 0;
    }
    log_msg("register with ServiceManager FAILED");
    return -1;
}

#define TYPE_RX_BYTES   0
#define TYPE_TX_BYTES   1
#define TYPE_RX_PACKETS 2
#define TYPE_TX_PACKETS 3

static size_t skip_string16(const uint8_t** pp) {
    uint32_t len = read_uint32(pp);
    if (len == 0xFFFFFFFF) return 4;
    *pp += len * 2;
    size_t total = 4 + len * 2;
    while ((uintptr_t)(*pp) % 4 != 0) { (*pp)++; total++; }
    return total;
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

static void handle_transaction(const struct binder_transaction_data* tr) {
    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf), "got transaction code=%u", tr->code);
    log_msg(logbuf);

    uint8_t reply_data[1024];
    uint8_t* rp = reply_data;

    write_uint32(&rp, 0);

    if (tr->code == TX_getIfaceStats) {
        const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
        pp += 4;
        skip_string16(&pp);
        uint32_t name_len = read_uint32(&pp);
        char iface[64] = "wlan0";
        if (name_len > 0 && name_len < 32) {
            size_t copy_len = name_len < 32 ? name_len : 31;
            for (size_t i = 0; i < copy_len; i++) {
                iface[i] = (char)pp[i*2];
            }
            iface[copy_len] = '\0';
        }
        pp += name_len * 2;
        int type = (int)read_uint32(&pp);

        struct net_stats s;
        if (read_iface_stats(iface, &s) != 0) {
            read_all_stats(&s);
        }
        uint64_t val = pick_stat(&s, type);
        write_uint64(&rp, val);
        send_reply(tr, reply_data, rp - reply_data);

    } else if (tr->code == TX_getTotalStats) {
        const uint8_t* pp = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
        pp += 4;
        skip_string16(&pp);
        int type = (int)read_uint32(&pp);

        struct net_stats s;
        read_all_stats(&s);
        uint64_t val = pick_stat(&s, type);
        write_uint64(&rp, val);
        send_reply(tr, reply_data, rp - reply_data);

    } else {
        write_uint64(&rp, 0);
        send_reply(tr, reply_data, rp - reply_data);
    }
}

int main(void) {
    log_msg("starting native netproxy...");

    local_binder = (void*)(uintptr_t)0x4242;

    if (open_binder() < 0) {
        log_msg("failed to open binder");
        return 1;
    }

    uint32_t enter_cmd = BC_ENTER_LOOPER;
    if (send_binder_cmd(enter_cmd, NULL, 0) < 0) {
        log_msg("BC_ENTER_LOOPER failed");
        return 1;
    }
    log_msg("BC_ENTER_LOOPER OK");

    if (register_with_sm() < 0) {
        log_msg("failed to register service");
        return 1;
    }

    log_msg("proxy active, entering main loop...");

    uint8_t rbuf[16384];

    while (1) {
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(rbuf);
        bwr.read_buffer = (binder_uintptr_t)(uintptr_t)rbuf;

        int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            log_errno("main loop ioctl");
            if (errno == EINTR) continue;
            break;
        }
        if (bwr.read_consumed == 0) continue;

        const uint8_t* rp = rbuf;
        const uint8_t* rend = rbuf + bwr.read_consumed;

        while (rp < rend) {
            uint32_t cmd = *(const uint32_t*)rp; rp += 4;
            switch (cmd) {
                case BR_TRANSACTION: {
                    const struct binder_transaction_data* trp =
                        (const struct binder_transaction_data*)rp;
                    rp += sizeof(*trp);
                    handle_transaction(trp);
                    break;
                }
                case BR_REPLY:
                    rp += sizeof(struct binder_transaction_data);
                    break;
                case BR_TRANSACTION_COMPLETE:
                    break;
                case BR_NOOP:
                    break;
                case BR_SPAWN_LOOPER:
                    break;
                case BR_DEAD_BINDER:
                    rp += 8;
                    break;
                default: {
                    char ebuf[64];
                    snprintf(ebuf, sizeof(ebuf), "unknown cmd %u", cmd);
                    log_msg(ebuf);
                    goto done;
                }
            }
        }
    }

done:
    log_msg("exiting");
    if (binder_map) munmap(binder_map, binder_map_size);
    if (binder_fd >= 0) close(binder_fd);
    return 0;
}
