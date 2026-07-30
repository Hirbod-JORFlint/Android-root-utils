#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
#define NETPROXY_VERSION "5.0"

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

struct net_stats {
    uint64_t rxBytes, rxPackets, txBytes, txPackets;
};

struct per_iface_stats {
    char iface[64];
    struct net_stats stats;
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
    return -1;
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

static int read_iface_list(struct per_iface_stats* out, int max_ifaces) {
    int count = 0;
    FILE* f = fopen("/proc/net/dev", "r");
    if (!f) return 0;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    while (fgets(line, sizeof(line), f) && count < max_ifaces) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "lo:", 3) == 0) continue;
        char* colon = strchr(p, ':');
        if (!colon) continue;
        size_t iflen = (size_t)(colon - p);
        if (iflen >= sizeof(out[0].iface)) iflen = sizeof(out[0].iface) - 1;
        memcpy(out[count].iface, p, iflen);
        out[count].iface[iflen] = '\0';
        memset(&out[count].stats, 0, sizeof(out[count].stats));
        char* vals = colon + 1;
        int col = 0;
        char* saveptr;
        char* tok = strtok_r(vals, " \t\n\r", &saveptr);
        while (tok) {
            uint64_t v = strtoull(tok, NULL, 10);
            if      (col == 0) out[count].stats.rxBytes   = v;
            else if (col == 1) out[count].stats.rxPackets  = v;
            else if (col == 8) out[count].stats.txBytes    = v;
            else if (col == 9) out[count].stats.txPackets  = v;
            col++;
            if (col > 9) break;
            tok = strtok_r(NULL, " \t\n\r", &saveptr);
        }
        count++;
    }
    fclose(f);
    return count;
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
 * Binder IPC - simplified and more compatible approach
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
    bwr.read_size    = 0;
    bwr.read_buffer  = 0;
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
    if (ret < 0) {
        log_errno("enter_looper send_bc");
        return -1;
    }
    log_msg("BC_ENTER_LOOPER sent");
    return 0;
}

/* String helpers - writeUTF16AsNeeded for Android parcel format */
static void write_parcel_string16(uint8_t** buf, const char* s) {
    uint32_t len = (uint32_t)strlen(s);
    memcpy(*buf, &len, 4); *buf += 4;
    for (uint32_t i = 0; i < len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(*buf, &c, 2); *buf += 2;
    }
    uint16_t nul = 0;
    memcpy(*buf, &nul, 2); *buf += 2;
    /* Align to 4 bytes */
    while ((uintptr_t)(*buf) % 4 != 0) { **buf = 0; (*buf)++; }
}

/* Skip a parcel string16 in read buffer */
static void skip_parcel_string16(const uint8_t** pp) {
    uint32_t len;
    memcpy(&len, *pp, 4); *pp += 4;
    if (len == 0xFFFFFFFFu) return;
    *pp += (len + 1) * 2;
    while ((uintptr_t)(*pp) % 4 != 0) (*pp)++;
}

static uint32_t read_uint32(const uint8_t** p) {
    uint32_t v; memcpy(&v, *p, 4); *p += 4; return v;
}
static uint64_t read_uint64(const uint8_t** p) {
    uint64_t v; memcpy(&v, *p, 8); *p += 8; return v;
}

/* ============================================================
 * ServiceManager registration with multiple strategies
 * ============================================================ */

#define SM_HANDLE          0
#define SM_CHECK_SERVICE   1
#define SM_ADD_SERVICE     3

/* Strategy 1: Standard AOSP format (what service call uses) */
static int check_service_sm1(const char* name) {
    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;

    /* Exception code */
    *(uint32_t*)p = 0; p += 4;

    /* Interface descriptor */
    write_parcel_string16(&p, "android.os.IServiceManager");

    /* Service name */
    write_parcel_string16(&p, name);

    size_t psize = (size_t)(p - pbuf);

    uint8_t rbuf[512];
    memset(rbuf, 0, sizeof(rbuf));
    size_t consumed = 0;

    /* Build BC_TRANSACTION */
    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;

    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr));
    wp += sizeof(*tr);

    tr->target.handle = SM_HANDLE;
    tr->code          = SM_CHECK_SERVICE;
    tr->flags         = TF_ACCEPT_FDS;
    tr->data_size     = (binder_size_t)psize;
    tr->offsets_size  = 0;
    tr->data.ptr.buffer  = (binder_uintptr_t)(uintptr_t)wp;
    tr->data.ptr.offsets = 0;

    memcpy(wp, pbuf, psize);

    int ret = send_bc_with_reply(wbuf, (size_t)(wp + psize - wbuf),
                                  rbuf, sizeof(rbuf), &consumed);
    free(wbuf);

    if (ret < 0) {
        log_fmt("SM1 check '%s': send failed errno=%d", name, errno);
        return -1;
    }

    /* Parse reply */
    const uint8_t* rp = rbuf;
    const uint8_t* rend = rbuf + consumed;
    while (rp < rend) {
        if (rp + 4 > rend) break;
        uint32_t cmd = *(const uint32_t*)rp; rp += 4;
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
                if (rp + sizeof(struct binder_transaction_data) > rend) goto done;
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);
                if (rtr->data_size >= 8) {
                    const uint8_t* data = (const uint8_t*)(uintptr_t)rtr->data.ptr.buffer;
                    uint32_t exc = *(const uint32_t*)data;
                    if (exc == 0) {
                        uint32_t has = *(const uint32_t*)(data + 4);
                        free_binder_buf(rtr->data.ptr.buffer);
                        if (has != 0) {
                            log_fmt("SM1 '%s': service EXISTS", name);
                            return 1;
                        }
                        log_fmt("SM1 '%s': not found", name);
                        return 0;
                    }
                    free_binder_buf(rtr->data.ptr.buffer);
                    log_fmt("SM1 '%s': exception %u", name, exc);
                    return 0;
                }
                free_binder_buf(rtr->data.ptr.buffer);
                goto done;
            }
            case BR_ACQUIRE:
            case BR_INCREFS: {
                if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                    binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memcpy(ack + 4, &ptr, sizeof(binder_uintptr_t));
                    memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
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
                log_fmt("SM1 '%s': BR_FAILED_REPLY", name);
                goto done;
            case BR_DEAD_REPLY:
                log_fmt("SM1 '%s': BR_DEAD_REPLY", name);
                goto done;
            case BR_ERROR: {
                int32_t err = 0;
                if (rp + 4 <= rend) memcpy(&err, rp, 4);
                log_fmt("SM1 '%s': BR_ERROR %d", name, err);
                goto done;
            }
            default:
                goto done;
        }
    }
done:
    return -1;
}

/* Strategy 2: No offsets (for check_service) - sometimes required */
static int check_service_sm2(const char* name) {
    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;

    /* No explicit exception prefix - just interface + name */
    write_parcel_string16(&p, "android.os.IServiceManager");
    write_parcel_string16(&p, name);

    size_t psize = (size_t)(p - pbuf);

    uint8_t rbuf[512];
    memset(rbuf, 0, sizeof(rbuf));
    size_t consumed = 0;

    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;

    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr));
    wp += sizeof(*tr);

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
    int ret = send_bc_with_reply(wbuf, total, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);

    if (ret < 0) {
        log_fmt("SM2 check '%s': send failed errno=%d", name, errno);
        return -1;
    }

    const uint8_t* rp = rbuf;
    const uint8_t* rend = rbuf + consumed;
    while (rp < rend) {
        if (rp + 4 > rend) break;
        uint32_t cmd = *(const uint32_t*)rp; rp += 4;
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
                if (rp + sizeof(struct binder_transaction_data) > rend) goto done2;
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);
                if (rtr->data_size >= 8) {
                    const uint8_t* data = (const uint8_t*)(uintptr_t)rtr->data.ptr.buffer;
                    uint32_t exc = *(const uint32_t*)data;
                    if (exc == 0) {
                        uint32_t has = *(const uint32_t*)(data + 4);
                        free_binder_buf(rtr->data.ptr.buffer);
                        if (has != 0) {
                            log_fmt("SM2 '%s': service EXISTS", name);
                            return 1;
                        }
                        log_fmt("SM2 '%s': not found", name);
                        return 0;
                    }
                    free_binder_buf(rtr->data.ptr.buffer);
                    log_fmt("SM2 '%s': exception %u", name, exc);
                    return 0;
                }
                free_binder_buf(rtr->data.ptr.buffer);
                goto done2;
            }
            case BR_ACQUIRE:
            case BR_INCREFS: {
                if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                    binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memcpy(ack + 4, &ptr, sizeof(binder_uintptr_t));
                    memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
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
                log_fmt("SM2 '%s': BR_FAILED_REPLY", name);
                goto done2;
            case BR_DEAD_REPLY:
                log_fmt("SM2 '%s': BR_DEAD_REPLY", name);
                goto done2;
            case BR_ERROR: {
                int32_t err = 0;
                if (rp + 4 <= rend) memcpy(&err, rp, 4);
                log_fmt("SM2 '%s': BR_ERROR %d", name, err);
                goto done2;
            }
            default:
                goto done2;
        }
    }
done2:
    return -1;
}

static int check_service_exists(const char* name) {
    int r = check_service_sm1(name);
    if (r >= 0) return r;
    return check_service_sm2(name);
}

static int register_one_name(const char* name) {
    int exists = check_service_exists(name);
    if (exists > 0) {
        log_fmt("'%s' already registered, skipping", name);
        return 0;
    }
    if (exists < 0) {
        log_fmt("check failed for '%s', trying registration anyway", name);
    }

    /* Build add_service parcel */
    uint8_t pbuf[2048];
    memset(pbuf, 0, sizeof(pbuf));
    uint8_t* p = pbuf;

    /* Exception prefix */
    *(uint32_t*)p = 0; p += 4;

    /* Interface descriptor */
    write_parcel_string16(&p, "android.os.IServiceManager");

    /* Service name */
    write_parcel_string16(&p, name);

    uint32_t fbo_offset = (uint32_t)(uintptr_t)(p - pbuf);

    /* flat_binder_object */
    if (use_new_fbo) {
        struct flat_binder_object fbo;
        memset(&fbo, 0, sizeof(fbo));
        fbo.hdr.type = BINDER_TYPE_BINDER;
        fbo.flags = 0x7f | FLAT_BINDER_FLAG_ACCEPTS_FDS;
        fbo.binder = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        fbo.cookie = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);
    } else {
        struct {
            uint32_t type;
            uint32_t flags;
            uint32_t __reserved;
            binder_uintptr_t binder;
            binder_uintptr_t cookie;
        } fbo_legacy;
        memset(&fbo_legacy, 0, sizeof(fbo_legacy));
        fbo_legacy.type   = 1;
        fbo_legacy.flags  = 0x7f | 0x100;
        fbo_legacy.binder = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        fbo_legacy.cookie = (binder_uintptr_t)(uintptr_t)binder_local_obj;
        memcpy(p, &fbo_legacy, sizeof(fbo_legacy)); p += sizeof(fbo_legacy);
    }

    /* int32 uid = 0 */
    *(uint32_t*)p = 0; p += 4;
    /* int32 flags = 0 */
    *(uint32_t*)p = 0; p += 4;

    size_t   psize   = (size_t)(p - pbuf);
    uint32_t offsets[1] = { fbo_offset };

    /* Build BC_TRANSACTION */
    size_t offsets_bytes = sizeof(offsets);
    size_t wsize = 4 + sizeof(struct binder_transaction_data) + psize + offsets_bytes + 64;
    uint8_t* wbuf = (uint8_t*)calloc(1, wsize);
    if (!wbuf) return -1;

    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;

    struct binder_transaction_data* tr = (struct binder_transaction_data*)wp;
    memset(tr, 0, sizeof(*tr));
    wp += sizeof(*tr);

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

    uint8_t rbuf[512];
    memset(rbuf, 0, sizeof(rbuf));
    size_t consumed = 0;

    int ret = send_bc_with_reply(wbuf, write_len, rbuf, sizeof(rbuf), &consumed);
    free(wbuf);

    if (ret < 0) {
        log_fmt("register '%s': send failed errno=%d", name, errno);
        return -1;
    }

    const uint8_t* rp = rbuf;
    const uint8_t* rend = rbuf + consumed;
    while (rp < rend) {
        if (rp + 4 > rend) break;
        uint32_t cmd = *(const uint32_t*)rp; rp += 4;
        switch (cmd) {
            case BR_NOOP:
            case BR_TRANSACTION_COMPLETE:
            case BR_FINISHED:
                break;
            case BR_REPLY: {
                if (rp + sizeof(struct binder_transaction_data) > rend) goto reg_done;
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);
                if (rtr->data_size >= 4) {
                    const uint8_t* data = (const uint8_t*)(uintptr_t)rtr->data.ptr.buffer;
                    uint32_t exc = *(const uint32_t*)data;
                    free_binder_buf(rtr->data.ptr.buffer);
                    if (exc != 0) {
                        log_fmt("register '%s': exception %u", name, exc);
                        return -1;
                    }
                    log_fmt("registered '%s' OK", name);
                    return 0;
                }
                free_binder_buf(rtr->data.ptr.buffer);
                goto reg_done;
            }
            case BR_ACQUIRE:
            case BR_INCREFS: {
                if (rp + sizeof(binder_uintptr_t) * 2 <= rend) {
                    binder_uintptr_t ptr    = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    binder_uintptr_t cookie = *(binder_uintptr_t*)rp; rp += sizeof(binder_uintptr_t);
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memcpy(ack + 4, &ptr, sizeof(binder_uintptr_t));
                    memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
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
                log_fmt("register '%s': BR_FAILED_REPLY", name);
                goto reg_done;
            case BR_DEAD_REPLY:
                log_fmt("register '%s': BR_DEAD_REPLY", name);
                goto reg_done;
            case BR_ERROR: {
                int32_t err = 0;
                if (rp + 4 <= rend) memcpy(&err, rp, 4);
                log_fmt("register '%s': BR_ERROR %d", name, err);
                goto reg_done;
            }
            default:
                goto reg_done;
        }
    }
reg_done:
    return -1;
}

static const char* SERVICE_NAMES[] = {
    "netstats",
    "netstats_service",
    "network_stats",
    NULL
};

static int register_with_sm(void) {
    log_msg("registering with ServiceManager...");
    int success = 0;

    for (int retry = 0; retry < 5 && !success; retry++) {
        for (int i = 0; SERVICE_NAMES[i]; i++) {
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
        log_msg("  Traffic indicator will show total traffic (no per-app)");
        unlink(REGFILE);
        return -1;
    }

    FILE* rf = fopen(REGFILE, "w");
    if (rf) {
        fprintf(rf, "registered=1\n");
        fclose(rf);
    }
    return 0;
}

/* ============================================================
 * Binder event loop - handle incoming transactions
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

static void write_no_exception(uint8_t** buf) {
    *(uint32_t*)*buf = 0; *buf += 4;
}

static void handle_getIfaceStats(const struct binder_transaction_data* tr,
                                  uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    const uint8_t* pp   = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t* pend = pp + tr->data_size;

    if (pp + 4 <= pend) pp += 4;
    if (pp + 4 <= pend) skip_parcel_string16(&pp);

    char iface[64];
    strncpy(iface, "wlan0", sizeof(iface));
    if (pp + 4 <= pend) {
        uint32_t name_len;
        memcpy(&name_len, pp, 4); pp += 4;
        if (name_len > 0 && name_len < 60 && pp + name_len * 2 <= pend) {
            for (uint32_t i = 0; i < name_len; i++)
                iface[i] = (char)pp[i * 2];
            iface[name_len] = '\0';
            pp += (name_len + 1) * 2;
            while ((uintptr_t)pp % 4 != 0) pp++;
        }
    }

    int type = TYPE_RX_BYTES;
    if (pp + 4 <= pend) { memcpy(&type, pp, 4); pp += 4; }

    struct net_stats s;
    if (read_iface_stats(iface, &s) != 0) read_all_stats(&s);

    uint64_t val = pick_stat(&s, type);
    memcpy(rp, &val, 8); rp += 8;
    *reply_size = (size_t)(rp - reply_buf);
}

static void handle_getTotalStats(const struct binder_transaction_data* tr,
                                  uint8_t* reply_buf, size_t* reply_size) {
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    const uint8_t* pp   = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t* pend = pp + tr->data_size;

    if (pp + 4 <= pend) pp += 4;
    if (pp + 4 <= pend) skip_parcel_string16(&pp);

    int type = TYPE_RX_BYTES;
    if (pp + 4 <= pend) { memcpy(&type, pp, 4); pp += 4; }

    struct net_stats s;
    read_all_stats(&s);
    uint64_t val = pick_stat(&s, type);
    memcpy(rp, &val, 8); rp += 8;
    *reply_size = (size_t)(rp - reply_buf);
}

static void handle_getDeviceSummary(const struct binder_transaction_data* tr,
                                     uint8_t* reply_buf, size_t* reply_size) {
    (void)tr;
    uint8_t* rp = reply_buf;
    write_no_exception(&rp);

    struct net_stats s;
    read_all_stats(&s);

    memcpy(rp, &(uint64_t){0}, 8); rp += 8;
    memcpy(rp, &s.rxBytes, 8); rp += 8;
    memcpy(rp, &s.txBytes, 8); rp += 8;
    memcpy(rp, &s.rxPackets, 8); rp += 8;
    memcpy(rp, &s.txPackets, 8); rp += 8;
    memcpy(rp, &(uint64_t){0}, 8); rp += 8;
    *(uint32_t*)rp = 0; rp += 4;

    *reply_size = (size_t)(rp - reply_buf);
}

static void handle_transaction(const struct binder_transaction_data* tr) {
    uint8_t reply_data[2048];
    uint8_t* reply_rp = reply_data;
    size_t   reply_size = 0;

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
            write_no_exception(&reply_rp);
            memcpy(reply_rp, &(uint64_t){0}, 8); reply_rp += 8;
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
            write_no_exception(&reply_rp);
            *(uint32_t*)reply_rp = 1; reply_rp += 4;
            reply_size = (size_t)(reply_rp - reply_data);
            break;

        case 5:
        case 6:
        case 7:
        case 8:
            handle_getDeviceSummary(tr, reply_data, &reply_size);
            break;

        default:
            {
                const uint8_t* pp   = (const uint8_t*)(uintptr_t)tr->data.ptr.buffer;
                const uint8_t* pend = pp + tr->data_size;
                if (pp + 8 <= pend) {
                    pp += 4;
                    if (pp + 4 <= pend) skip_parcel_string16(&pp);
                    if (pp + 4 <= pend) {
                        int guessed_type;
                        memcpy(&guessed_type, pp, 4);
                        if (guessed_type >= 0 && guessed_type <= 3) {
                            struct net_stats s;
                            read_all_stats(&s);
                            uint64_t val = pick_stat(&s, guessed_type);
                            write_no_exception(&reply_rp);
                            memcpy(reply_rp, &val, 8); reply_rp += 8;
                            reply_size = (size_t)(reply_rp - reply_data);
                            break;
                        }
                    }
                }
            }
            write_no_exception(&reply_rp);
            reply_size = (size_t)(reply_rp - reply_data);
            break;
    }

    /* Send BC_REPLY */
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

    size_t write_len = (size_t)(rwp + reply_size - rwbuf);
    uint8_t discard[256];
    size_t consumed = 0;
    send_bc_with_reply(rwbuf, write_len, discard, sizeof(discard), &consumed);
    free(rwbuf);
}

static void run_event_loop(void) {
    uint8_t* rbuf = (uint8_t*)malloc(BINDER_BUF_SIZE);
    if (!rbuf) { log_msg("FATAL: malloc for event loop buffer"); return; }

    log_msg("Proxy active, entering main loop...");

    uint32_t idle_count = 0;

    while (1) {
        size_t consumed = 0;
        int ret = send_bc_with_reply(NULL, 0, rbuf, BINDER_BUF_SIZE, &consumed);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            log_errno("main loop read");
            break;
        }
        if (consumed == 0) {
            idle_count++;
            usleep(5000);
            if ((idle_count % 200) == 0) update_stats_file();
            continue;
        }
        idle_count = 0;

        const uint8_t* rp   = rbuf;
        const uint8_t* rend = rbuf + consumed;

        while (rp < rend) {
            if (rp + 4 > rend) break;
            uint32_t cmd;
            memcpy(&cmd, rp, 4); rp += 4;

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
                    binder_uintptr_t ptr, cookie;
                    memcpy(&ptr, rp, sizeof(binder_uintptr_t)); rp += sizeof(binder_uintptr_t);
                    memcpy(&cookie, rp, sizeof(binder_uintptr_t)); rp += sizeof(binder_uintptr_t);
                    uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                    *(uint32_t*)ack = (cmd == BR_ACQUIRE) ? BC_ACQUIRE_DONE : BC_INCREFS_DONE;
                    memcpy(ack + 4, &ptr, sizeof(binder_uintptr_t));
                    memcpy(ack + 4 + sizeof(binder_uintptr_t), &cookie, sizeof(binder_uintptr_t));
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
                    break;
                case BR_DEAD_REPLY:
                    break;
                case BR_ERROR: {
                    int32_t err = 0;
                    if (rp + 4 <= rend) memcpy(&err, rp, 4);
                    rp += 4;
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
                        rp += sizeof(binder_uintptr_t) * 2;
                        uint8_t ack[4 + sizeof(binder_uintptr_t) * 2];
                        *(uint32_t*)ack = BC_ACQUIRE_DONE;
                        memset(ack + 4, 0, sizeof(binder_uintptr_t) * 2);
                        send_binder_cmd(ack, sizeof(ack));
                    }
                    break;
                }
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
    signal(SIGINT,  sig_handler);

    if (open_binder() < 0) {
        log_msg("FATAL: failed to open binder");
        return 1;
    }

    if (enter_looper() < 0) {
        log_msg("FATAL: enter_looper failed");
        return 1;
    }

    update_stats_file();

    if (register_with_sm() < 0) {
        log_msg("WARNING: ServiceManager registration failed; continuing in passive mode");
    }

    run_event_loop();

    log_msg("Exiting");
    unlink(REGFILE);
    if (binder_map && binder_map != MAP_FAILED)
        munmap(binder_map, BINDER_MMAP_SIZE);
    if (binder_fd >= 0)
        close(binder_fd);
    return 0;
}
