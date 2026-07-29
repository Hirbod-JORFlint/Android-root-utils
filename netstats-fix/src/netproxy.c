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

#define LOGFILE "/data/local/tmp/netproxy.log"
static void log_msg(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "netproxy: %s\n", msg); fclose(f); }
}

/* ---- Binder driver structures (from linux/binder.h) ---- */
#define BINDER_CURRENT_PROTOCOL_VERSION 8

struct binder_version {
    int32_t protocol_version;
};

struct flat_binder_object {
    int32_t  type;
    int32_t  flags;
    void*    binder;
    void*    cookie;
};

struct binder_transaction_data {
    union {
        size_t  handle;
        void*   ptr;
    } target;
    void*   cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    int32_t  sender_euid;
    size_t   data_size;
    size_t   offsets_size;
    union {
        struct {
            const void* buffer;
            const void* offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_write_read {
    size_t  write_size;
    size_t  write_consumed;
    void*   write_buffer;
    size_t  read_size;
    size_t  read_consumed;
    void*   read_buffer;
};

/* Binder command codes (write to driver) */
#define BC_TRANSACTION        _IOC(_IOC_WRITE, 'c', 0, sizeof(struct binder_transaction_data))
#define BC_REPLY              _IOC(_IOC_WRITE, 'c', 1, sizeof(struct binder_transaction_data))
#define BC_ENTER_LOOPER       _IOC(_IOC_WRITE, 'c', 3, 0)
#define BC_EXIT_LOOPER        _IOC(_IOC_WRITE, 'c', 4, 0)
#define BC_REGISTER_LOOPER    _IOC(_IOC_WRITE, 'c', 2, 0)
#define BC_FREE_BUFFER        _IOC(_IOC_WRITE, 'c', 5, sizeof(void*))

/* Binder response codes (read from driver) */
#define BR_TRANSACTION        _IOC(_IOC_READ, 'c', 0, sizeof(struct binder_transaction_data))
#define BR_REPLY              _IOC(_IOC_READ, 'c', 1, sizeof(struct binder_transaction_data))
#define BR_TRANSACTION_COMPLETE _IOC(_IOC_READ, 'c', 6, 0)
#define BR_NOOP               _IOC(_IOC_READ, 'c', 8, 0)
#define BR_SPAWN_LOOPER       _IOC(_IOC_READ, 'c', 7, 0)
#define BR_DEAD_BINDER        _IOC(_IOC_READ, 'c', 5, sizeof(void*))
#define BR_CLEAR_DEATH_NOTIFICATION_DONE _IOC(_IOC_READ, 'c', 12, sizeof(void*))

/* Binder ioctls */
#define BINDER_WRITE_READ     _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION        _IOWR('b', 9, struct binder_version)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, size_t)

/* flat_binder_object types */
enum {
    BINDER_TYPE_BINDER  = 1,
    BINDER_TYPE_WEAK_BINDER = 2,
    BINDER_TYPE_HANDLE = 3,
    BINDER_TYPE_WEAK_HANDLE = 4,
    BINDER_TYPE_FD      = 5,
    BINDER_TYPE_FD_ABSOLUTE = 6,
};

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
static void write_obj(uint8_t** p, const void* data, size_t len) {
    memcpy(*p, data, len); *p += len;
}

static uint32_t read_uint32(const uint8_t** p) {
    uint32_t v; memcpy(&v, *p, 4); *p += 4; return v;
}
static uint64_t read_uint64(const uint8_t** p) {
    uint64_t v; memcpy(&v, *p, 8); *p += 8; return v;
}

/* Write a String16 (length + data, 4-byte aligned) */
static void write_string16(uint8_t** p, const char* s) {
    // Convert ASCII to char16_t manually
    size_t len = strlen(s);
    uint32_t alen = (uint32_t)len;
    write_uint32(p, alen + 1);  // includes null terminator
    for (size_t i = 0; i <= len; i++) {
        // null terminates: i==len writes \0
        write_uint32(p, (uint32_t)((unsigned char)s[i]));
        // Actually each char16_t is 2 bytes, need alignment:
    }
}
/* More careful String16 write with alignment */
static void write_string16_aligned(uint8_t** buf, const char* s) {
    size_t len = strlen(s);
    // String16 in Parcel: int32(length) + char16_t[length+1] (null-terminated)
    // Total bytes = 4 + (len+1)*2
    uint32_t total_chars = (uint32_t)(len + 1);  // +1 for null
    write_uint32(buf, total_chars);
    for (size_t i = 0; i <= len; i++) {
        uint16_t c = (uint16_t)(unsigned char)s[i];
        memcpy(*buf, &c, 2);
        *buf += 2;
    }
    // 4-byte align
    size_t data_bytes = 4 + total_chars * 2;
    while ((uintptr_t)(*buf) % 4 != 0) { **buf = 0; (*buf)++; }
}

static void align_to_4(uint8_t** buf) {
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
            // Format: rxBytes rxPackets rxErrs rxDrop rxFifo rxFrame rxCompressed rxMulticast
            //         txBytes txPackets txErrs ...
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
    fgets(line, sizeof(line), f); // header
    fgets(line, sizeof(line), f); // header
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
static size_t binder_map_size = 1024 * 1024;  // 1 MB

static int open_binder() {
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        log_msg("open /dev/binder failed");
        return -1;
    }
    
    struct binder_version ver;
    if (ioctl(binder_fd, BINDER_VERSION, &ver) < 0) {
        log_msg("BINDER_VERSION ioctl failed");
        close(binder_fd); binder_fd = -1;
        return -1;
    }
    if (ver.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION) {
        log_msg("binder version mismatch");
    }
    
    size_t max_threads = 4;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    
    binder_map = (uint8_t*)mmap(NULL, binder_map_size, PROT_READ,
                                MAP_PRIVATE | MAP_NORESERVE | MAP_POPULATE,
                                binder_fd, 0);
    if (binder_map == MAP_FAILED) {
        log_msg("mmap binder failed, trying without POPULATE");
        binder_map = (uint8_t*)mmap(NULL, binder_map_size, PROT_READ,
                                    MAP_PRIVATE, binder_fd, 0);
        if (binder_map == MAP_FAILED) {
            log_msg("mmap binder failed");
            close(binder_fd); binder_fd = -1;
            return -1;
        }
    }
    log_msg("binder opened, mmap OK");
    return 0;
}

static int send_binder_cmd(int cmd, const void* data, size_t data_size) {
    // Build command buffer: [cmd32, data...]
    size_t total = 4 + data_size;
    uint8_t* wbuf = (uint8_t*)malloc(total);
    if (!wbuf) return -1;
    *(uint32_t*)wbuf = cmd;
    if (data && data_size) memcpy(wbuf + 4, data, data_size);
    
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = wbuf;
    bwr.write_size = total;
    
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(wbuf);
    return ret;
}

static int binder_call(uint32_t target_handle, uint32_t code,
                       const uint8_t* send_data, size_t send_size,
                       uint8_t* reply_buf, size_t reply_buf_size,
                       size_t* reply_actual) {
    struct binder_transaction_data tr;
    memset(&tr, 0, sizeof(tr));
    tr.target.handle = target_handle;
    tr.code = code;
    tr.data.ptr.buffer = send_data;
    tr.data.ptr.offsets = NULL;
    tr.data_size = send_size;
    tr.offsets_size = 0;
    tr.flags = 0;
    
    // Write BC_TRANSACTION to driver
    uint8_t wbuf[512];
    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    memcpy(wp, &tr, sizeof(tr)); wp += sizeof(tr);
    size_t wsize = wp - wbuf;
    
    // Read buffer for response
    uint8_t rbuf[4096];
    
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = wbuf;
    bwr.write_size = wsize;
    bwr.read_buffer = rbuf;
    bwr.read_size = sizeof(rbuf);
    
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_msg("binder_call ioctl failed");
        return -1;
    }
    
    // Process responses
    const uint8_t* rp = rbuf;
    const uint8_t* rend = rbuf + bwr.read_consumed;
    int got_reply = 0;
    
    while (rp < rend) {
        uint32_t cmd = *(const uint32_t*)rp; rp += 4;
        switch (cmd) {
            case BR_TRANSACTION: {
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);
                size_t dsize = rtr->data_size;
                if (dsize <= reply_buf_size) {
                    memcpy(reply_buf, rtr->data.ptr.buffer, dsize);
                    if (reply_actual) *reply_actual = dsize;
                }
                got_reply = 1;
                // Free buffer
                uint8_t free_cmd[4 + 8];
                *(uint32_t*)free_cmd = BC_FREE_BUFFER;
                memcpy(free_cmd + 4, &rtr->data.ptr.buffer, 8);
                // Send free (non-blocking)
                struct binder_write_read fbwr;
                memset(&fbwr, 0, sizeof(fbwr));
                fbwr.write_buffer = free_cmd;
                fbwr.write_size = sizeof(free_cmd);
                ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
                break;
            }
            case BR_REPLY: {
                const struct binder_transaction_data* rtr =
                    (const struct binder_transaction_data*)rp;
                rp += sizeof(*rtr);
                size_t dsize = rtr->data_size;
                if (dsize <= reply_buf_size) {
                    memcpy(reply_buf, rtr->data.ptr.buffer, dsize);
                    if (reply_actual) *reply_actual = dsize;
                }
                got_reply = 1;
                // Free buffer
                uint8_t free_cmd[4 + 8];
                *(uint32_t*)free_cmd = BC_FREE_BUFFER;
                memcpy(free_cmd + 4, &rtr->data.ptr.buffer, 8);
                struct binder_write_read fbwr;
                memset(&fbwr, 0, sizeof(fbwr));
                fbwr.write_buffer = free_cmd;
                fbwr.write_size = sizeof(free_cmd);
                ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
                break;
            }
            case BR_TRANSACTION_COMPLETE:
                break;
            case BR_NOOP:
                break;
            case BR_SPAWN_LOOPER:
                break;
            case BR_DEAD_BINDER: {
                rp += 8;
                break;
            }
            default:
                break;
        }
    }
    return got_reply ? 0 : -1;
}

/* ---- Main proxy logic ---- */

// We store our local binder pointer so we can reply to transactions
static void* local_binder = NULL;

static int send_reply(const struct binder_transaction_data* req,
                      const uint8_t* data, size_t dsize) {
    struct binder_transaction_data tr;
    memset(&tr, 0, sizeof(tr));
    tr.target.ptr = NULL;
    tr.cookie = req->cookie;
    tr.code = 0;
    tr.flags = 0;
    tr.data.ptr.buffer = data;
    tr.data_size = dsize;
    
    uint8_t wbuf[4096];
    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_REPLY; wp += 4;
    memcpy(wp, &tr, sizeof(tr)); wp += sizeof(tr);
    size_t wsize = wp - wbuf;
    
    uint8_t rbuf[256];
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = wbuf;
    bwr.write_size = wsize;
    bwr.read_buffer = rbuf;
    bwr.read_size = sizeof(rbuf);
    
    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_msg("send_reply ioctl failed");
        return -1;
    }
    return 0;
}

static int register_with_sm() {
    int ret = 0;
    // Build Parcel: String16("netstats") + flat_binder_object + int32(allow_isolated=0)
    uint8_t pbuf[512];
    uint8_t* p = pbuf;
    
    // String16 service name
    write_string16_aligned(&p, "netstats");
    
    // flat_binder_object representing our local service
    // type = BINDER_TYPE_BINDER (local)
    // binder = our AIBinder pointer (we use a static value)
    // cookie = 0
    align_to_4(&p);
    struct flat_binder_object fbo;
    memset(&fbo, 0, sizeof(fbo));
    fbo.type = BINDER_TYPE_BINDER;
    fbo.binder = local_binder;
    fbo.cookie = 0;
    fbo.flags = 0;  // 0x127 = private, 0 = normal
    memcpy(p, &fbo, sizeof(fbo)); p += sizeof(fbo);
    
    // allow_isolated = 0
    write_uint32(&p, 0);
    
    size_t psize = p - pbuf;
    
    log_msg("registering with ServiceManager...");
    
    // craft a transaction with offsets for the flat_binder_object
    // We need to tell the driver where the flat_binder_object is
    // For simplicity, we put a fake offset at 0
    // Actually, for binder objects we MUST provide offsets
    uint8_t tbuf[1024];
    uint8_t* tp = tbuf;
    
    // The transaction data format: Parcel data + offsets array
    // But the driver expects binder_transaction_data with offsets
    
    // Actually, let me restructure: we send a BC_TRANSACTION with proper offset info
    // The offsets array points to each flat_binder_object in the data
    
    // We need offsets_size > 0 because we have a flat_binder_object
    // Each offset is the byte offset from start of data buffer to the flat_binder_object
    
    // Wait, the offset of fbo from the start of the data buffer:
    // String16 = 4 (length) + (len("netstats")+1)*2 bytes
    // then padding to 4 bytes
    // then fbo starts at `pbuf + 4 + (7+1)*2 = pbuf + 20`, aligned to 4
    // Actually: write_string16_aligned does:
    //   write_uint32(len+1) = 4 bytes
    //   write 8 char16_t values = 16 bytes
    //   total = 20 bytes, already aligned
    //   fbo starts at offset 20 from pbuf
    uint32_t fbo_offset = 20;
    
    // But wait, the driver expects the data to be in a specific format for
    // registering services. Let me look at the ServiceManager source.
    
    // Actually, for ADD_SERVICE, the ServiceManager expects:
    // Parcel containing:
    //   strong_ptr_t: Binder (which is a flat_binder_object)
    //   int32_t: allow_isolated
    // The name is passed as String16
    
    // But the parcel is actually encoded by the framework's Parcel class.
    // The flat_binder_object is embedded at a specific offset within the Parcel data.
    
    // Let me just try to build the complete transaction with offsets
    uint8_t* tx_data = tbuf + sizeof(struct binder_transaction_data);
    uint32_t* offsets_arr = (uint32_t*)(tx_data + psize);
    size_t offs_size = sizeof(uint32_t); // one offset
    
    memcpy(tx_data, pbuf, psize);
    offsets_arr[0] = fbo_offset;
    
    struct binder_transaction_data tr;
    memset(&tr, 0, sizeof(tr));
    tr.target.handle = 0;  // ServiceManager
    tr.code = ADD_SERVICE_TRANS;
    tr.data.ptr.buffer = tx_data;
    tr.data.ptr.offsets = offsets_arr;
    tr.data_size = psize;
    tr.offsets_size = offs_size;
    
    uint8_t wbuf[2048];
    uint8_t* wp = wbuf;
    *(uint32_t*)wp = BC_TRANSACTION; wp += 4;
    memcpy(wp, &tr, sizeof(tr)); wp += sizeof(tr);
    size_t wsize = wp - wbuf;
    // Add the actual data after the command struct
    memcpy(wp, tx_data, psize); wp += psize;
    // Actually the data is referenced by pointer in the struct, but the ioctl
    // expects everything in the write buffer. The driver reads the buffer pointer
    // from the struct and expects it to be valid. Since we're not relocating,
    // the buffer pointer should point to the data within the same memory.
    // Let me fix this: the data buffer pointer should point to the actual data.
    // But our struct has data.ptr.buffer = tx_data which is in stack.
    // The ioctl copies the write buffer to kernel space. The kernel then reads
    // the data.ptr.buffer pointer. Since we passed the buffer via write_buffer,
    // the pointer tx_data is a user-space address that the kernel will copy_from_user.
    // This should work.
    
    // Actually, the way BINDER_WRITE_READ works:
    // 1. Kernel copies write_buffer from userspace
    // 2. Kernel processes the commands in the buffer
    // 3. For BC_TRANSACTION, the binder_transaction_data contains pointers to data
    //    These pointers are user-space addresses that the kernel copies from
    
    // So the data.ptr.buffer and data.ptr.offsets must point to memory within
    // the userspace process that is accessible. Since we allocated them on the
    // stack, they should be accessible. But the kernel copies FROM them during
    // the ioctl call, so they need to be valid at the time of the call.
    
    // Let me rewrite more carefully:
    uint8_t* bigbuf = (uint8_t*)malloc(4096);
    if (!bigbuf) return -1;
    
    // Layout: cmd + binder_transaction_data + [data_buffer + offsets]
    uint8_t* bb = bigbuf;
    
    // Command
    *(uint32_t*)bb = BC_TRANSACTION; bb += 4;
    
    // Transaction header (with pointers to data AFTER the header)
    struct binder_transaction_data* trp = (struct binder_transaction_data*)bb;
    memset(trp, 0, sizeof(*trp)); bb += sizeof(*trp);
    
    trp->target.handle = 0;
    trp->code = ADD_SERVICE_TRANS;
    trp->data_size = psize;
    trp->offsets_size = offs_size;
    trp->data.ptr.buffer = bb;       // point to data right here
    trp->data.ptr.offsets = (void*)((uintptr_t)bb + psize);
    
    // Copy data
    memcpy(bb, pbuf, psize); bb += psize;
    memcpy(bb, offsets_arr, offs_size); bb += offs_size;
    
    size_t total_size = bb - bigbuf;
    
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_buffer = bigbuf;
    bwr.write_size = total_size;
    bwr.read_buffer = malloc(4096);
    bwr.read_size = 4096;
    
    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) {
        log_msg("ADD_SERVICE ioctl failed");
        free(bigbuf); free(bwr.read_buffer);
        return -1;
    }
    
    // Parse response
    const uint8_t* rp = (const uint8_t*)bwr.read_buffer;
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
                // Free buffer
                uint8_t fcmd[4 + 8];
                *(uint32_t*)fcmd = BC_FREE_BUFFER;
                memcpy(fcmd + 4, &rtr->data.ptr.buffer, 8);
                struct binder_write_read fbwr;
                memset(&fbwr, 0, sizeof(fbwr));
                fbwr.write_buffer = fcmd;
                fbwr.write_size = sizeof(fcmd);
                ioctl(binder_fd, BINDER_WRITE_READ, &fbwr);
                break;
            }
            default:
                break;
        }
    }
    
    free(bigbuf); free(bwr.read_buffer);
    
    if (registered) {
        log_msg("registered with ServiceManager OK");
        return 0;
    }
    log_msg("register with ServiceManager FAILED");
    return -1;
}

/* Stats type constants (from TrafficStats) */
#define TYPE_RX_BYTES   0
#define TYPE_TX_BYTES   1
#define TYPE_RX_PACKETS 2
#define TYPE_TX_PACKETS 3

/* Parcel: skip a String16, return bytes consumed */
static size_t skip_string16(const uint8_t** pp) {
    uint32_t len = read_uint32(pp);
    if (len == 0xFFFFFFFF) return 4; // null string
    *pp += len * 2;
    // Align to 4
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
    
    // Common reply header: writeNoException() = int32(0)
    write_uint32(&rp, 0);
    
    if (tr->code == TX_getIfaceStats) {
        const uint8_t* pp = (const uint8_t*)tr->data.ptr.buffer;
        // Skip: int32(0) from writeInterfaceToken
        pp += 4;
        // Skip: String16(interface descriptor)
        skip_string16(&pp);
        // Read: String16(iface name)
        uint32_t name_len = read_uint32(&pp);
        char iface[64] = "wlan0";
        if (name_len > 0 && name_len < 32) {
            size_t copy_len = name_len < 32 ? name_len : 31;
            for (size_t i = 0; i < copy_len; i++) {
                iface[i] = (char)pp[i*2]; // ASCII only
            }
            iface[copy_len] = '\0';
        }
        pp += name_len * 2;
        // Read: int32(type)
        int type = (int)read_uint32(&pp);
        
        struct net_stats s;
        if (read_iface_stats(iface, &s) != 0) {
            read_all_stats(&s);
        }
        uint64_t val = pick_stat(&s, type);
        write_uint64(&rp, val);
        send_reply(tr, reply_data, rp - reply_data);
        
    } else if (tr->code == TX_getTotalStats) {
        const uint8_t* pp = (const uint8_t*)tr->data.ptr.buffer;
        // Skip: int32(0) from writeInterfaceToken
        pp += 4;
        // Skip: String16(interface descriptor)
        skip_string16(&pp);
        // Read: int32(type)
        int type = (int)read_uint32(&pp);
        
        struct net_stats s;
        read_all_stats(&s);
        uint64_t val = pick_stat(&s, type);
        write_uint64(&rp, val);
        send_reply(tr, reply_data, rp - reply_data);
        
    } else {
        // Unknown transaction: send back 0 as reply to avoid hanging
        write_uint64(&rp, 0);
        send_reply(tr, reply_data, rp - reply_data);
    }
}

int main(void) {
    log_msg("starting native netproxy...");
    
    // Set up our local binder identity
    local_binder = (void*)0x4242;  // placeholder
    
    if (open_binder() < 0) {
        log_msg("failed to open binder");
        return 1;
    }
    
    // Enter looper
    uint32_t enter_cmd = BC_ENTER_LOOPER;
    if (send_binder_cmd(enter_cmd, NULL, 0) < 0) {
        log_msg("BC_ENTER_LOOPER failed");
        return 1;
    }
    log_msg("BC_ENTER_LOOPER OK");
    
    // Register with ServiceManager
    if (register_with_sm() < 0) {
        log_msg("failed to register service");
        return 1;
    }
    
    log_msg("proxy active, entering main loop...");
    
    // Main loop: read and process binder transactions
    uint8_t rbuf[16384];
    
    while (1) {
        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_buffer = rbuf;
        bwr.read_size = sizeof(rbuf);
        
        int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            log_msg("main loop ioctl failed");
            break;
        }
        
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
                case BR_SPAWN_LOOPER: {
                    // Driver wants more threads, ignore for single-threaded
                    break;
                }
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
