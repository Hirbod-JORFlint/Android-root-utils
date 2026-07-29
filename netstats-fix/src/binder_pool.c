#include <jni.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <android/log.h>

#define LOG_TAG "binder_pool"
#define LOGFILE "/data/local/tmp/netproxy.log"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static void file_log(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "binder_pool: %s\n", msg); fclose(f); }
}

typedef void* (*ipc_self_t)();
typedef void  (*join_pool_t)(void*, bool);

/*
 * Returns: 0=success(joined), 1=dlopen fail, 2=dlsym self fail,
 *          3=dlsym join fail, 4=self NULL, 5=join returned unexpected,
 *          6=no symbols found at all
 */
JNIEXPORT jint JNICALL Java_com_flint_netstats_NetworkStatsProxy_nativeJoinThreadPool(
    JNIEnv* env, jclass clazz) {

    ipc_self_t ipc_self = NULL;
    join_pool_t join_pool = NULL;
    void* handle = NULL;

    // First try RTLD_DEFAULT — libbinder.so is already loaded in process
    ipc_self = (ipc_self_t)dlsym(RTLD_DEFAULT, "_ZN7android14IPCThreadState4selfEv");
    if (ipc_self) {
        join_pool = (join_pool_t)dlsym(RTLD_DEFAULT, "_ZN7android14IPCThreadState14joinThreadPoolEb");
    }

    if (!ipc_self) {
        file_log("RTLD_DEFAULT failed, trying dlopen...");
        // Try absolute path first (bypasses namespace restrictions)
        handle = dlopen("/system/lib64/libbinder.so", RTLD_LAZY);
        if (!handle) handle = dlopen("libbinder.so", RTLD_LAZY);
        if (!handle) {
            file_log("dlopen libbinder.so failed");
            LOGE("dlopen libbinder.so failed: %s", dlerror());
            return 1;
        }

        ipc_self = (ipc_self_t)dlsym(handle, "_ZN7android14IPCThreadState4selfEv");
        if (!ipc_self) {
            file_log("dlsym IPCThreadState::self failed via dlopen");
            LOGE("dlsym IPCThreadState::self failed: %s", dlerror());
            dlclose(handle);
            return 2;
        }

        join_pool = (join_pool_t)dlsym(handle, "_ZN7android14IPCThreadState14joinThreadPoolEb");
        if (!join_pool) {
            file_log("dlsym IPCThreadState::joinThreadPool failed via dlopen");
            LOGE("dlsym IPCThreadState::joinThreadPool failed: %s", dlerror());
            dlclose(handle);
            return 3;
        }
    } else if (!join_pool) {
        // Found self but not join
        file_log("dlsym IPCThreadState::self OK but joinThreadPool missing");
        LOGE("found self but joinThreadPool missing from RTLD_DEFAULT");
        return 6;
    } else {
        file_log("symbols found via RTLD_DEFAULT (no dlopen needed)");
    }

    void* self = ipc_self();
    if (!self) {
        file_log("IPCThreadState::self returned NULL");
        LOGE("IPCThreadState::self returned NULL");
        if (handle) dlclose(handle);
        return 4;
    }

    file_log("entering binder thread pool (blocking)...");
    LOGI("entering binder thread pool...");
    join_pool(self, true);
    file_log("binder thread pool exited UNEXPECTEDLY");
    LOGE("binder thread pool exited unexpectedly");
    if (handle) dlclose(handle);
    return 5;
}
