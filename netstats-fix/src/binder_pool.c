#include <jni.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <android/log.h>

#define LOG_TAG "binder_pool"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

typedef void* (*ipc_self_t)();
typedef void  (*join_pool_t)(void*, bool);

JNIEXPORT void JNICALL Java_com_flint_netstats_NetworkStatsProxy_nativeJoinThreadPool(
    JNIEnv* env, jclass clazz) {

    void* handle = dlopen("libbinder.so", RTLD_LAZY);
    if (!handle) {
        LOGE("dlopen libbinder.so failed: %s", dlerror());
        return;
    }

    ipc_self_t ipc_self = (ipc_self_t)dlsym(handle, "_ZN7android14IPCThreadState4selfEv");
    if (!ipc_self) {
        LOGE("dlsym IPCThreadState::self failed: %s", dlerror());
        dlclose(handle);
        return;
    }

    join_pool_t join_pool = (join_pool_t)dlsym(handle, "_ZN7android14IPCThreadState14joinThreadPoolEb");
    if (!join_pool) {
        LOGE("dlsym IPCThreadState::joinThreadPool failed: %s", dlerror());
        dlclose(handle);
        return;
    }

    void* self = ipc_self();
    if (!self) {
        LOGE("IPCThreadState::self returned NULL");
        dlclose(handle);
        return;
    }

    LOGI("entering binder thread pool...");
    join_pool(self, true);
    LOGE("binder thread pool exited unexpectedly");
    dlclose(handle);
}
