#include <jni.h>
#include <stdio.h>
#include <android/log.h>

#define LOG_TAG "binder_pool"
#define LOGFILE "/data/local/tmp/netproxy.log"

static void file_log(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "binder_pool: %s\n", msg); fclose(f); }
}

namespace android {
class IPCThreadState {
public:
    static IPCThreadState* self();
    void joinThreadPool(bool clearCallingIdentity);
};
}

extern "C" {

JNIEXPORT jint JNICALL Java_com_flint_netstats_NetworkStatsProxy_nativeJoinThreadPool(
    JNIEnv* env, jclass clazz) {

    android::IPCThreadState* self = android::IPCThreadState::self();
    if (!self) {
        file_log("IPCThreadState::self returned NULL");
        return 4;
    }

    file_log("entering binder thread pool (linked at compile time)...");
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "entering binder thread pool via compile-time link...");
    self->joinThreadPool(true);
    file_log("binder thread pool exited UNEXPECTEDLY");
    return 5;
}

}
