// File events for File Shield's real-time watch (macOS FSEvents), behind a tiny C interface the
// Rust side calls (src/platform/macos/observe/file_watch.rs). Each change reaches
// `bb_fs_event(path, flags, context)` on a private dispatch queue: no run loop to drive.
#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>
#include <stdint.h>

extern void bb_fs_event(const char *path, uint32_t flags, void *context);

static void bb_fs_callback(ConstFSEventStreamRef stream, void *info, size_t count, void *paths,
                           const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
    (void)stream; (void)ids;
    char **names = (char **)paths;
    for (size_t i = 0; i < count; i++) bb_fs_event(names[i], (uint32_t)flags[i], info);
}

typedef struct { FSEventStreamRef stream; dispatch_queue_t queue; } bb_fs_watch;

// Starts watching *paths* (absolute); NULL when nothing could be watched.
void *bb_fs_watch_start(const char **paths, int count, double latency, void *context) {
    if (count <= 0) return NULL;
    CFMutableArrayRef list = CFArrayCreateMutable(NULL, count, &kCFTypeArrayCallBacks);
    for (int i = 0; i < count; i++) {
        CFStringRef path = CFStringCreateWithCString(NULL, paths[i], kCFStringEncodingUTF8);
        if (path) { CFArrayAppendValue(list, path); CFRelease(path); }
    }
    FSEventStreamContext ctx = {0, context, NULL, NULL, NULL};
    FSEventStreamRef stream = FSEventStreamCreate(NULL, bb_fs_callback, &ctx, list, kFSEventStreamEventIdSinceNow,
        latency, kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagWatchRoot);
    CFRelease(list);
    if (!stream) return NULL;
    dispatch_queue_t queue = dispatch_queue_create("ai.umanitek.blackbox.file-watch", DISPATCH_QUEUE_SERIAL);
    FSEventStreamSetDispatchQueue(stream, queue);
    if (!FSEventStreamStart(stream)) {
        FSEventStreamInvalidate(stream); FSEventStreamRelease(stream); dispatch_release(queue);
        return NULL;
    }
    bb_fs_watch *watch = malloc(sizeof(bb_fs_watch));
    watch->stream = stream; watch->queue = queue;
    return watch;
}

// Stops a watch started above (no callback runs after this returns).
void bb_fs_watch_stop(void *handle) {
    if (!handle) return;
    bb_fs_watch *watch = (bb_fs_watch *)handle;
    FSEventStreamStop(watch->stream);
    FSEventStreamInvalidate(watch->stream);
    FSEventStreamRelease(watch->stream);
    dispatch_sync(watch->queue, ^{});   // drain: the last callback has finished
    dispatch_release(watch->queue);
    free(watch);
}
