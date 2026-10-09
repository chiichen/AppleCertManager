# AppleCertManager

用一条命令管理 Apple 签名证书和描述文件。仓库布局、加密格式和 `sigh_*` 环境变量与 fastlane match 兼容，实现是 Rust 命令 `apple-cert-manager`。

`apple-cert-manager sync` 会读取证书仓库里的 `devices.txt`，在 App Store Connect 上登记设备、创建 Bundle ID、证书和描述文件，把它们加密后写入存储，再生成 Xcode 可以直接使用的签名文件。在 macOS 上，同一条命令通过 Security.framework 把证书导入钥匙串，并把描述文件装进 Xcode。

## 准备

```bash
cargo build --release
export MATCH_PASSWORD='仓库加密口令'
```

口令只从 `MATCH_PASSWORD` 读取，不会写入 `acm.toml`。Apple 侧只使用 App Store Connect API Key（`.p8`），不使用 Apple ID 密码。

```bash
apple-cert-manager init
```

这会在当前目录生成 `acm.toml`，并在证书仓库里写入 `devices.txt`。示例配置的证书仓库是本地目录 `./certs`，所以设备文件在 `./certs/devices.txt`。按团队信息改 `acm.toml`，把设备按下面的格式写进证书仓库里的 `devices.txt`（制表符、逗号或空白都可以，表头可省略）：

```text
Device ID	Device Name	Device Platform
00008030-001C25E40A68802E	前台 iPhone	ios
```

API Key 也可以用环境变量，不放进配置文件：

- `APP_STORE_CONNECT_API_KEY_KEY_ID` 或 `ASC_KEY_ID`
- `APP_STORE_CONNECT_API_KEY_ISSUER_ID` 或 `ASC_ISSUER_ID`
- `APP_STORE_CONNECT_API_KEY_PATH` 或 `ASC_KEY_PATH`
- `APP_STORE_CONNECT_API_KEY_KEY`（PEM 正文，换行写成 `\n`）
- `FASTLANE_TEAM_ID` 或 `ACM_TEAM_ID`

## 同步

```bash
apple-cert-manager doctor
apple-cert-manager sync
```

`apple-cert-manager sync` 会：

1. 读取证书仓库里的 `devices.txt`，把还没有的设备登记到开发者门户。文件和 `certs/`、`profiles/` 放在同一套 local、git 或 s3 存储里，以明文保存。
2. 创建缺少的 Bundle ID、证书和描述文件。Ad Hoc 与 App Store 共用 `certs/distribution` 里的发布证书。
3. 用 match v2（`match_encrypted_v2__`，AES-256-GCM）加密后写入存储。已有的 match v1 `Salted__` 文件仍能解密。
4. 在 `signing/` 下写出 `signing.env`、每个 lane 的 `Signing.xcconfig` 和 `ExportOptions.plist`。
5. 在 macOS 上把描述文件复制到 Xcode 的 Provisioning Profiles 目录，并用 Security.framework 导入 `.p12`。导入后会给签名私钥写上 `apple-tool:`、`apple:`、`codesign:` 分区，避免 codesign 弹出口令框。分区列表用的是和 `security set-key-partition-list` 相同的 Security.framework 调用。钥匙串口令放在 `MATCH_KEYCHAIN_PASSWORD`。

其他系统会写出同样的签名文件，并跳过钥匙串。`signing.env` 里的 `sigh_*` 变量和 fastlane sigh 一致，可以直接 `source`。

只拉取、不创建：

```bash
apple-cert-manager sync --readonly
```

## 存储

`storage_mode` 取 `local`、`git` 或 `s3`。

- 本地目录：`[local] path`
- Git：系统自带的 `git`，`[git] url` 和 `branch`。也认 `MATCH_GIT_URL`、`MATCH_GIT_BRANCH`
- S3 / MinIO：`[s3] bucket`、`region`、`endpoint`。设置了 `endpoint` 时默认 path-style。访问密钥默认读 `AWS_ACCESS_KEY_ID` 和 `AWS_SECRET_ACCESS_KEY`

仓库里的路径与 match 相同，例如 `certs/development/<id>.cer`、`certs/distribution/<id>.p12`、`profiles/development/Development_<bundle id>.mobileprovision`。

## 其他命令

```bash
apple-cert-manager import --type development ./cert.cer ./cert.p12 ./Development_com.example.app.mobileprovision
apple-cert-manager nuke --type development --yes
apple-cert-manager change-password          # 新口令放在 MATCH_PASSWORD_NEW
apple-cert-manager migrate --dest other.toml
apple-cert-manager encrypt ./certs
apple-cert-manager decrypt ./certs
```

`nuke` 会删除该 lane 的证书目录和描述文件，并在 Apple 上吊销对应证书。Ad Hoc 和 App Store 共用发布证书，吊销其中任意一个都会删掉这份发布证书。Developer ID 不能用 API Key 创建，用 `apple-cert-manager import` 放进仓库。

`--legacy` 让新写入的文件使用 match v1 加密。

## 开发

仓库是 Cargo workspace。各模块是独立的库 crate，命令行 crate 是 `apple-cert-manager`，二进制名也是 `apple-cert-manager`。

```text
crates/apple-cert-manager-error      统一错误类型
crates/apple-cert-manager-types      签名类型、平台、match 路径和 sigh 名称
crates/apple-cert-manager-crypto     match v1/v2 加解密和证书检查
crates/apple-cert-manager-devices    devices.txt 解析
crates/apple-cert-manager-config     acm.toml 和环境变量
crates/apple-cert-manager-storage    本地、Git、S3 存储
crates/apple-cert-manager-portal     App Store Connect API
crates/apple-cert-manager-engine     sync、nuke、import、migrate、改口令
crates/apple-cert-manager-signing    signing.env、xcconfig、ExportOptions
crates/apple-cert-manager-install    描述文件安装和 macOS 钥匙串
crates/apple-cert-manager          命令行，组合上面的库
```

```bash
cargo test --workspace
cargo build --workspace --release
```

需要 Rust 1.88 或更新版本。OpenSSL 随依赖从源码编译，互操作测试还会调用系统里的 `openssl` 命令。macOS 钥匙串代码只在目标系统是 macOS 时编译。发布二进制在 `target/release/apple-cert-manager`。

CI 在 Linux、macOS 和 Windows 上分别编译并测试各自的本机目标。
