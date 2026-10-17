# dsh-encrypt 架构

本项目使用分层模块承载加密凭证生命周期，并保留 `src/index.ts`、`src/vault.ts`、`src/web.ts`、`src/client.ts` 作为兼容入口。兼容入口负责组合与导出，不再承载可复用的底层规则。

## 模块边界

| 层       | 目录                 | 职责                                                   | 允许依赖                  |
| :------- | :------------------- | :----------------------------------------------------- | :------------------------ |
| 领域     | `src/domain`         | 常量、稳定错误码、文档和 Provider 类型、Valibot schema | `src/shared`、Valibot     |
| 应用     | `src/application`    | 密码转换、记住登录、串行操作、状态视图策略             | 领域层、基础设施端口实现  |
| 基础设施 | `src/infrastructure` | Node 密码学、磁盘文档、权限、运行时配置                | 领域层、共享校验          |
| 传输     | `src/transport`      | HTTP 结构类型、请求 schema、限量读取和边界错误         | 领域层、共享校验、Valibot |
| 安全     | `src/security`       | 字面量泄露匹配、HTTP 与 WebSocket 脱敏                 | LeakGuard 的窄接口        |
| 客户端   | `src/client`         | 浏览器 SHA3、API、票据存储、界面状态映射               | 浏览器标准 API            |
| 共享     | `src/shared`         | 无状态、无平台依赖的字符文本校验与纯 JS Keccak         | 无项目内依赖              |

依赖方向以领域类型为中心。密码学模块不读取文件，文档模块不处理 HTTP，HTTP schema 不调用 Provider，客户端不导入 Node API。

## 与 dsh 的接缝

插件继承运行时提供的 `CredentialProvider` 抽象类，并实现凭证接缝的全部方法：引用半边(`resolve`/`describe`/`set`/`unset`)与记录半边(`readRecord`/`describeRecord`/`listRecords`/`modifyRecord`/`deleteRecord`)。插件不锁定 dsh 版本：`src/compat.ts` 只识别启动它的 dsh 版本并记入日志，实际不兼容时在对应的接缝调用点明确报错。

引用变更发 `credentials/reference-updated`(当前线)并同时发 `credentials/updated`(旧线监听)事件；记录变更发 `credentials/record-updated`。解锁后，所有 `password` 封装的记录重新宣告一次，让锁定期间读到空的消费方刷新。

锁定期间引用半边的 `describe` 仍对已存在的引用返回 `configured: true`、`source: "locked"`、`writable: false`：条目名本就以明文存在于文档中，而只问“是否已配置”的启动期消费方(桌面欢迎页的 API key 探测、provider 目录)若把锁定库当成空库，就会把用户重新送进引导流程；实际取值仍由 `resolve` 抛 `VAULT_LOCKED`。

## 浏览器票据通道

免密票据默认走 HttpOnly Cookie。dsh 桌面壳把 WebUI 挂在 `dsh-app:` 自定义 scheme 下：它用外壳自己的 Host 认证 Cookie 替换每个请求的 `Cookie`，并从响应中扣留 `Set-Cookie`，因此 HttpOnly 票据在桌面版既存不下也发不出。客户端检测到页面不是 http(s) 时自动改走 header 通道：票据存 localStorage，并在每个请求上带 `x-dsh-encrypt-remember-channel: header` 与 `x-dsh-encrypt-remember`；web 层按请求协商通道(配置的 `rememberChannel` 仍是全局默认，可强制 header)，只在选择 header 通道时把新签发的票据放进响应体，客户端据此持久化。自动解锁在页面加载、连接代际重建、可见/聚焦时触发，Host 未就绪或暂时不可达时按退避重试。

## Vault 组合

`src/vault.ts` 维持原有包导出。实际实现由以下模块组成：

1. `domain/vault/model.ts` 定义文档常量、类型和 `VaultError`。
2. `domain/vault/schemas.ts` 用 Valibot 校验持久化文档(含 v4 `records` 段)。
3. `domain/vault/records.ts` 校验凭证记录载荷(api-key / grant)，规则与凭证接缝一致且不回显任何值。
4. `infrastructure/crypto/sha3.ts` 提供 SHA3-256：优先 `node:crypto`，Electron(BoringSSL 无 `sha3-256`)回退到 `shared/crypto/keccak.ts` 的纯 JS 实现，两条路径输出一致。
5. `infrastructure/crypto/vault-crypto.ts` 处理 Argon2id、scrypt、AES-GCM 和密钥清零。
6. `infrastructure/persistence/vault-document.ts` 处理规范化序列化、结构校验、文档指纹和记录密文。
7. `infrastructure/persistence/plain-credential-document.ts` 处理明文 YAML 的版式布局、扁平布局迁移与未知字段报告。
8. `application/password-service.ts` 处理设密、解锁和密码证明。
9. `application/remember-service.ts` 处理票据签发、有效期和主密钥恢复。

每个模块都可以通过内存输入单独测试。磁盘文档格式、公开函数名和稳定错误码由兼容入口保持。

## 记录封装与锁定语义

记录以两种封装存于密文文档的 `records` 段(v4 起；无记录时仍写 v3 以便回退)：

- `password`：用保险库密钥封装，逻辑与引用密文一致。
- `machine`：用运行时状态文件中的安装密钥(`recordsKey`)封装，锁定期间照常可读——本地浏览器会话等必须在 WebUI 解锁前工作的启动期消费方无需密码。其余记录(如账号平台授权)默认仍是 `password` 封装：它们在锁定期间读取为“不存在”，解锁(含免密票据解锁)后由 `credentials/record-updated` 重宣告刷新。

已有记录的封装不再改变；锁定期间新建的记录只能是 `machine`。锁定语义：`readRecord` 对 `password` 封装返回 `undefined`(启动路径安全)，`describeRecord` 标记 `writable: false`，`modifyRecord` 对已存在的 `password` 记录抛 `VAULT_LOCKED`，删除与 `machine` 写入无需解锁。安装密钥必须先写入状态文件，再写入依赖它的密文；状态文件丢键时，无法解读的 `machine` 密文按错误记录并丢弃，下次写入重新生成。

## 校验策略

项目使用两类校验：

- Valibot 校验 JSON、状态文件和 HTTP 请求等不可信结构。
- 显式字符扫描校验十六进制、凭证引用和版本文本。

项目不使用正则表达式。泄露检测使用不可变字面量 trie，并按“最早位置、最长值、互不重叠”选择匹配项。该实现不会把凭证内容拼进动态正则，也不会受到正则特殊字符影响。

`@deepseek-ai/schemastery` 只保留在 Cordis 的静态插件配置边界，因为该边界由宿主框架读取。业务输入和磁盘输入统一由 Valibot 校验。

## 并发与状态

`OperationQueue` 为文件修改提供失败隔离的串行顺序。Provider 的任务失败不会污染队列尾部，后续任务仍可运行。密码解锁入口限制待处理请求数量，已接收的请求再进入同一串行队列执行状态变更。

`src/web.ts` 只组合路由、访问检查和应用操作。共享 HTTP 结构及限量请求读取位于传输层；HTTP 与 WebSocket 输出脱敏位于安全层。

运行时状态文件按字段独立校验。一个损坏字段不会抹掉同文件内其他有效字段。Provider 只把加密记录保存在长期快照中；明文只存在于一次解析或回调期间。状态文件还保存安装密钥(`recordsKey`)：它不参与锁定状态，只用于 `machine` 记录，失败校验不会影响其他字段。

## 变更规则

- 新磁盘字段必须先加入领域类型和 Valibot schema，再加入规范化指纹字段顺序。
- 新 HTTP 操作必须先定义精确请求 schema，禁止使用字符串强制转换接受错误类型。
- 新密码学能力必须留在 `infrastructure/crypto`，并通过领域类型返回结果。
- 新输出通道必须复用安全模块的字面量脱敏器，或明确记录无法扫描的二进制边界。
- 兼容入口的导出变更必须配套声明构建和回归测试。
