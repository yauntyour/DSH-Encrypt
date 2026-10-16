# dsh-encrypt

> **DSH 凭证加密插件**(bundle 形态):一个文件(`$DSH_HOME/.credentials.yaml`)双形态存储——未设密码时是与官方 `dsh-credentials-local` 同版式的明文 YAML;设置密码后,同一文件原地替换为 **AES-256-GCM 密文文档**(Argon2id 派生密钥 + SHA3-256 完整性指纹)。浏览器只提交密码的 SHA3-256 摘要(前后端分离),模型请求按需临时解密、明文从不缓存;内置**解锁爆破锁定、凭证泄露检测与输出脱敏、发行代码完整性自校验**。插件实现凭证接缝的**引用半边与记录半边**(`resolve`/`describe`/`set`/`unset` + `readRecord`/`describeRecord`/`listRecords`/`modifyRecord`/`deleteRecord`),不为 dsh 版本设围栏。

| 项目     | 值                                                                                                                                                                                   |
| :------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 形态     | **bundle**(`dsh.bundle.patch` → `cordis.patch.yml`,随 profile 启动)                                                                                                                  |
| 版本     | `0.2.0`                                                                                                                                                                              |
| 兼容基线 | dsh 接缝包 `0.2.1-alpha.5` 线(cordis `4.0.5-alpha.2`、`dsh-credentials` 等,精确钉版;构建 + 测试基线)                                                                                 |
| 兼容策略 | **无版本围栏**:`src/compat.ts` 只识别启动它的 dsh 版本并记入日志;真正不兼容时在该接缝调用点明确报错。旧 `0.1.0-rc.x` 线可加载(记录半边为其新增能力);密文 v3 与旧扁平明文保持读取兼容 |
| 环境     | Node.js(跟随所运行的 dsh);本仓库以 `@types/node` 26 开发                                                                                                                             |
| License  | [MIT](./LICENSE)                                                                                                                                                                     |

## 特性

- **单文件双形态**:明文 YAML ↔ 密文 JSON 原地互转,不产生第二个文件、不迁移路径
- **完整凭证接缝(引用 + 记录)**:引用半边存 API Key/环境变量;记录半边供插件存取结构化凭证(如 WebUI 登录用的 `client-connection/browser-session`、账号平台的授权载荷),新旧两线消费方都工作
- **记录双封装(policy seal)**:`machine` 封装用状态文件中的安装密钥,启动期消费方(浏览器会话、账号平台)在锁定态照常读写;`password` 封装用保险库密钥,锁定期间不可读、不可改、无痕删除。封装一经建立不再改变,锁定期间新建的记录只能是 `machine`
- **AES-256-GCM**:每条凭证/记录独立随机 nonce,引用名/记录键绑定为 GCM AAD(换位即认证失败)
- **SHA3-256 损坏检测**:条目级指纹 + 覆盖文档头部(含 `records`)的文档级指纹,损坏文件启动即被拒绝(绝不当作“空库”);密文真实性由 AES-GCM 标签提供
- **Argon2id 密码派生**(m=64 MiB, t=3, p=1,OWASP 对齐):密码不落盘,仅存盐与 AEAD 验证器;旧版 scrypt(v2)密文仍可解锁并在解锁时自动升级
- **摘要校验(前后端分离)**:WebUI 用纯 JS Keccak-f[1600] 计算密码的 SHA3-256,只 POST `{ digest }` 到后端;原始密码不离开浏览器
- **解锁爆破锁定**:连续失败计数持久化(重启不清零),达阈值(默认 5 次)指数退避(30s 起、×2、上限 15min),HTTP 429 + `Retry-After`
- **凭证泄露检测与输出脱敏(Leak Guard)**:解析过的凭证值登记为掩码模式,WebUI 的 HTTP 响应体与 WebSocket 文本帧离开主机前替换为 `[REDACTED:dsh-encrypt]`(分块边界安全的流式脱敏)
- **发行文件一致性自校验**:构建时生成 `lib/integrity-manifest.json`(`lib/` 全部构建文件与 `cordis.patch.yml` 的 SHA3-256),启动逐文件校验,并拒绝清单遗漏、越界文件名和内容不一致;该清单用于发现安装损坏,不作为防恶意改包的信任根
- **免密登录滑块**:0 = 每次输密码 / 1–30 天 / 永远;解锁成功后签发 256 位票据,**默认仅 HttpOnly Cookie**(响应体不回传);页面加载、**标签页重新可见/聚焦**时自动重试解锁,服务重启后切回页面即可
- **仅本机密码操作**:解锁、设密、改密和免密设置都要求 Host 回环 **且** socket 回环;带代理转发头的请求不会被当成本机请求
- **永远密文(ciphertext-only)**:设密后文件永不回退明文;外部明文替换在解锁态被立即重加密、锁定/启动态被拒绝(`plaintextForbidden`)
- **阅后即焚**:密文只在被使用的时刻解密,中间 Buffer 立即清零,密钥在锁定/卸载时清零
- **按请求解密**:明文只存活于单次操作,不缓存、不进日志
- **热重载** + **原子写 + 文件锁**(POSIX 强制 0600)+ **自动化解锁**(`DSH_CREDENTIAL_PASSWORD`)
- **事件新旧双发 + 解锁重宣告**:引用变更同时发 `credentials/reference-updated`(当前线)与 `credentials/updated`(旧线);记录变更发 `credentials/record-updated`;解锁后重新宣告全部 `password` 封装记录,让锁定期间读到空的消费方刷新
- **明文版式化**:明文形态采用与官方 `credentials-local` 一致的布局(`version: 1` + `refs` + `records`);旧扁平布局读取兼容,首次写入自动迁移并保留注释;未知顶层键保留并告警,不做静默丢弃
- **运行时识别(非围栏)**:启动时读取 dsh 版本并记日志(`dsh-encrypt: running on dsh …`),不阻断加载

## 形态与架构

实现代码采用领域、应用、基础设施、传输、安全和客户端分层。`index.ts`、`vault.ts`、`web.ts`、`client.ts` 保留为兼容入口;磁盘结构与 HTTP 输入由 Valibot 校验,Cordis 静态配置继续使用宿主要求的 Schemastery。项目的字符语法和泄露匹配均使用显式解析,不使用正则表达式。完整边界与变更规则见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

bundle 形态由三个组合行构成:

| 组合行               | 入口                            | 注入                         | 职责                                                                             |
| :------------------- | :------------------------------ | :--------------------------- | :------------------------------------------------------------------------------- |
| `dsh-encrypt`        | `dsh-encrypt`(`lib/index.js`)   | —(`CredentialProvider` 服务) | 双形态存储:替换被禁用的基础 `credentials` 行,在同一 `ctx.credentials` 接缝上工作 |
| `dsh-encrypt-web`    | `dsh-encrypt/web`(`lib/web.js`) | `webServer`、`credentials`   | 浏览器密码路由(5 条 `/api/credentials.*`)+ 输出脱敏安装                          |
| `dsh-encrypt/client` | package.json 的 `dsh.client`    | `slots`                      | 「设置 → 加密安全」面板(web 组合自动挂载)                                        |

替换方式遵循 bundle 生态边界:不修改任何核心 row,只禁用基础 `credentials` 行并插入本插件行。LLM 适配器、Models 页、web-search 等既有消费者零改动(drop-in)。

## 安装

### 1. 打包并安装(bundle)

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm pack                      # prepack 自动重建 lib/integrity-manifest.json
dsh plugin --profile web add ./dsh-encrypt-0.2.0.tgz
dsh plugin --profile headless add ./dsh-encrypt-0.2.0.tgz   # 如需要 headless
```

`@node-rs/argon2` 为带预编译二进制的原生依赖,极少平台组合缺失时 `pnpm rebuild @node-rs/argon2` 即可。

**源码目录安装**:profile 的 `node_modules` 里建 junction 指向源码,源码改动即位于安装位置、重启生效,无需 `dsh plugin add`:

```sh
dsh plugin --profile web add "<仓库绝对路径>"
```

### 2. 挂载 Web 密码路由(仅 web profile)

bundle patch 只插入 provider 行;浏览器路由是独立组合行。在 `$DSH_HOME/profiles/web/cordis.patch.yml` 用户层追加:

```yaml
- insert:
    - id: dsh-encrypt-web
      name: 'dsh-encrypt/web'
      config:
        trustedHosts: [] # LAN/隧道部署时才需要,见下
```

LAN 部署(如经 frp 隧道远程访问)需把放行的权威来源写进 `trustedHosts`(与官方 `connection` 行同源取值)。注意 `!!js` 表达式引用 `ctx.webRuntime` 时必须加**行级 `inject: [webRuntime]`**,否则加载器抛 `cannot get property "webRuntime" without inject`:

```yaml
- insert:
    - id: dsh-encrypt-web
      name: 'dsh-encrypt/web'
      inject: [webRuntime]
      config:
        trustedHosts: !!js '[...ctx.webRuntime.trustedHosts, "app.internal.example"]'
```

### 3. 验证安装

```sh
dsh --profile web --dump-config | grep dsh-encrypt
# 期望:dsh-encrypt 与 dsh-encrypt-web 两个行在,基础 credentials 行被禁用
```

## 使用

全部人工操作在「设置 → 加密安全」完成(面板 id `encryption`);凭证**记录**由各插件自动读写(例如 WebUI 登录在首次使用时自动创建 `client-connection/browser-session` 记录),无需手动管理:

| 操作                           | 前置状态          | 效果                                                     |
| :----------------------------- | :---------------- | :------------------------------------------------------- |
| 设置加密密码(两次,至少 8 字符) | 明文              | 同一文件原地替换为密文文档,进程保持解锁                  |
| 解锁                           | 加密+锁定(重启后) | 校验密码摘要并派生密钥,恢复模型调用                      |
| 修改密码                       | 加密+解锁         | 需输入「当前密码」(旧口令证明),全部条目重加密,作废旧票据 |
| 免密登录时长(滑块)             | 任意              | 0 = 每次;1–30 天;-1 = 永远(均仅本机)                     |

状态机:

```text
             set-password                    (restart)            unlock
  plain ──────────────────► encrypted+unlocked ──────► encrypted+locked ──► unlocked
    ▲                            │  ▲                                        │
    └──── 外部明文替换(重加密/拒绝) ──┘  └──────────── change-password ───────────┘
```

- **锁定期间**:web 服务照常;继承环境凭证仍可解析,文件凭证抛 `VAULT_LOCKED`;`password` 封装记录读取为“不存在”、修改抛 `VAULT_LOCKED`;`machine` 封装记录照常读写;设置页即解锁入口
- **免密窗口**:票据签发时写入 `issuedAt` 与 `days`;滑块改动立即作废旧票据并(解锁态)按新时长重签;打开 WebUI 自动尝试免密解锁
- **忘记密码**:不可恢复(设计如此);删除 `.credentials.yaml` 后,设置页仍要求先建立新密码,随后才能重新配置凭证

## 凭证解析顺序

| 优先级 | 来源                                | 说明                                        |
| :----- | :---------------------------------- | :------------------------------------------ |
| 1      | 继承环境(launching environment)     | 只读、高于受管文件;对其遮蔽的引用写入被拒绝 |
| 2      | 受管文件 `.credentials.yaml`        | 明文或密文形态,可写                         |
| 3      | `.env` 回退(project-env / user-env) | 低于受管文件,仅在文件无此引用时兜底         |

`allowEnvFallback: false` 可关闭第 1、3 层(严格仅文件策略)。

## 磁盘格式

**明文形态**(未设密码;与官方 `dsh-credentials-local` 同版式的 YAML):

```yaml
version: 1
refs:
  OPENCODE_GO_API_KEY: sk-…
records: # 仅存在记录时有此段
  client-connection/browser-session:
    kind: grant
    payload: { … }
```

- 旧版扁平布局(引用 → 值直接在根上)读取兼容;首次写入自动迁移到上面的版式,注释与空行保留(YAML 可能归一化空格)
- 未知顶层键原样保留并可告警,不会因写入被丢弃
- 明文形态下记录就是明文——此时没有第二把锁,这是与官方实现一致的语义

**密文形态**(设密码后,同一文件内容被替换;`version` 3 = 无记录,4 = 含记录):

```json
{
  "format": "dsh-encrypt-credentials",
  "version": 4,
  "algorithm": "aes-256-gcm+sha3-256",
  "kdf": "argon2id",
  "kdfInput": "sha3-256-password",
  "m": 65536,
  "t": 3,
  "p": 1,
  "salt": "<base64url>",
  "verifier": { "data": "<base64url>", "sha3": "<hex>" },
  "remember": {
    "salt": "<base64url>",
    "issuedAt": 1755000000000,
    "days": 7,
    "cipher": { "data": "<base64url>", "sha3": "<hex>" }
  },
  "entries": { "OPENCODE_GO_API_KEY": { "data": "<base64url>", "sha3": "<hex>" } },
  "records": {
    "client-connection/browser-session": {
      "kind": "grant",
      "seal": "machine",
      "data": "<base64url>",
      "sha3": "<hex>"
    }
  },
  "sha3": "<document fingerprint>"
}
```

- 主密钥 = Argon2id(密码的 SHA3-256 摘要, salt, m/t/p);原始密码不进后端
- v2 scrypt 密文仍可解析与解锁,成功解锁时自动原地升级为 v3 Argon2id
- v3 ↔ v4 按需选择:无记录时写 v3(旧 rc.12 构建也能读取);一旦存在记录即写 v4
- `verifier` 是固定明文的 AEAD 密文,用于在不接触任何真实凭证的前提下校验摘要
- `remember` 块仅在签发过免密票据时存在:`cipher` 是票据密钥 AEAD 包裹的主密钥,版本、盐、签发时间和期限均绑定到 GCM 认证;票据本身只在浏览器 Cookie(HttpOnly),永不落盘;`days: -1` 表示永远
- `records` 每条为平铺条目:`kind` 是清晰标签(供锁定期间描述),`seal` 是封装类型,`data` 是 AEAD 密文(记录键绑定为 GCM AAD),`sha3` 是条目指纹
- 文档级指纹覆盖 `sha3` 以外全部字段(含 `records`);成本参数有上限(防恶意构造耗尽内存/CPU)
- 密码与票据从不落盘;`machine` 封装的安装密钥存于 `$DSH_HOME/.dsh-encrypt.json`(`recordsKey`),先落盘再写依赖它的密文

## HTTP 路由(web 行)

仅 `POST application/json`(与官方 /api 相同的跨站写护栏),全部路由在读取请求体前先过 **Host 头信任围栏**(防 DNS rebinding):Host 必须解析为回环主机名或命中 `trustedHosts`,否则 **403 `FORBIDDEN_HOST`**;解锁、改密、设密和免密设置进一步**限制为本机**(Host 回环 **且** socket 回环,不给 `trustedHosts` 例外)。请求体上限 4 KiB,读取时限 10 秒。响应 `{ ok: true, value }` 或 `{ ok: false, code, message }`,错误消息不含密码或任何密钥材料:

| 路径                               | 请求体                                                  | 作用                                                                                                                |
| :--------------------------------- | :------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------ |
| `/api/credentials.status`          | `{}`                                                    | 状态快照;本机且携带免密票据(Cookie;header 通道下也接受 `x-dsh-encrypt-remember`)时先尝试票据解锁                    |
| `/api/credentials.unlock`          | `{ digest }`                                            | 密码摘要解锁(**仅本机**);成功后再按滑块签发免密票据(HttpOnly Cookie;header 通道才随响应体回传票据);失败过多返回 429 |
| `/api/credentials.set-password`    | `{ digest }`                                            | 明文 → 密文(**仅本机**),写入密文策略标记                                                                            |
| `/api/credentials.change-password` | `{ oldDigest, digest }`                                 | 重加密(**已解锁 + 证明当前口令**,仅本机;作废旧票据并签发新票)                                                       |
| `/api/credentials.config`          | `{ action: "get" }` / `{ action: "set", rememberDays }` | 读取状态 / 设置免密天数(set 仅本机)                                                                                 |

`rememberChannel: "header"` 可显式切回响应体回传 + localStorage + 请求头通道(XSS 可读票据,仅用于 Cookie 存取异常的 WebView);默认 Cookie 通道下,响应体永不携带票据,旧 localStorage 副本自动清理作废。headless 组合不挂载 web 行,无 HTTP 面。

## 配置项

provider 行 `config`:

| 字段                                                   | 类型             | 默认值                        | 说明                                                                             |
| :----------------------------------------------------- | :--------------- | :---------------------------- | :------------------------------------------------------------------------------- |
| `path`                                                 | string           | `$DSH_HOME/.credentials.yaml` | 凭证文件绝对路径                                                                 |
| `dshHome`                                              | string           | 运行时注入                    | Harness home                                                                     |
| `allowEnvFallback`                                     | boolean          | `true`                        | 启用继承环境与 `.env` 回退层                                                     |
| `passwordEnv`                                          | string           | `DSH_CREDENTIAL_PASSWORD`     | 启动自动解锁的环境变量名                                                         |
| `watch` / `debounceMs`                                 | boolean / number | `true` / `100`                | 热重载与防抖                                                                     |
| `rememberDays`                                         | number           | `0`                           | 免密天数:-1 永远;0 每次;1–30 天(运行时值写入 `$DSH_HOME/.dsh-encrypt.json` 优先) |
| `rememberChannel`                                      | string           | `"cookie"`                    | 免密票据通道:cookie(默认)/ header(兼容通道)                                      |
| `leakGuard`                                            | boolean          | `true`                        | 凭证泄露检测与输出脱敏总开关                                                     |
| `leakMinMaskLength` / `leakMaxMaskLength`              | number           | `8` / `256`                   | 脱敏长度窗口(4–64 / 16–1024)                                                     |
| `maxUnlockAttempts` / `lockoutBaseMs` / `lockoutMaxMs` | number           | `5` / `30000` / `900000`      | 解锁爆破锁定阈值与指数退避参数                                                   |

web 行 `config`:

| 字段           | 类型     | 默认值 | 说明                                                                                 |
| :------------- | :------- | :----- | :----------------------------------------------------------------------------------- |
| `trustedHosts` | string[] | `[]`   | 除回环外只放行状态读取和配置读取的权威来源(host 或 host:port);该配置不会放行密码操作 |

## 安全模型

**保证**:

- 静态存储只含密文;内存快照在密文形态下只保存密文记录
- 每条目/记录随机 12 字节 nonce;引用名与记录键作为 GCM AAD,换位认证失败
- 双层 SHA3-256 指纹(文档级 + 条目级)+ GCM 认证标签:篡改且重算指纹仍以 `VAULT_KEY_MISMATCH` 失败(与错误主密钥不可区分——AEAD 的诚实答案)
- 密码经 Argon2id 派生,只存盐与 AEAD 验证器;文档成本参数有上限
- `password` 封装记录与引用同等保护:锁定期间密文不可解、修改被拒、读取为“不存在”(不做存在性侧信道以外的泄露)
- 阅后即焚 + 按请求解密 + 密钥锁定/卸载清零
- 永远密文:设密后无法回退明文
- POSIX 上凭证文件必须由当前用户拥有且权限为 0600,父目录不得由其他用户写入;读取拒绝符号链接和非普通文件
- 防爆破:失败计数持久化 + 指数退避 + 429/`Retry-After`;密码派生串行执行,待处理请求数量受限
- 防注入回显(Leak Guard):解析过的凭证在 HTTP 文本响应与 WS 文本消息离开主机前被替换为 `[REDACTED:dsh-encrypt]`;过滤器覆盖 HTTP 分块边界、运行中新增的凭证值和 WS continuation 分帧
- 防 DNS rebinding(Host 围栏)与防 LAN 伪造回环(Host+socket 双重判定)
- 改密需证明当前口令(`oldDigest`),且与解锁共用锁定计数(锁定窗口期间改密同样 429 拒绝)
- 发行文件一致性检查会拒绝缺失、多出、越界或哈希不一致的构建文件

**诚实边界**:

- `machine` 封装防的是「密文文件被单独拷走」的离线读取:其安装密钥与密文同在 `$DSH_HOME`,能同时读取两者的本地代码/攻击者可以直接解开这些记录——机密性保证来自 `password` 封装,`machine` 只是启动期可用性的取舍
- JS 字符串不可变,解密明文无法在内存中清零——给出的保证是**不持久化、不缓存、不进日志**,操作结束即丢弃引用
- 解锁期间主密钥必须驻留内存,请以操作系统账户 + 0600 文件保护
- 忘记密码不可恢复;唯一恢复手段是清除凭证文件后重新配置
- 完整性清单不是信任根:能改写插件目录的攻击者也能重新生成清单;真正的信任根是用户密码
- 锁定计数存于状态文件,同一 OS 用户可编辑重置——锁定防的是在线猜密码,防不了同账户自我解锁
- 脱敏只覆盖本插件已知的值;模型把密钥经工具调用(bash/web_search/网络)外传不属输出脱敏覆盖范围;拆分/转码可绕过子串匹配
- **服务端无法校验密码强度**:后端只见摘要,「至少 8 个字符」仅由 WebUI 前端强制;直连 API 可设置任意弱口令,摘要即口令,请自行保证强度
- 摘要即口令等价物:捕获一次即可解锁直到改密;密码操作只接受本机请求,`trustedHosts` 不会扩大该范围
- `rememberChannel: "header"` 的票据对页面脚本可读(XSS 可窃取);默认 Cookie 通道无此暴露面
- 锁定计数为全局:任何能到达解锁接口的客户端故意输错即可反向锁定合法用户(DoS),属在线猜口令防御的固有代价
- 仅本机操作的“本机”判定依赖 Host+socket:非浏览器进程仍可伪造两者,但那已是你本机可执行的任意代码等价物——护栏防的是浏览器/局域网,不是同主机恶意进程
- 锁定期间 `password` 记录的键名与 `kind` 标签仍以清晰文本存在(用于描述与列表);只有载荷是机密

## 错误码

| code                                                               | 含义                                                                      |
| :----------------------------------------------------------------- | :------------------------------------------------------------------------ |
| `PASSWORD_WRONG` / `PASSWORD_INVALID`                              | 摘要与验证器不匹配 / 摘要不是 64 位小写 hex                               |
| `LOCAL_ONLY`                                                       | 该操作(改密/设密/免密设置/票据签发)仅允许本机(Host+socket 回环)           |
| `FORBIDDEN_HOST`                                                   | Host 非受信来源(HTTP 403)                                                 |
| `REMEMBER_EXPIRED` / `REMEMBER_INVALID`                            | 免密票据超窗 / 与本凭证库不匹配                                           |
| `VAULT_LOCKED` / `VAULT_NOT_ENCRYPTED` / `VAULT_ALREADY_ENCRYPTED` | 锁定 / 未设密 / 已设密(`VAULT_LOCKED` 也用于锁定期间修改 `password` 记录) |
| `VAULT_CORRUPTED` / `VAULT_INVALID` / `VAULT_KEY_MISMATCH`         | 完整性校验失败 / 结构非法 / 主密钥不匹配或密文被替换                      |
| `TOO_MANY_ATTEMPTS`                                                | 解锁失败过多,进入锁定窗口(HTTP 429 + `Retry-After`)                       |
| `INTEGRITY_FAILED`                                                 | 发行代码完整性校验失败(拒绝加载;合法重建后 `pnpm build`)                  |

## 卸载与回滚

密文策略下没有「移除密码」路径,文件永为密文;基础 `credentials` 行读不懂密文文档,因此卸载前**先备份并删除凭证文件**(或接受重新录入):

1. 备份/删除 `$DSH_HOME/.credentials.yaml` 与 `.dsh-encrypt.json`;
2. 删除 `$DSH_HOME/profiles/web/cordis.patch.yml` 中的 `dsh-encrypt-web` insert;
3. `dsh plugin --profile web remove dsh-encrypt`(headless 同理)。

基础 `credentials` 行随 bundle 移除自动恢复启用。源码 junction 安装时,「移除」= 移除 junction + 删除 package.json 里的 `link:` 依赖。

## 开发与测试

```sh
corepack enable
pnpm install --frozen-lockfile # 自包含依赖树;接缝包精确钉版
pnpm check                 # 格式、lint、TypeScript、Vitest、Knip 全量检查
pnpm test                  # Vitest 回归测试;pretest 自动执行 tsdown 构建与完整性清单
pnpm build                 # 构建并自动重建 lib/integrity-manifest.json
pnpm pack                  # prepack 自动重建清单后打包
```

源码使用 TypeScript 7,由 tsdown 生成 ESM、类型声明和 source map;格式化与 lint 配置来自 `@mzwing/oxc-config`。

安全测试覆盖记录封装与锁定语义(`machine` 可读、`password` 拒绝、解锁重宣告、状态文件丢键恢复)、明文版式迁移与未知字段保留、v4 文档指纹与记录条目校验、引用事件新旧双发、密码解锁与并发锁定、密文文件缺失、登录票据期限认证、文件符号链接、请求结构校验、字面量最长匹配、HTTP 分块过滤、WebSocket continuation 分帧、完整性清单覆盖和浏览器 SHA3。

浏览器包 ModuleLoader/SSR 冒烟已包含在 Vitest 套件中。测试套件仅本地回归用,不随 npm 包分发(`files` 仅含 `lib` 与 `cordis.patch.yml`)。

## 版本历史(简)

- **0.1.0-rc.6 → rc.8**:KDF 输入改为密码摘要;永久密文策略;免密票据通道;阅后即焚
- **rc.9 → rc.12**:scrypt → Argon2id(v3);解锁爆破锁定;泄露检测与输出脱敏;完整性自校验;Host 头信任围栏;改密证明当前口令;请求体上限
- **0.2.0**:对接接缝记录半边(`readRecord`/`describeRecord`/`listRecords`/`modifyRecord`/`deleteRecord`);`machine`/`password` 双封装与 v4 文档(无记录仍写 v3);明文版式化为 `version: 1` + `refs` + `records`(旧扁平布局读取兼容、写入迁移);记录事件与解锁重宣告;引用事件新旧双发;移除运行时版本围栏(仅探测记录)。接缝包钉版升级到 `0.2.1-alpha.5` 线

## 许可证

[MIT](./LICENSE) · © 2026 Yauntyours
