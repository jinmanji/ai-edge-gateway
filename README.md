# AI Edge Gateway

面向 OpenAI、Anthropic 和 Gemini 官方 API 的 Rust 流式反向代理。下游支持 HTTP/1.1、HTTP/2 和 HTTP/3；上游默认用 TLS ALPN 首选 H2，兼容 H1，按路由/账号选择是否优先 H3。没有任意 URL 转发、数据库、请求重放队列、压缩中间件或 OpenSSL 运行时依赖。

## 快速开始

### Linux / Alpine：一行下载并启动

适用 **x86_64 / ARM64 Linux**。需要 `curl`、`tar`、`awk` 和 `sha256sum`，不需要 Rust、sudo 或 Docker。复制整行运行：

```sh
s=$(curl -fsS -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/jinmanji/ai-edge-gateway/contents/scripts/quick-start.sh?ref=main') && sh -c "$s"
```

[启动脚本](scripts/quick-start.sh)自动选择对应架构的全静态 [v0.1.0](https://github.com/jinmanji/ai-edge-gateway/releases/tag/v0.1.0) 产物，校验 `SHA256SUMS` 后安装到 `${XDG_DATA_HOME:-$HOME/.local/share}/ai-edge-gateway`（可用环境变量 `AIEG_HOME` 改位置）。首次启动生成 `config.toml`，以后不会覆盖；启动前先校验配置。默认以前台方式运行，按 `Ctrl+C` 停止。

### 原生 Termux：一行构建并启动

首次使用先安装工具链：`pkg install git rust clang cmake make pkg-config curl`。如项目尚未克隆，下面的命令会先克隆，再构建并启动；已有 `config.toml` 不会被覆盖：

```sh
(cd "$HOME" && { [ -d ai-edge-gateway ] || git clone https://github.com/jinmanji/ai-edge-gateway.git; } && cd ai-edge-gateway && cargo build --locked --release && { [ -e config.toml ] || (umask 077; set -C; cat config.example.toml > config.toml); } && ./target/release/ai-edge-gateway --config config.toml --check && exec ./target/release/ai-edge-gateway --config config.toml)
```

首次构建 AWS-LC 和 fat LTO 较慢；内存紧张时可在 `cargo build` 后加 `-j 1`。Termux 使用本机编译的 Android 二进制，不使用 Linux Release 安装包。

### 验证并发送第一个请求

另开一个终端检查就绪状态，**不需要 API Key**：

```sh
curl -fsS http://127.0.0.1:9080/healthz
```

默认代理监听 `127.0.0.1:8080`，管理端口 `127.0.0.1:9080` 另提供 `/metrics`。默认是 BYOK。以 OpenAI 为例，先通过安全渠道提供 `OPENAI_API_KEY`，再请求模型列表（不要开启 shell 或 curl 的详细请求跟踪）：

```sh
printf 'header = "Authorization: Bearer %s"\n' "$OPENAI_API_KEY" |
  curl --config - -fsS http://127.0.0.1:8080/openai/v1/models
```

SDK 的 Base URL 可设为 `http://127.0.0.1:8080/openai/v1`、`http://127.0.0.1:8080/claude` 或 `http://127.0.0.1:8080/gemini`，按 SDK 是否自行添加版本路径调整。不要在不可信网络上暴露明文端口。明文 H2 使用 prior knowledge（如 `curl --http2-prior-knowledge`）；启用 `[tls]` 和 `listen.h3 = true` 时，需开放同一端口的 **TCP 和 UDP**。如果做了端口映射，还需确保外部 `Alt-Svc` 中的端口正确。

### 编译选项

| 用途 | 构建命令 | 产物目录 |
|---|---|---|
| 通用发布（同目标平台） | `cargo build --locked --release` | `target/release/` |
| 在部署机上本机优化 | `cargo build-native` | `target/release-native/` |
| 优先缩小体积 | `cargo build --locked --profile release-min` | `target/release-min/` |

- `release` 保留 `opt-level = 3`、fat LTO、单 codegen unit、panic abort 和剥符号；release 系列在编译期裁掉 `DEBUG`/`TRACE`，仍保留 `INFO`/`WARN`/`ERROR` 启停和重载日志。
- `cargo build-native` 通过 `.cargo/config.toml` 给 Rust 编译单元及其依赖传入 `-C target-cpu=native`，允许用构建机的原生 CPU 指令和调度优化，不会覆盖通用版产物。请在实际部署机上构建，不用于交叉编译或分发到不同 CPU。构建前如环境另设了 `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` 或 target 专用 `rustflags`，请清除冲突配置；它们可能覆盖别名的 `build.rustflags`。单独指定 `--profile release-native` 不会自动传入 CPU 参数。收益主要取决于 CPU 热路径和真实负载，不保证降低网络等待时间。
- `release-min` 的 `opt-level = "z"` 以体积而非吞吐为目标。
- `--no-default-features --features websocket`：改用系统分配器。`--no-default-features` 同时移除 WS；此时模板中的 `websocket` 必须改为 `false`。
- `--features quiet` 编译期关闭全部 tracing；`AIEG_LOG=off` 运行期关闭。进程默认使用至多两个 Tokio worker，可调 `--workers N`。
- AWS-LC 和 Rust crate 会静态进入二进制；Termux 产物仍链接 Android 的系统 libc 等，不是跨发行版可用的全静态 ELF。需要全静态 Linux 时，用适配目标架构的 musl C 工具链构建，例如 `--target aarch64-unknown-linux-musl`，并用 `readelf -d` 核实实际链接结果。

## GitHub Release 安装包

[Releases](https://github.com/jinmanji/ai-edge-gateway/releases) 提供四种通用 Linux 二进制。用 `uname -m` 确认 CPU 架构：

| 系统 | CPU | 下载包 |
|---|---|---|
| Alpine / musl Linux | x86_64 | `ai-edge-gateway-x86_64-unknown-linux-musl.tar.gz` |
| Alpine / musl Linux | ARM64 (`aarch64`) | `ai-edge-gateway-aarch64-unknown-linux-musl.tar.gz` |
| glibc 2.35+ Linux（如 Ubuntu 22.04+、Debian 12+） | x86_64 | `ai-edge-gateway-x86_64-unknown-linux-gnu.tar.gz` |
| glibc 2.35+ Linux | ARM64 (`aarch64`) | `ai-edge-gateway-aarch64-unknown-linux-gnu.tar.gz` |

musl 两包为全静态 ELF，不需要额外安装 glibc 兼容层或 OpenSSL。四种包都不使用 `target-cpu=native`。Android/Termux 仍按上文在设备上单独编译，不要把 Linux glibc 包当 Android 原生包使用。

在下载 `SHA256SUMS` 和所需的包后，可只校验已下载的包。例如在 x86_64 Alpine：

```sh
package=ai-edge-gateway-x86_64-unknown-linux-musl
awk -v f="${package}.tar.gz" '$2 == f { print }' SHA256SUMS | sha256sum -c -
tar -xzf "${package}.tar.gz"
cd "$package"
./ai-edge-gateway --config config.example.toml --check
```

### 维护者发布流程

- 推送到 `main` 或在 [Actions](https://github.com/jinmanji/ai-edge-gateway/actions) 手动运行 **Release binaries**：只构建、测试并保存工作流 artifacts，不创建 Release。
- 推荐先更新版本并提交，然后推送 `v` 开头的版本 tag。四个构建全部通过后，工作流创建草稿、上传四个 `.tar.gz` 与 `SHA256SUMS`、再发布草稿。这个顺序兼容不可变 Releases，不要求本机登录 `gh`。

  ```sh
  git tag -a v0.1.0 -m 'Release v0.1.0'
  git push origin refs/tags/v0.1.0
  ```

- 直接在网页发布 Release 也会触发构建并补齐附件；若启用了**不可变 Releases**，请使用上面的 tag 发布方式，因为附件不能在 Release 公布后添加。工作流从触发事件的 commit 编译，而不是从最新的 `main` 取代码。

## 路由和认证

| 前缀 | 固定 HTTPS 上游 | BYOK 或 Managed 下游可提交的认证形式 |
|---|---|---|
| `/openai/` | `api.openai.com` | `Authorization: Bearer …` |
| `/claude/` | `api.anthropic.com` | `x-api-key`，完整保留 `anthropic-version` / `anthropic-beta` |
| `/gemini/` | `generativelanguage.googleapis.com` | `x-goog-api-key`、精确的 `?key=`，或 `/v1beta/openai/…` 上的 Bearer |

没有端点白名单，转发剥前缀后的路径；Host 路由可直接转发完整路径，两者冲突返回 421。不会跟随重定向或把 `Location`/响应体中的绝对 URL 改写成网关 URL。遇到厂商返回的续传、文件上传或其他绝对地址，SDK 若要继续通过网关，应显式使用该厂商的网关 URL。

- **BYOK**：不保存原始官方 Key；按 `(provider, egress, SHA-256 指纹)` 建立有界隔离域。按 TTL 清理过期空闲域；达到容量时淘汰最久未使用的空闲域，只有池都在用时才因容量返回 503，不借用其他账号连接。`allow_wildcard` 仅供 BYOK 不固定 IP 的场景使用。
- **Managed**：设置全局或指定 provider 的 `mode = "managed"`。`users.<name>.grants.<provider>` 将高熵 UserKey 映射到 `upstreams.<name>`，再绑定到固定出口。可以沿用厂商认证字段，也可用 `x-gateway-key`；后者在 Gemini 兼容路径生成 Bearer、在 H1 Live WebSocket 使用 Query，其他 Gemini HTTP 端点生成 `x-goog-api-key`。认证形态重复或冲突则拒绝；不会在 Managed 失败后回落到 BYOK。不同 provider 可以同时使用不同模式。
- **范围**：`path_prefixes` 和 `methods` 省略或为空表示不限。前缀匹配有分段边界，例如 `/v1/models` 不允许 `/v1/models-extra`。设置路径范围时拒绝 `%`、点路径段、反斜线等有规范化歧义的写法。N 个 UserKey 可共享同一个官方 Key/出口；不同官方 Key 即使同出口也不会共享连接。UserKey 只保存摘要并对全部槽做固定长度恒定时间比较；每次比较不因命中的槽提前中止。
- **Gemini Query**：只识别 URL 解码后大小写精确的 `key` 字段，拒绝重复；原位替换 Managed Key，其他参数的顺序、编码、空项和 `alt=sse` 保持原样。
- **WebSocket**：保留 H1.1 升级协商头和子协议，验证 101 的 `Sec-WebSocket-Accept`，用相同认证/出口规则再做双向字节透传。不解析、注入或缓存 WS 帧。H2/H3 Extended CONNECT 不开放。

Host、连接指定的 hop-by-hop 字段、转发地址头和上游 `Alt-Svc` 不会被信任。网关不打印请求地址、Query、认证头或库的 HTTP debug。`zeroize` 覆盖自管密钥和部分临时缓冲，但不是整进程擦除承诺，协议栈、环境变量、TLS/HTTP 序列化以及 URI 的内存无法都保证擦除。上线请禁用 core dump，保护配置、私钥和进程 UID，审计前置代理日志。运行时不主动采集响应内容；上游和客户端仍可能记录其自身处理的请求。

## 多出口 IP（Linux）

出口配置不会凭空分配地址，也不会绕过路由。`v4_only` 仅查询 A，`v6_only` 仅查询 AAAA；双栈并发解析，根据优先策略交错尝试，默认优先 IPv6，IPv4 地址先返回时最多等 50ms；按 250ms 间隔发起备选连接，硬失败则更早尝试下一地址。TCP/TLS 和 QUIC 都按目标族选择绑定的源地址；DNS 解析器的**网络传输**走独立系统 DNS 路由（只查 A 不等于要求 DNS 服务器必须是 IPv4）。DNS 命中使用 Hickory 的 TTL 缓存。

以下为文档地址，部署前替换地址、网关和网卡名。公网 IP/NAT 规则需要由云厂商或网络管理员配置；先用 `ip route get ... from ...` 验证策略路由：

```sh
sudo ip addr add 192.0.2.21/24 dev eth0
sudo ip route replace 192.0.2.0/24 dev eth0 src 192.0.2.21 table 121
sudo ip route replace default via 192.0.2.1 dev eth0 table 121
sudo ip rule add priority 121 from 192.0.2.21/32 lookup 121
ip route get 203.0.113.20 from 192.0.2.21

sudo ip -6 addr add 2001:db8:2::21/64 dev eth0
sudo ip -6 route replace 2001:db8:2::/64 dev eth0 table 122
sudo ip -6 route replace default via fe80::1 dev eth0 table 122
sudo ip -6 rule add priority 122 from 2001:db8:2::21/128 lookup 122
ip -6 route get 2001:db8:3::20 from 2001:db8:2::21
```

把绑定值写入 `egress` 表并执行 `--check`。TCP 明确设置 NODELAY/Keepalive/ReuseAddr；QUIC 用隔离的 UDP sockets，每个隔离域的每个启用地址族一个 Endpoint。启用了上游 H3 时同时验证 UDP bind。`interface` 可能受 Linux capabilities/Android SELinux 限制；只在确有需要时开启。`freebind` 允许预绑定，不代表地址上线或可达。Android 上普通 app 通常不能改接口/路由，请使用宿主已分配的地址或外部受控出口；VM/LXC 也要检查其网络命名空间。

## 并发、超时与协议行为

- `config/` 读取严校验的 TOML，`net/` 管 DNS、Socket 和 TLS，`pool/` 管 H1/H2/H3 和 BYOK 隔离域，`proxy/` 路由/认证/流式适配，`server/` 监听和 drain。`ArcSwap`发布整个快照；普通连接池命中不走配置锁。BYOK 缓存满或新建时有短暂异步写序列化，H3 初次探测同域合并。
- HTTP 数据以受流量控制的 frame/`Bytes` 推进，不读取完整上传或完整 SSE、不做二次压缩。正常流经过协议和 TLS 自身的有限缓冲，而不是内核到内核零拷贝。一旦下游流被关闭，drop 上游响应和未完成的上传；H2 发 RST_STREAM，H3 发 STOP_SENDING/RESET_STREAM，H1 关闭尚有未读响应的连接。SSE 添加 `X-Accel-Buffering: no`；前置代理也应显式关闭缓冲。
- DNS/连接/握手期限、首部期限、流分片 idle 期限独立。活跃上传不消耗后续模型响应头预算；无 body 的请求从派发开始计算头部预算。流已提交响应头后，idle 超时只能结束/重置流，不能再写 504。没有短总超时截断正常长流；取消只能尽快通知上游，无法撤回已执行的推理或保证撤销计费。
- 下游 H2（包括 h2c）只有在所有流结束后才开始计算 `listen.idle_connection_timeout_secs`（默认 90s），超时发送 GOAWAY 并释放连接名额。连接 PING 不算请求活动；活跃的 SSE/上传不受此空闲回收影响。
- 确认只含 HEADERS/FIN 的 H3 请求按空 body 转发；`Content-Length: 0` 仍检查 DATA/FIN，不把非法数据丢弃后当作空请求。无长度且暂未读到 FIN 时保持流式，不猜测无体。
- 每个隔离域独立持有 TLS resumption store；H2/H3 是多路复用连接，连接断开时不会在发送了业务数据之后换协议重发。只有 H3 建连/初始化探测失败才进入冷却；已建连的 QUIC 断开或收到 GOAWAY 时比较并清除旧会话，后续请求立即重新探测。若当前请求尚未发送，可回退到 H2/H1。0-RTT 只允许确定无 body 的 GET/HEAD/OPTIONS 上游尝试；明确的 TLS early rejection 才用新 1-RTT H3 连接再发，状态不明则失败，不猜测重试。
- 下游 QUIC 根据 STREAM 帧的实际 0-RTT 数据来源及可选的 `Early-Data: 1` 判定，不依赖应用读到 stream 时握手是否已结束；默认 POST/PUT/DELETE 等返回 425。TCP TLS 1.3 可接收有限 early bytes，但等待完整握手再交给 HTTP 处理器，不做半握手派发。无 early data 时采用 AWS-LC 定期轮换的 stateless tickets；支持 early data 时 Rustls 使用有界的有状态票据缓存（TCP 与 QUIC 分开，每代容量 `max(512, max_connections * 4)`）。每六小时滚动一代，只向新代写入；前一代的票据仅能以 `take` 原子消费，跨代也不重复使用，不跨实例共享。即使启用保护，也不要将 GET 设计为计费或有副作用的操作。
- `vendor/` 保留上游许可和补丁说明。H3 适配器需在等待响应头时观察 STOP_SENDING；H3 解码器限制非 DATA 帧缓冲；Quinn 保留 stream 的 0‑RTT 数据来源，供应用在解析完请求头后检查。升级对应库时应回归这些补丁。
- **`ring` 依赖审计**：`h3-quinn` 不启用 Quinn 默认 features 或 `futures-io`；`quinn-proto` 的 WASM `ring` 边已改为可选。`cargo tree --locked -i ring -e normal,build,dev` 在 Android/Linux 的启用依赖图均无 `ring`。`Cargo.lock` 仍记录上游 `hickory-proto` / `rustls-webpki` 声明的可选 `ring` 边；重新生成 lockfile 也保留，不代表构建或链接启用了它。保留这些上游包而不为清理 lockfile 再 fork DNS/TLS 验证库。

## 热重载、指标和 systemd

修改配置/证书文件时在同一文件系统写临时文件并 `rename` 替换，然后 `kill -HUP PID`。解析、出口、凭据、作用域、证书与私钥校验成功才发布；失败保留旧快照。连接/请求对新配置的选择点分别为新握手/新请求；在途旧流持有旧池并继续完成。`[listen]` 或启用/移除 TLS 要重启；证书路径与证书内容可热换。更改 shell/systemd 中的环境变量不会改变已运行进程的环境，需重启或切换到已经注入的 Key 环境变量名。`SIGINT`/`SIGTERM` 停止接受新连接并限时 drain；到期断开剩余流。

`/healthz` 检查进程就绪，不探测/计费官方 API。`/metrics` 是 Prometheus 文本：连接数、请求数、按 provider/egress 请求与错误、取消、H3 回退，TTFB histogram 及桶上界估算 P50/P99。TTFB 从转发派发到上游最终响应头，包含建连与实际上传耗时；错误口径为上游 4xx/5xx 和网关上游/流式故障。指标无凭据、无用户或路径标签。相同 provider/egress 的统计可跨成功重载延续。建议只在可信回环 namespace 下接入采集，并监控 503/504、内存和文件描述符。

建立专用 `ai-edge-gateway` 系统用户；以该用户可读、非其他用户可读的权限安装配置与私钥。如下 unit 可保存为 `/etc/systemd/system/ai-edge-gateway.service`（例如 TCP/UDP 8443，无特权端口）：

```ini
[Unit]
Description=AI Edge Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ai-edge-gateway
Group=ai-edge-gateway
UMask=0077
EnvironmentFile=-/etc/ai-edge-gateway/keys.env
ExecStartPre=/usr/local/bin/ai-edge-gateway --config /etc/ai-edge-gateway/config.toml --check
ExecStart=/usr/local/bin/ai-edge-gateway --config /etc/ai-edge-gateway/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2
TimeoutStopSec=35
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
LimitCORE=0
LimitNOFILE=8192

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now ai-edge-gateway
sudo systemctl reload ai-edge-gateway
```

`TimeoutStopSec` 要大于自身 drain 时间。systemd journal 的启动/校验日志脱敏，不开启 HTTP 库的请求追踪。公网用户或共享 BYOK 场景还应按使用量做限流/访问控制，不要把连接上限当每个账户的配额系统。

## 验证与资源指标

`cargo test --locked` 使用本地 TLS/QUIC 模拟上游，不需要真实 API Key。`tests/smoke.py` 用构建产物测试配置验证、进程级重载和信号退出。部署时应单独测量目标平台 RSS/峰值、压测慢客户端与逐 token TTFB；可以用 `grep VmRSS /proc/$pid/status` 看空闲 RSS。`< 15 MB` 是空闲目标，不适用于长流、大并发、TLS 缓存预热或很多同时活跃的隔离域。

初版在 Termux（aarch64 Android、Rust 1.99.1）的优化前基线：默认 feature 的 `release` 产物 **7,002,880 字节（6.68 MiB）**；两 worker、示例 BYOK、无请求/上游连接时，`VmRSS` 三次采样中位数为 **6.89 MiB**（明文）与 **8.26 MiB**（启用证书和 H3）。ELF 的动态依赖只有 Android `libc`、`libm`、`libdl`，没有 OpenSSL。15 项 Rust 本地测试、严格 Clippy、禁默认 feature 的 `quiet` 编译检查和进程 smoke test 均通过。没有使用真实 Key、调用计费端点或做公网负载压测。
