# Pulse Agent

**Collect and report. 采集并上报。**

Pulse Agent 运行在被监控的服务器上，采集系统状态并通过 WebSocket / WSS 上报给
[Pulse Server](https://github.com/pulse-monitor/pulse)。

它不是远程运维工具，也不是远程控制代理。

## 安全模型

Agent 遵循最小权限原则。它**不提供**：

- 远程 Shell
- 远程命令执行
- 远程文件读写
- 远程进程管理
- 任何入站监听端口

Server 能收到 Agent 上报的数据，但**不能通过 Pulse 获得对服务器的控制权**。

这不是承诺，是可以机器验证的断言 —— [tools/check-agent-hardening.sh](tools/check-agent-hardening.sh)
逐条检查源码里有没有 `process::Command`、有没有 `TcpListener`、配置是否经过校验，
在 CI 里每次都跑，不过就是红的。

| | |
|---|---|
| 体积 | 约 2.3 MB（musl 静态链接，strip 过） |
| 常驻内存 | 约 4 MB RSS |
| 运行身份 | 非 root（`pulse` 用户），capabilities 为空 |
| 监听端口 | 无 |
| 平台 | Linux（musl，不挑发行版）、Windows、macOS |

实际占用会随平台、构建方式与配置变化。

## 采集的数据

| 指标 | 说明 |
|---|---|
| CPU 使用率与负载 | 三平台 |
| 内存 / 交换分区 | 三平台 |
| 磁盘用量 | 三平台 |
| 网络流量与速率 | 三平台，网卡可按名字包含/排除 |
| 网络连接数 | 三平台 |
| 进程数 | 三平台 |
| 网络延迟与丢包 | 由 Server 下发探测目标 |
| CPU 温度 | **仅 Linux**（`/sys/class/hwmon`）。Windows 要 WMI + 管理员、macOS 要 SMC 特权访问，两者按最小权限原则都不做，如实上报「不可用」 |
| GPU | **需要以 `--features gpu` 构建**，默认关闭。走 NVML 动态加载，不调用 `nvidia-smi` 子进程 |

采不到的指标一律**如实标记为不可用**，不用 0 填充 —— 前端会隐藏那一行，而不是显示一个假的 0。

## 安装

推荐从 Pulse Server 的 Dashboard 获取安装命令，那里会带好地址和该机器的 token：

```bash
curl -fsSL https://panel.example.com/install.sh | sudo bash -s -- \
  --server wss://panel.example.com \
  --token <TOKEN>
```

安装脚本由 Server 提供（它要按每台机器生成 token），脚本本身在
[Server 仓库](https://github.com/pulse-monitor/pulse/blob/main/deploy/scripts/install.sh)。
手动安装见[文档](https://pulse-doc.pages.dev/install/agent)。

## 连接

Agent 通过 WebSocket 与 Server 通信。生产环境用 `wss://`：

```text
Agent → WSS → Pulse Server
```

Server 在 HTTPS 反向代理之后时，Agent 也要用对应的 `wss://` 地址。
明文 `ws://` 会把 token 暴露在链路上。

**断线时**按指数退避重连，重连后从当前时刻继续上报。Agent
**不缓存**断线期间的采样 —— 那段时间在图上就是一个空缺，
这比补一段来历不明的数据更诚实。

## 自更新

Agent 支持版本更新，两道防线：

1. 下载的产物要对得上 `SHA256SUMS`；
2. 清单本身必须通过 **minisign 签名**校验，公钥在**编译期内置**。

换公钥必须重新编译并重装 Agent。没有配置公钥时，自更新整个功能关闭，
`capabilities.self_update` 如实上报 `false`。

## 从源码构建

```bash
cargo build --release
```

协议定义（`pulse-proto`）在 Server 仓库 —— 它是 Server 与 Agent 之间的契约，
由 Server 那边定版，这里按 tag 引用。本地联调时用 patch 指到本地 checkout：

```toml
# .cargo/config.toml
[patch."https://github.com/pulse-monitor/pulse"]
pulse-proto = { path = "../pulse/crates/pulse-proto" }
```

三平台交叉检查（开发机只有一个平台，另外两个靠它兜）：

```bash
sh tools/cross-check.sh
```

想在自己机器上核实「非特权用户能采到哪些指标」：

```bash
sh tools/check-linux-caps.sh
```

## 相关仓库

| 仓库 | 内容 |
|---|---|
| [pulse](https://github.com/pulse-monitor/pulse) | Server + 协议定义 |
| [pulse-web](https://github.com/pulse-monitor/pulse-web) | Web 前端 |
| [pulse-docs](https://github.com/pulse-monitor/pulse-docs) | 文档站 |

文档：<https://pulse-doc.pages.dev/>

## 许可

[MIT](LICENSE)
