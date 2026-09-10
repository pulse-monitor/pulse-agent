# Pulse Agent

[Pulse](https://github.com/pulse-monitor/pulse) 的探针。装在被监控的机器上，
定时把指标推给面板。

**它只上报，不听命。** 探针里没有任何执行外部命令、打开监听端口、
或者接受面板下发指令的代码路径 —— 面板就算被攻陷，也动不了你的机器。
这条约束由 [tools/check-agent-hardening.sh](tools/check-agent-hardening.sh)
在 CI 里逐条断言，不是靠自觉。

| | |
|---|---|
| 体积 | 2.3 MB（静态链接，strip 过） |
| 常驻内存 | 约 4 MB RSS |
| 运行身份 | 非 root（`pulse` 用户），capabilities 为空 |
| 监听端口 | 无 |
| 平台 | Linux（musl，不挑发行版）、Windows、macOS |

## 安装

从面板后台复制安装命令，那里会带好地址和 token：

```bash
curl -fsSL https://你的面板/install.sh | sudo bash -s -- \
  --server wss://你的面板 --token XXXX
```

安装脚本由面板提供（它要按每台机器生成 token）。手动安装见
[文档](https://pulse-doc.pages.dev/install/agent)。

## 从源码构建

```bash
cargo build --release
```

协议定义（`pulse-proto`）在面板仓库里 —— 它是 server 和 agent 之间的契约，
由 server 那边定版。本地联调时用 patch 指到本地 checkout：

```toml
# .cargo/config.toml
[patch."https://github.com/pulse-monitor/pulse"]
pulse-proto = { path = "../monitor/crates/pulse-proto" }
```

三平台交叉检查（开发机只有一个平台，另外两个靠它兜）：

```bash
sh tools/cross-check.sh
```

## 采集权限

Linux 上全部指标都能在非特权用户下采到。想在自己的机器上核实一遍：

```bash
sh tools/check-linux-caps.sh
```

## 相关仓库

| 仓库 | 内容 |
|---|---|
| [pulse](https://github.com/pulse-monitor/pulse) | 面板（server） + 协议定义 |
| [pulse-web](https://github.com/pulse-monitor/pulse-web) | 面板前端 |
| [pulse-docs](https://github.com/pulse-monitor/pulse-docs) | 文档站 |

文档：<https://pulse-doc.pages.dev/>
