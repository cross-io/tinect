# Tinect

[![codecov](https://codecov.io/gh/cross-io/tinect/branch/master/graph/badge.svg)](https://codecov.io/gh/cross-io/tinect) [![CI](https://github.com/cross-io/tinect/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/cross-io/tinect/actions/workflows/ci.yml)

[English](README.md)

Tinect 是一个策略驱动的三层 Overlay 网络，将 **路由**（由哪个出口处理目的地址）、**路径**（流量经过哪些节点）和 **Circuit**（沿路径安装的转发状态）分开管理。

Tinect 支持经过身份认证的节点连接、端到端加密 Circuit、多跳中继、动态路径选择、故障切换、出口 ACL，以及可选的 FakeIP 域名路由。中继只转发加密后的 Circuit 载荷，不会解密。支持 Linux 和 macOS。

## 核心功能

Tinect 的设计受到 tinc 启发，并进一步支持显式指定流量经过的节点；针对承载链路丢包和 UDP 受限场景，分别提供自适应 FEC 与内置 Fake TCP。

1. **策略驱动的三层网络转发** —— 将目的路由、出口选择、节点路径与转发电路分层管理。Tinect 根据目标网段、策略优先级和链路健康状态选择出口，并可在远端路径不可用时回退至本地直连。
2. **多跳路径的显式编排与故障恢复** —— 可为不同出口指定首选和候选路径，明确控制流量经过的节点；同时，Tinect 持续跟踪链路状态，并在路径失效时重建或迁移转发电路。
3. **节点身份认证与端到端加密** —— 使用 Ed25519 公钥认证节点身份，并通过临时 X25519 密钥协商派生 ChaCha20-Poly1305 加密密钥。中继节点只负责转发密文，无法读取端到端载荷。
4. **精细化流量策略与出口访问控制** —— 支持基于网段、域名和端口配置路由策略与出口 ACL；可选 FakeIP 将域名解析结果纳入路由决策，并允许本地出口参与选路或作为回退。
5. **面向复杂承载网络的链路增强** —— 数据报 FEC 在各物理链路上独立运行，并根据链路丢包情况动态调整修复冗余，在带宽开销与丢包恢复能力之间自适应权衡。对于 UDP 被限速、降优先级或受到网络策略限制的场景，内置 Fake TCP 提供具有 TCP 报文外观的替代承载；该模式目前仅支持 Linux，且需要原始套接字权限。

## 安装与运行

使用 Rust 从源码构建：

```sh
cargo build --release --locked
```

Linux 源码构建需要 `libmnl`、`libnftnl` 开发库和 `pkg-config`。Nix 包会自动提供构建依赖。

也可以使用 Nix flake：

公共的 [`cross-io` Cachix 缓存](https://app.cachix.org/cache/cross-io#pull)可为 Linux 上的 Nix 构建提供已有的二进制产物。将以下配置加入 `/etc/nix/nix.conf`（单用户 Nix 安装可使用 `~/.config/nix/nix.conf`）：

```conf
extra-substituters = https://cross-io.cachix.org
extra-trusted-public-keys = cross-io.cachix.org-1:/W1AzPgeUf/kaqz/XtdkWpIQmoj/9x/oIdgVRnXuP3w=
```

如果使用 NixOS，在系统配置中设置对应选项：

```nix
nix.settings.extra-substituters = [ "https://cross-io.cachix.org" ];
nix.settings.extra-trusted-public-keys = [
  "cross-io.cachix.org-1:/W1AzPgeUf/kaqz/XtdkWpIQmoj/9x/oIdgVRnXuP3w="
];
```

然后使用 Nix 构建或运行 Tinect：

```sh
nix build github:cross-io/tinect
nix run github:cross-io/tinect -- --help
```

创建节点身份、检查示例配置并启动节点：

```sh
./target/release/tinect keygen --output node.key
./target/release/tinect pubkey --key node.key
cp examples/client.yaml node.yaml
./target/release/tinect check node.yaml
sudo ./target/release/tinect up node.yaml
```

连接节点前，请编辑 `node.yaml` 添加 peer 和 route。示例配置使用 `identity_key_path: ./node.key`，因此生成的密钥应和复制后的配置放在同一目录。`up` 会应用配置中的网络变更，需要具备创建 TUN 接口、管理路由和防火墙资源的权限。可先用 `./target/release/tinect up node.yaml --dry-run` 检查计划。若节点只作为中继且不需要本地 TUN 接口，可设置 `tun.enabled: false`。

## 文档

- [配置说明](docs/config.md)
- [架构说明](docs/architecture.md)
- [通信协议](docs/protocol.md)
- [网络路由与防火墙行为](docs/netfilter-routing.md)
- [示例配置](examples/client.yaml)
- [详细使用指南（英文）](docs/usage.md)
- [设计 RFC](docs/specs/README.md)

## 安全

节点身份使用 Ed25519 公钥。Circuit 载荷通过经过认证的临时 X25519 密钥派生密钥进行端到端加密；中继不会解密载荷。请按部署需求配置明确的 peer allowlist 和出口规则。PCAP 默认关闭，因为其中包含已解密的内层数据包。

Tinect 仍处于实验阶段。在生产网络中使用前，请先阅读安全与网络配置文档。

## 许可

本项目依据 [Apache License 2.0](LICENSE) 授权。
