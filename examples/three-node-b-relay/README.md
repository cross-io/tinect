# A → B → C 示例

三个文件的内部节点名是 `A`、`B`、`C`。连接发起仅由顶层 `connect_to` 控制：B 配置 `connect_to: [A, C]`，因此由 B 主动连接；`peers.*.endpoints` 保存对端地址。

示例地址使用 `example.invalid`，部署前请改为实际可达的 underlay 地址。每个节点都必须使用独立身份密钥；运行 `tinect keygen --output node.key` 生成密钥，并将私钥安全地配置到对应节点。示例中的 `192.168.233.0/24` 是 overlay 地址段。

启动前运行 `tinect check <对应 yaml>`，并使用 `tinect up <对应 yaml> --dry-run` 审阅网络改动。

B 没有 `peers.*.routes` 和 `allowed_routes`，因此只承载 A→C 的中继 Circuit。要让 B 不创建 TUN 接口，可设置 `tun.enabled: false`。
