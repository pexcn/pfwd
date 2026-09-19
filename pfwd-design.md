# pfwd 设计手册

**目标平台**：Linux ≥ 6.12，glibc / musl，x86_64 / aarch64
**语言**：C23，无 C++；在保持高性能写法的情况下尽量使用 C23 的特性

---

## 1. 概述

pfwd 是一个 L4 端口转发器：监听本机端口，把收到的流量原样转发到远端地址，并把回程流量送回客户端。它对两端完全透明——不理解、也不改写任何应用层内容。

| 能力 | 说明 |
|---|---|
| TCP + UDP | 同一命令同时支持；一条规则可同时转发两种协议 |
| IPv4 / IPv6 | 任意组合，包括 IPv4 ↔ IPv6 跨族转发（userspace 模式） |
| 两种数据面 | `userspace`（进程内转发）与 `nftables`（内核 DNAT + flowtable），按场景选择 |
| 低依赖 | 无 libevent / glib / C++ / Lua / Python 等 |
| 生命周期干净 | nftables 模式下规则、sysctl 与 FORWARD policy 绑定进程生命周期，退出即清理 / 还原 |
| 启动期失败原则 | 不可行的配置在启动阶段明确失败，绝不出现"启动成功但流量不通" |

**明确不做**：应用层协议改写、TLS 终止、鉴权、负载均衡 / 多后端 / 健康检查、配置文件 / 热重载 / 控制 socket、iptables 兼容层、eBPF / XDP 数据面、内核模块。

---

## 2. 两种数据面模式

通过 `-m/--mode` 选择。两种模式只共享命令行解析、地址处理、日志与信号框架，数据面完全独立。

| 维度 | `userspace` | `nftables` |
|---|---|---|
| 转发位置 | 本进程（TCP 载荷经内核管道零拷贝，不进用户内存） | 内核 DNAT/SNAT + flowtable 快速路径 |
| IPv4 ↔ IPv6 跨族 | **支持** | **不支持**，启动即报错（内核 DNAT 无 NAT64 能力） |
| 所需权限 | 普通用户（监听 < 1024 端口需 `CAP_NET_BIND_SERVICE`） | `CAP_NET_ADMIN` |
| 是否改动系统状态 | 否 | 是（一张 nft table + 2 项 sysctl + FORWARD policy），退出还原 |
| 被强杀后 | 无残留 | 规则残留（下次启动自愈）、sysctl / FORWARD policy 残留（无法可靠自愈） |
| 上游看到的源地址 | 本机地址 | 本机地址（SNAT 后），上游端 ACL/基于源 IP 的日志会失效 |
| 统计 | 进程内计数器，精确 | nft counter（包/字节），无连接级细节 |
| 适用场景 | 跨族转发、非 root、容器内、需要精确统计 | 网关 / 路由器高带宽、CPU 受限设备、连接数极大 |

选择指引：**需要跨族、没有 root、或在容器里 → userspace；机器本身就是网关、追求高吞吐低 CPU → nftables。**

---

## 3. 命令行

### 3.1 规则

规则用**一对位置参数**表示，单条命令只转发一条规则：

```
pfwd [options] <local> <remote>

<local>  := [proto/]addr:port    监听地址；proto 为 tcp（默认）、udp 或 tcp,udp
<remote> := addr:port            上游地址
```

- 地址写法：`0.0.0.0:1022`、`[::]:1022`、`[2001:db8::2]:80`；host 部分也可以是域名，**仅在启动时解析一次并固化**（上游地址变化需重启进程）。
- 监听端口不能为 0。
- 一条规则可用 `tcp,udp` 前缀同时转发两种协议；需要多条转发规则时，运行多个 pfwd 实例。

### 3.2 选项

```
  -m, --mode MODE            数据面实现：userspace（默认）或 nftables
  -d, --daemonize            后台运行
  -o, --v6only               IPv6 监听只接受 IPv6 连接（默认双栈）
  -t, --udp-timeout SECS     UDP 会话空闲超时秒数（默认 60）

nftables 模式：
      --nft-table NAME       nftables table 名（默认 pfwd）
      --nft-devices DEVS     flowtable 出入设备，逗号分隔（默认自动推导）
      --no-flowtable         禁用 flowtable 快速路径
      --no-hw-offload        禁用硬件 offload 探测

其他：
  -v, --version
  -h, --help
```

另有少量容量与调优参数（`--workers`、`--max-conns`、`--udp-max-sessions`、`--tcp-idle-timeout`、`--pipe-size`、`--batch-size`、`--run-dir` 等），有合理默认值，不指定也能正常运行。

### 3.3 示例

```
# 本机 1022 -> 192.168.1.77:22（TCP）
pfwd 0.0.0.0:1022 192.168.1.77:22        # 所有来源可访问
pfwd 127.0.0.1:1022 192.168.1.77:22      # 仅本机可访问
pfwd [::]:1022 192.168.1.77:22           # IPv6 双栈监听

# UDP：本机 53 -> 8.8.8.8:53
pfwd udp/0.0.0.0:53 8.8.8.8:53

# 跨族转发（userspace 模式）：给 IPv4 服务加 IPv6 入口，反之亦然
pfwd [::]:1701 192.168.1.77:1701
pfwd 0.0.0.0:80 [2001:db8:3::2]:80

# nftables 模式：网关上做端口映射
pfwd -m nftables 192.168.1.10:25 8.8.8.8:53

# 只探测不运行
pfwd -m nftables 0.0.0.0:25 8.8.8.8:53 --check
```

---

## 4. 运行行为

### 4.1 通用

- **启动期统一探测**：规则语法、端口冲突、域名可解析、权限、fd/内存预算、内核能力等全部在启动阶段完成。任何致命问题都以如下格式报告（一次列出全部问题，而不是遇到第一个就退出）：

  ```
  [FATAL] <probe-name>: <what went wrong>
          hint: <what the user should do>
  ```

- **信号语义**：`SIGTERM` / `SIGINT` / `SIGQUIT` / `SIGHUP` 都是干净退出（不做重载），走同一条退出路径完成清理。
- **TCP keepalive 默认开启**（回收对端已消失的僵尸连接）；TCP 空闲超时默认关闭——转发器不应比端点更聪明。

### 4.2 userspace 模式

- 单规则单监听 socket；每条客户端连接在进程内开一条到上游的连接，TCP 载荷经内核管道零拷贝搬运。
- **半关闭正确传播**：一端关闭写方向后，另一方向继续传完才关闭。依赖"单向 EOF 后对端还有尾部数据"的协议（HTTP/1.0、rsync、`cat | nc` 等）不会被截断。
- **上游失败忠实传递，不重试**：上游拒绝 → 客户端看到连接被重置；上游超时 → 客户端超时。不做健康检查（单后端下无意义）。
- UDP：每个客户端地址一个会话，会话空闲 `--udp-timeout` 秒后回收；回包源地址与收包目的地址严格一致（多 IP / 多网卡下正确）。
- 大于 2048 字节的 UDP 包丢弃并计数（不支持巨帧）。
- 普通用户即可运行；对象与连接数有硬上限，耗尽时拒绝新连接/丢包并计数，绝不无界增长。

### 4.3 nftables 模式

- 启动时向内核**原子提交**一张 table（`prerouting`/`output` 做 DNAT，`postrouting` 做 SNAT，`forward` 链挂 flowtable 加速）：要么全部生效要么全部回滚，不存在漏流量窗口。
- **SNAT 源地址 = 规则的监听地址**（客户端拨入的那个 IP）。监听地址为通配（`0.0.0.0`/`[::]`）时静态无法确定源地址，此时回退 masquerade。
- **幂等自愈**：启动时先删除同名 table 再重建，上次异常退出残留的规则自动清除。
- **sysctl 自动管理**：存在 IPv4/IPv6 规则时自动开启 `ip_forward` / `ipv6.conf.all.forwarding`，退出时还原。运行期间若值被第三方改过，则不还原（不覆盖别人的设置）。多实例通过文件锁引用计数，最后一个实例才还原。`--no-sysctl` 可完全关闭此行为。
- **FORWARD 默认策略兜底**：仅开启 `ip_forward` 还不够；若 IPv4 的 iptables `FORWARD` policy 为 `DROP`，DNAT 后的数据包仍会在转发阶段被丢弃。nftables 模式启动时将其设为 `ACCEPT`（等价于 `iptables -P FORWARD ACCEPT`），不向 Docker / 其他第三方链插入规则；退出时按与 sysctl 相同的原则恢复原策略。
- **跨族规则直接拒绝**（FATAL），并提示改用 userspace 模式——否则规则装得上但流量全不通。
- flowtable 是纯加速：不支持时自动降级（硬件 offload → 软件 flowtable → 普通转发路径），只影响性能，不影响正确性，只产生 WARN。
- DNAT 目标是本机地址时给出 WARN（流量仍正确，只是不走 forward 路径、无加速）。
- 监听通配地址（如 `0.0.0.0:25`）时给出 INFO 提示：这会拦截**所有经过本机**的该端口流量，包括与本机无关的转发流量。

### 4.4 与手工 iptables 的对应

一条 `pfwd -m nftables 192.168.1.10:25 8.8.8.8:53` 等价于（且优于）：

```
iptables -t nat -A PREROUTING  -p tcp -d 192.168.1.10 --dport 25 -j DNAT --to-destination 8.8.8.8:53
iptables -t nat -A OUTPUT      -p tcp -d 192.168.1.10 --dport 25 -j DNAT --to-destination 8.8.8.8:53  # 本机发起的流量也能转发
iptables -t nat -A POSTROUTING -p tcp -d 8.8.8.8 --dport 53 -j SNAT --to-source 192.168.1.10
iptables -P FORWARD ACCEPT
# + ip_forward 自动开启、退出自动清理、重复执行不会累积规则
```

源地址取 `--to-source` 而非 `masquerade`：NAT 判定只发生在每条流的第一个包，之后的包复用 conntrack 中的绑定，两者热路径成本相同；`SNAT` 省掉首包的路由查找，且源地址由配置显式决定，行为确定。代价是出口 IP 变化（DHCP 续租、PPPoE 重拨）时需重启 pfwd，仅监听通配地址的规则例外（回退 masquerade 自动跟随）。

---

## 5. 已知限制

| # | 限制 | 说明 |
|---|---|---|
| 1 | 上游域名只在启动时解析一次 | DNS failover / 动态 DNS 不生效，地址变化需重启 |
| 2 | `--udp-timeout` 是全局的 | 无法 per-rule；需要不同超时就跑多个实例 |
| 3 | 无热重载 | 改配置必须重启，期间 TCP 连接断开、UDP 会话丢失 |
| 4 | 单后端，无负载均衡 / failover | 这是设计取舍，不是缺陷 |
| 5 | UDP 包 > 2048 字节被丢弃 | 巨帧场景不可用 |
| 6 | nftables 模式不支持跨族 | 内核 DNAT 无 NAT64 能力，物理限制 |
| 7 | nftables 模式上游看不到真实客户端 IP | SNAT 的代价；仅当本机在回程路径上才能省掉 SNAT |
| 8 | **SIGKILL / 断电后系统状态残留** | 规则可自愈，sysctl / FORWARD policy 不能可靠自愈（程序无法知道原始值）。检查命令：`sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding`、`iptables -S FORWARD`；需要保证 sysctl 清理就用 `--no-sysctl` |
| 9 | 与其他 NAT 软件共存 | 机器上跑着 Docker / libvirt / tailscale 时，建议用 `--no-sysctl`，把 `ip_forward` 交给它们管 |
