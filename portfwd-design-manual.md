# portfwd 设计手册

**版本**：Draft 1.0
**目标平台**：Linux ≥ 4.14（推荐 ≥ 5.10），glibc / musl，x86_64 / aarch64 / mips / mipsel（OpenWrt）
**语言**：C23，无 C++，无 libevent / glib

> 本手册只描述设计。文中出现的结构体定义、函数签名、状态转换表、nftables 规则模板、伪代码均为接口契约，不是实现代码。
> 所有标识符、注释、CLI 参数、日志文本一律英文。

---

## 目录

1. [目标与非目标](#1-目标与非目标)
2. [总体架构与两种模式的能力对照](#2-总体架构与两种模式的能力对照)
3. [源文件布局与模块划分](#3-源文件布局与模块划分)
4. [关键数据结构](#4-关键数据结构)
5. [模块间接口](#5-模块间接口)
6. [状态机](#6-状态机)
7. [启动期能力探测与错误处理策略](#7-启动期能力探测与错误处理策略)
8. [日志策略](#8-日志策略)
9. [资源预算](#9-资源预算)
10. [关键性能决策及其理由](#10-关键性能决策及其理由)
11. [已知风险与权衡](#11-已知风险与权衡)
12. [分阶段实现里程碑](#12-分阶段实现里程碑)
13. [未来演进（不进入里程碑）](#13-未来演进不进入里程碑)
- [附录 A：从 iptables 命令到本项目的映射](#附录-a从-iptables-命令到本项目的映射)
- [附录 B：开放性设计问题结论索引](#附录-b开放性设计问题结论索引)

---

## 1. 目标与非目标

### 1.1 目标

| 编号 | 目标 |
|---|---|
| G1 | 单一静态可链接的 C 二进制，把本机监听端口转发到远端主机，TCP 与 UDP 同时支持 |
| G2 | 提供两种可由用户选择的数据面：`userspace`（进程内 splice/recvmmsg）与 `nftables`（内核 DNAT/SNAT + flowtable） |
| G3 | 低 CPU、低内存，性能优先；转发热路径上无 `malloc`、无日志、无字符串格式化 |
| G4 | 可交叉编译到 OpenWrt；不依赖 libevent / glib / C++ / Lua / Python |
| G5 | `userspace` 模式支持 IPv4 ↔ IPv6 跨族转发 |
| G6 | `nftables` 模式的规则与 sysctl 变更严格绑定进程生命周期，退出即清理，异常退出后下次启动自愈 |
| G7 | 不可行的配置在**启动阶段**明确失败，绝不出现"启动成功但流量不通" |

### 1.2 非目标（明确排除）

| 编号 | 非目标 | 理由 |
|---|---|---|
| N1 | iptables 兼容层 | 现代内核上 `iptables` 本身就是 nft backend 的前端；维护两套规则生成器只增加代码面积和测试矩阵，收益为零 |
| N2 | eBPF / XDP / AF_XDP 数据面 | 需要 libbpf + clang + BTF/CO-RE，交叉编译到 OpenWrt 的工具链成本远超收益；且 XDP 在多数目标网卡上只有 generic 模式，性能不如 flowtable |
| N3 | 内核模块 | 违背"用户可自行部署的单一二进制"定位 |
| N4 | IPVS 模式 | IPVS 面向 L4 负载均衡（多 real server + 调度算法），与"单目标端口转发"定位不匹配 |
| N5 | 应用层协议改写、TLS 终止、SNI 分流、鉴权 | 本项目是 L4 透明管道，任何 L7 处理都会强制载荷进入用户态，与 G3（splice 零拷贝）直接冲突 |
| N6 | 负载均衡、多后端、健康检查 | 见 [10.5](#105-不重试不做健康检查q5) |
| N7 | 配置文件、热重载、控制 socket | 第一版只有 CLI；配置管理交给 procd / systemd / rc 脚本 |

---

## 2. 总体架构与两种模式的能力对照

### 2.1 分层

```
                      +---------------------------+
                      |  main / CLI / config      |   ← 两模式共享
                      |  addr abstraction (inx)   |
                      |  log / signal / mainloop  |
                      |  capability probe fw      |
                      +------------+--------------+
                                   |
                    struct fwd_rule[]  (mode-agnostic)
                                   |
              +--------------------+--------------------+
              |                                         |
   +----------v-----------+                 +-----------v-----------+
   | backend: userspace   |                 | backend: nftables     |
   |  epoll + splice      |                 |  libmnl + libnftnl    |
   |  recvmmsg/sendmmsg   |                 |  sysctl manager       |
   |  conn pool / udp ht  |                 |  table lifecycle      |
   +----------------------+                 +-----------------------+
        data plane = this process              data plane = kernel
```

**边界（Q8 结论）**：CLI 解析、地址抽象（`struct sockaddr_inx` 及其访问宏）、日志、信号与主循环骨架、能力探测框架 **共享**；两个 backend 只通过 `struct fwd_backend` 的 5 个函数指针接入，**数据面代码零共享**。理由见 [10.8](#108-两模式共享配置解析与地址抽象q8)。

### 2.2 能力对照表

| 维度 | `userspace` | `nftables` |
|---|---|---|
| 数据面位置 | 本进程用户态（TCP 载荷经内核 pipe，不进用户内存） | 内核 netfilter / flowtable / 网卡 |
| TCP 实现 | `splice(2)` × 2 pipe，零拷贝 | DNAT + SNAT，conntrack 跟踪 |
| UDP 实现 | `recvmmsg`/`sendmmsg` 批量 + 每客户端一个 connected socket | DNAT + SNAT，conntrack UDP 表项 |
| **IPv4 ↔ IPv6 跨族** | **支持**（唯一支持的模式） | **不支持**（DNAT 无 NAT64 能力），启动即报错 |
| 所需权限 | 普通用户即可（端口 <1024 需 `CAP_NET_BIND_SERVICE`） | `CAP_NET_ADMIN` + 可写 `/proc/sys` |
| 是否改动全局系统状态 | 否 | 是（nft table + 2 项 sysctl），退出还原 |
| 进程被 `SIGKILL` 后 | 无残留 | 规则残留、sysctl 残留（见 [11.2](#112-sigkill--断电下的残留)） |
| 客户端源地址对后端可见 | 否（后端看到本机地址） | 否（SNAT 后同样是本机地址）；若本机在回程路径上可省 SNAT 保留原地址 |
| 单核吞吐量级（参考） | TCP ~5–15 Gbit/s（大包、少连接）；UDP ~0.3–1.0 Mpps | 软件 flowtable ~5–20 Gbit/s；硬件 offload 受限于线速，CPU 近 0 |
| 每连接 CPU 成本 | 每次唤醒 1–2 次 `splice` 系统调用 | 首包走完整 netfilter 路径，后续包走 fastpath |
| 短连接场景 | 每连接 6 个 fd + accept/close 开销 | 每连接 1 个 conntrack 表项，无 fd |
| 观测性 | 进程内计数器，精确 | nft counter（包/字节），无连接级细节（见 [10.7](#107-nftables-模式下的统计q7)） |
| 适用场景 | 跨族转发、非 root 环境、容器内、需要精确统计 | 高带宽路由器 / 网关、CPU 受限的嵌入式设备、连接数极大 |
| 不适用场景 | 10 Gbit+ 大流量下 CPU 成为瓶颈 | 跨族、无 root、容器 netns 中无 conntrack |

### 2.3 CLI 形态

**Q1 结论：单二进制 + 单进程内支持多条转发规则。**

```
portfwd [global options] -f RULE [-f RULE ...]

RULE := <proto>/<local-addr>:<port>-><remote-addr>:<port>
        e.g.  tcp/0.0.0.0:1022->192.168.1.7:22
              udp/[::]:1701->192.168.1.7:1701
              tcp,udp/[::]:80->[2001:db8::2]:80

Global options:
  -m, --mode {userspace|nftables}   data plane implementation (required)
  -w, --workers N|auto              number of worker processes (default: 1)
  -d, --daemonize                   detach from controlling terminal
  -P, --pidfile PATH                write pid file
  -l, --log-level {error|warn|info|debug|trace}   (default: info)
  -L, --log-target {stderr|syslog}  (default: stderr, or syslog when daemonized)
      --udp-timeout SECONDS         UDP session idle timeout (default: 60)
      --udp-max-sessions N          per-worker session cap (default: 8192)
      --tcp-idle-timeout SECONDS    0 disables (default: 0)
      --max-conns N                 per-worker TCP connection cap (default: 4096)
      --pipe-size BYTES             splice pipe capacity (default: 65536)
      --batch-size N                recvmmsg/sendmmsg batch (default: 32)
      --v6only                      force IPV6_V6ONLY on [::] listeners
      --no-sysctl                   nftables mode: do not touch /proc/sys
      --nft-table NAME              nftables table name (default: portfwd)
      --nft-devices dev[,dev...]    flowtable ingress devices (default: autodetect)
      --no-flowtable                disable flowtable fast path
      --no-hw-offload               disable 'flags offload' probing
      --check                       run capability probe, print report, exit
  -v, --version
  -h, --help
```

#### 为什么是单二进制 + 多规则（Q1）

对比 `rssnsj/portfwd` 的 `tcpfwd` / `udpfwd` 双二进制、单规则模型：

| 方案 | 优点 | 缺点 |
|---|---|---|
| 每规则一进程（portfwd 风格） | 隔离性好；崩溃只影响一条规则；init 脚本简单 | **nftables 模式下致命**：N 个进程各自管理 sysctl 与 table，引用计数问题被放大 N 倍；每进程独立 epoll + 独立内存池，OpenWrt 上 10 条规则 = 10 份常驻 RSS |
| 单进程多规则（本项目） | nftables 模式下一张 table、一次 sysctl 变更、一次原子事务；userspace 模式下所有 listener 共享一个 epoll 和一个连接池；内存与 fd 摊薄 | 崩溃影响所有规则；配置解析略复杂 |

**决策：单二进制、单进程、多规则。** 决定性理由是 [2.6](#26-sysctl-自动管理nftables-模式) 描述的 sysctl 生命周期问题——把 N 条规则塞进一个进程，多实例并发问题就从"常态"退化为"用户显式启动多个实例时才发生的边缘情况"。隔离性的损失由"转发路径上不分配内存、不解析协议"这一设计本身来补偿：数据面代码没有可崩溃的复杂逻辑。

**协议参数 vs 拆分二进制**：用规则字符串中的 `tcp` / `udp` / `tcp,udp` 前缀区分，**不拆二进制**。理由：nftables 模式下 TCP 和 UDP 规则共用同一张 table、同一套 sysctl 状态；拆成两个二进制意味着两套 table 生命周期和两份 sysctl 引用计数，是自找麻烦。userspace 模式下二者共用同一个 epoll 循环也更省资源。

### 2.4 `userspace` 模式数据面概览

```
listener(SO_REUSEPORT) --accept4--> client_fd
                                       |
      conn = pool_alloc()              |
      upstream_fd = socket+connect(nonblocking)
                                       |
      pipe(c2u)  pipe(u2c)             |
                                       v
   +-----------+  splice   +--------+  splice   +-------------+
   | client_fd | --------> | c2u    | --------> | upstream_fd |
   |           | <-------- | u2c    | <-------- |             |
   +-----------+           +--------+           +-------------+
        载荷始终停留在内核 pipe buffer，不进入本进程地址空间
```

UDP：

```
listener(SO_REUSEPORT, IP_PKTINFO/IPV6_RECVPKTINFO)
   recvmmsg(batch) -> for each msg:
       key = client sockaddr
       sess = ht_lookup(key) ?: ht_insert(new connected upstream socket)
       queue msg into sess->tx batch
   sendmmsg(sess->upstream_fd, batch)

upstream_fd readable:
   recvmmsg(batch) -> sendmmsg(listener, batch, addr=client, cmsg=pktinfo(local_addr))
```

### 2.5 `nftables` 模式数据面概览

程序不在数据面上。启动时向内核提交一个 netlink 事务，内容大致等价于（以 `nft` 语法表达，仅作说明用途；实现走 libmnl+libnftnl）：

```
table inet portfwd {
    flowtable ft {
        hook ingress priority 0
        devices = { eth0, eth1 }
        flags offload            # only when hardware offload probe succeeded
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip  daddr <local-v4> tcp dport 1022 counter dnat ip  to 192.168.1.7:22
        ip6 daddr <local-v6> udp dport 1701 counter dnat ip6 to [2001:db8::2]:1701
    }

    chain output {
        type nat hook output priority dstnat; policy accept;
        # same matches, so that locally-generated traffic is forwarded too
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip  daddr 192.168.1.7 tcp dport 22 counter masquerade
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
        ct state established,related counter flow add @ft
    }
}
```

关于 flowtable 的三个事实，直接决定了设计：

- <cite index="10-1">flowtable 只对**被转发**的流量生效，且要求流的第一个包先完整走一遍常规 IP 转发路径，从第二个包开始才可能命中 fastpath；命中后包通过 `neigh_xmit()` 直接发往出口设备，绕过 ingress 之后的所有 netfilter hook。</cite>
- <cite index="11-1">流是在 conntrack 状态建立之后才被 offload 的，通常是第一个回包创建 flowtable 表项；forward 链上的 `flow` 表达式必须能匹配到初始连接的回程流量。</cite>
- <cite index="6-1">硬件卸载通过 flowtable 定义上的 `offload` 标志开启；不指定该标志时使用软件 flowtable 数据路径。</cite>

推论：
1. DNAT 目标必须是**本机之外**的地址，流量才走 forward 路径，flowtable 才有意义。DNAT 到 `127.0.0.1` 或本机地址时 flowtable 完全不生效——启动时检测到这种配置要 `WARN`，但不阻止（功能仍正确，只是无加速）。
2. flowtable 是纯加速，失败不影响正确性。因此 flowtable 创建失败降级为 `WARN` + 继续，硬件 offload 失败降级为软件 flowtable，**两者都不是致命错误**。这与"跨族"不同，后者是致命错误。
3. `flags offload` 需要驱动支持。探测策略见 [7.3](#73-nftables-模式专有探测)。

### 2.6 sysctl 自动管理（nftables 模式）

需要管理的项：

| 路径 | 要求值 | 何时需要 |
|---|---|---|
| `/proc/sys/net/ipv4/ip_forward` | `1` | 存在任一 IPv4 规则 |
| `/proc/sys/net/ipv6/conf/all/forwarding` | `1` | 存在任一 IPv6 规则 |

流程（`sysctl_mgr`）：

```
startup:
  for each item needed:
      orig = read(path)                       # fail-fast if unreadable
      if orig >= required:  owned = false     # someone else already enabled it
      else:                 write(path, required); owned = true; record orig

shutdown:
  for each item with owned == true:
      cur = read(path)
      if cur != required:      skip   # third party changed it, do not clobber
      if refcount_others > 0:  skip   # another instance still needs it
      write(path, orig)
```

**Q6 结论：采用"保守还原 + 基于 flock 的引用计数"的组合方案，并保留 `--no-sysctl` 作为逃生舱。**

三方案取舍：

| 方案 | 机制 | 优点 | 缺点 | 结论 |
|---|---|---|---|---|
| A. 纯保守还原 | 只在 `orig == 0` 且退出时当前值仍等于自己写入的 `1` 时才还原 | 无外部状态，无文件系统依赖，只读 `/proc` | **无法区分"第三方设为 1"和"实例 B 设为 1"**——两者当前值都是 1，都长得像"我设的"。实例 A 退出时会把仍在运行的实例 B 掐断 | 作为 fallback |
| B. flock 引用计数 | `/run/portfwd/sysctl.<item>.lock` 上加共享锁；退出时尝试升级为独占锁，成功说明自己是最后一个持有者，才还原 | 正确处理多实例；`flock` 在进程被 `SIGKILL` 时由内核自动释放，不会留下幽灵引用 | 需要可写的 `/run`（OpenWrt 上 `/var/run` 是 tmpfs，满足）；容器/只读根文件系统下不可用 | **默认方案** |
| C. 完全不管，`--no-sysctl` | 交给用户/init 脚本 | 零风险 | 用户体验差，"配好了不通"的头号来源 | 保留为选项 |

**默认行为**：启动时尝试在 `--run-dir`（默认 `/run/portfwd`，不可写时依次尝试 `/var/run/portfwd`、`/tmp/portfwd`）建立引用锁。
- 建锁成功 → 方案 B。
- 建锁失败（只读 fs / 无权限）→ 降级为方案 A，并输出一条 `WARN`：
  `[WARN] sysctl refcounting unavailable (/run/portfwd: Read-only file system); falling back to conservative restore. Concurrent instances may interfere. Consider --no-sysctl.`

**"还原前复查"是无条件的**，无论 A 还是 B：如果退出时 `read(path) != required`，说明运行期间有第三方（管理员、Ansible、另一个程序）改过，此时**不还原**，只记一条 `INFO`。覆盖别人的意图比留下一个 `1` 更糟。

**读写方式**：一律通过 `/proc/sys/...` 的 `open`/`read`/`write`。`sysctl(2)` 系统调用早已废弃，glibc 2.32 起彻底移除了 `sysctl()` 包装函数，musl 从未提供。不要用。

**已接受的局限**：`SIGKILL`、OOM kill、断电、内核 panic 场景下 sysctl 无法还原。这是**明确接受**的（见 [11.2](#112-sigkill--断电下的残留)）。规则可以靠"启动时删旧建新"自愈，sysctl 不能——因为无法区分"上次残留的 1"和"管理员本来就想要的 1"。

### 2.7 规则清理策略（nftables 模式）

**设计决策：只依赖进程内信号处理，不引入 systemd 单元、不引入 cron、不引入任何外部兜底进程。**

- 捕获 `SIGTERM` / `SIGINT` / `SIGQUIT` / `SIGHUP`，四者走**同一条退出路径**（`SIGHUP` 不做重载，第一版语义就是退出）。
- **async-signal-safety**：信号处理函数**只做一件事**——向 self-pipe 写 1 字节信号编号（`write(2)` 是 async-signal-safe）。主循环的 epoll 监听 self-pipe 读端，被唤醒后在**正常上下文**执行清理。netlink 事务、`/proc/sys` 写、日志输出全部在正常上下文完成。

  - 首选实现：`signalfd(2)`（更干净，一个 fd 直接进 epoll，无需 handler）。
  - fallback：self-pipe（`pipe2(O_NONBLOCK|O_CLOEXEC)` + `sigaction` with `SA_RESTART`）。musl 与所有目标内核都支持 `signalfd`，但保留 self-pipe 路径以便在极端裁剪的环境编译。
  - 绝不在 handler 里调用 `mnl_socket_sendto`、`fprintf`、`malloc`、`syslog`。
- **幂等自愈**：启动时**无条件**先 `delete table inet <name>`，再 `add table` + 建链 + 加规则。删除不存在的 table 会返回 `ENOENT`，正常忽略。这是应对上一次 `SIGKILL` 遗留规则的**唯一手段**。
- **原子性**：删旧 + 建新放进**同一个 netlink 事务**（`NFNL_MSG_BATCH_BEGIN` … `NFNL_MSG_BATCH_END` 一次 `sendmsg`），内核要么全部生效要么全部回滚，不存在"旧规则已删、新规则未加"的漏流量窗口。

### 2.8 nftables 交互方式选型（Q：三方案对比）

| 方案 | 运行时依赖 | 交叉编译难度 | 开发量 | 体积增量（stripped，aarch64 静态） |
|---|---|---|---|---|
| **libnftables (JSON API)** | libnftables → libnftnl → libmnl，**外加 libjansson（JSON）与 libgmp（多精度算术）** | 高：libgmp 的 configure 对交叉编译不友好，OpenWrt 需要额外 package | 最小（拼 JSON 字符串即可） | ~700 KB – 1.2 MB |
| **libmnl + libnftnl** | libmnl（~25 KB）+ libnftnl（~180 KB） | 低：两者都是纯 C、autotools 规范、OpenWrt 官方有 package | 中等（需要手工构造 expression 链：payload / cmp / immediate / nat / counter / flow_offload） | ~200–260 KB |
| **纯手写 netlink** | 无（只需内核 uapi 头） | 最低 | **最大**：要手写 nftables 的整套 TLV 编码、expression 序列化、batch 事务、错误解析 | ~40–60 KB |

Debian 的包依赖直接印证了第一条：<cite index="21-1">libnftables1 依赖 libgmp10、libjansson4、libmnl0、libnftnl11。</cite>而 <cite index="20-1">libnftnl 只依赖 libmnl 和一个包含 nf_tables 子系统的内核。</cite>

**决策：libmnl + libnftnl。**

理由：
1. **依赖闭包最小**。libnftables 为了解析人类可读语法和 JSON，拖进了 gmp 和 jansson——本项目生成的规则集是**程序完全掌控的固定形状**，不需要通用解析器。为固定 6 条规则拖进一个多精度算术库是荒唐的。
2. **交叉编译**。libmnl / libnftnl 在 OpenWrt feeds 里是现成的 package，`DEPENDS:=+libnftnl` 一行搞定。libgmp 虽然也有 package，但把它加进依赖会让一个"端口转发小工具"的安装尺寸翻三倍。
3. **纯手写不划算**。nftables 的 expression 编码不是稳定 ABI 意义上的"简单 TLV"——`nft_rule_expr` 的各类型属性、set/map 的引用、batch 事务的 seq 管理、`NLMSG_ERROR` 中的 `nlmsgerr` offset 解析，libnftnl 已经把这些都封装好了，而且随内核演进持续维护。省下的 200 KB 换来的是长期的兼容性债务。
4. **绝不 fork/exec `nft`**：需要目标系统安装 nft 二进制（OpenWrt 上不保证）；每次调用一次 fork+exec+解析文本输出；错误处理只能靠 grep stderr；且无法做到"删旧建新同一事务"。这条是硬性禁止。

编译期开关：`--disable-nftables` 产出仅含 userspace backend 的二进制，无任何外部依赖，体积 ~60 KB。

---

## 3. 源文件布局与模块划分

```
portfwd/
├── Makefile                 # plain make, no autotools/cmake
├── src/
│   ├── main.c               # entry, daemonize, worker fork, top-level lifecycle
│   ├── config.c/.h          # CLI parsing, rule list, defaults
│   ├── addr.c/.h            # sockaddr_inx, parse/format, family helpers
│   ├── log.c/.h             # leveled logging, stderr/syslog sink
│   ├── sig.c/.h             # signalfd / self-pipe, unified shutdown path
│   ├── probe.c/.h           # startup capability probe framework
│   ├── backend.h            # struct fwd_backend interface
│   ├── us/                  # userspace backend
│   │   ├── us_backend.c     # backend vtable impl, worker main loop
│   │   ├── us_loop.c/.h     # epoll wrapper, deferred-free queue, timers
│   │   ├── us_tcp.c/.h      # listener, accept, splice pump, half-close FSM
│   │   ├── us_udp.c/.h      # recvmmsg/sendmmsg, session hash table, aging
│   │   └── us_pool.c/.h     # slab/freelist object pool with generation
│   ├── nft/                 # nftables backend
│   │   ├── nft_backend.c    # backend vtable impl
│   │   ├── nft_batch.c/.h   # libmnl batch transaction helper
│   │   ├── nft_rules.c/.h   # table/chain/rule/flowtable construction
│   │   ├── nft_stats.c/.h   # counter readback via netlink dump
│   │   └── sysctl.c/.h      # /proc/sys read-modify-restore + flock refcount
│   └── util/
│       ├── hash.c/.h        # siphash-1-2 or xxhash32 for session keys
│       └── compat.h         # feature macros, fallbacks (signalfd, accept4...)
├── tests/
│   ├── t_addr.c             # unit: address parsing round-trip
│   ├── t_hash.c             # unit: hash table distribution/collision
│   ├── integration/*.sh     # socat/nping/dig based end-to-end scripts
│   └── netns/*.sh           # ip netns harness for nftables mode
└── README.md                # written last, see milestone M6
```

模块依赖方向严格单向：`util` ← `addr`/`log` ← `config`/`probe`/`sig` ← `backend impls` ← `main`。任何 backend 都不允许 include 另一个 backend 的头文件。

---

## 4. 关键数据结构

### 4.1 地址抽象

跨族差异**收敛在这一处**。转发主逻辑中不允许出现第二处 `if (family == AF_INET)` 分支。

```c
/* addr.h */
union sockaddr_inx {
    struct sockaddr     sa;
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;
};

#define sa_family_of(p)     ((p)->sa.sa_family)
#define is_v4(p)            (sa_family_of(p) == AF_INET)
#define is_v6(p)            (sa_family_of(p) == AF_INET6)

/* Returns the port in network byte order. */
#define port_of_sockaddr(p) \
    (is_v6(p) ? (p)->in6.sin6_port : (p)->in.sin_port)

/* Returns a pointer to the raw address bytes (4 or 16 octets). */
#define addr_of_sockaddr(p) \
    ((void *)(is_v6(p) ? (void *)&(p)->in6.sin6_addr : (void *)&(p)->in.sin_addr))

#define addrlen_of_sockaddr(p) \
    (is_v6(p) ? 16u : 4u)

#define sizeof_sockaddr(p) \
    (is_v6(p) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))
```

> 这组宏的写法直接借鉴 `rssnsj/portfwd`。它的价值在于：`connect()`、`sendto()`、`bind()` 全部写成 `connect(fd, &sa->sa, sizeof_sockaddr(sa))`，family 分支从调用点彻底消失。跨族转发之所以在 userspace 模式下"免费"，正是因为本地 listener 和上游 socket 是**两个独立创建的 socket**，各自用自己的 family 建立，中间只有 splice 搬运字节流——字节流本身没有 family。

```c
int  addr_parse(const char *s, union sockaddr_inx *out, int default_family);
/* "0.0.0.0:1022", "[::]:1701", "[2001:db8::2]:80", "example.com:80" */

int  addr_format(const union sockaddr_inx *sa, char *buf, size_t len);
/* Always bracket-quotes IPv6, so output can be fed back into addr_parse(). */

int  addr_equal(const union sockaddr_inx *a, const union sockaddr_inx *b);
uint32_t addr_hash(const union sockaddr_inx *sa, uint32_t seed);
```

### 4.2 配置与规则

```c
/* config.h */
enum fwd_proto { FWD_TCP = 1u << 0, FWD_UDP = 1u << 1 };
enum fwd_mode  { MODE_USERSPACE, MODE_NFTABLES };

struct fwd_rule {
    union sockaddr_inx  local;        /* listen / DNAT match address */
    union sockaddr_inx  remote;       /* upstream / DNAT target      */
    unsigned            proto;        /* bitmask of enum fwd_proto   */
    unsigned            cross_family; /* computed: local.family != remote.family */
    char                label[32];    /* for logs and nft comments   */
};

struct fwd_config {
    enum fwd_mode       mode;
    struct fwd_rule    *rules;
    unsigned            n_rules;

    unsigned            workers;          /* resolved, never 0            */
    unsigned            max_conns;        /* per worker                   */
    unsigned            udp_max_sessions; /* per worker                   */
    unsigned            udp_timeout_s;
    unsigned            tcp_idle_timeout_s; /* 0 = disabled               */
    unsigned            pipe_size;
    unsigned            batch_size;

    unsigned            v6only:1;
    unsigned            daemonize:1;
    unsigned            no_sysctl:1;
    unsigned            no_flowtable:1;
    unsigned            no_hw_offload:1;
    unsigned            check_only:1;

    const char         *pidfile;
    const char         *run_dir;
    const char         *nft_table;
    const char        **nft_devices;
    unsigned            n_nft_devices;
    int                 log_level;
    int                 log_target;
};
```

### 4.3 backend 抽象

```c
/* backend.h */
struct fwd_backend {
    const char *name;

    /* Validate config against this backend's constraints and the running
     * kernel. Must not mutate any system state. Called before fork(). */
    int (*probe)(const struct fwd_config *cfg, struct probe_report *rep);

    /* Install whatever is needed (rules, sysctl, listeners).
     * Called once in the parent for nftables, once per worker for userspace. */
    int (*setup)(const struct fwd_config *cfg, void **state);

    /* Run until shutdown is requested via the signal fd.
     * nftables backend just parks on the signal fd. */
    int (*run)(void *state, int sigfd);

    /* Undo everything setup() did. Must be idempotent and must not fail
     * silently: every unwind error is logged at WARN. */
    void (*teardown)(void *state);

    /* Optional. Fill in a stats snapshot. NULL if unsupported. */
    int (*stats)(void *state, struct fwd_stats *out);
};

extern const struct fwd_backend backend_userspace;
extern const struct fwd_backend backend_nftables;   /* NULL-able at link time */
```

### 4.4 userspace TCP 连接对象

```c
/* us_tcp.h */
enum conn_state {
    CONN_CONNECTING,   /* upstream connect() in flight        */
    CONN_ESTABLISHED,  /* both directions open                */
    CONN_HALF_C2U,     /* client->upstream closed, other open */
    CONN_HALF_U2C,     /* upstream->client closed, other open */
    CONN_CLOSING,      /* queued on deferred-free list        */
};

/* One unidirectional pump: src -> pipe -> dst. */
struct pump {
    int      pipe_r;        /* read end  (pipe -> dst)   */
    int      pipe_w;        /* write end (src -> pipe)   */
    uint32_t inflight;      /* bytes currently in pipe   */
    uint8_t  src_eof;       /* src returned 0 on splice  */
    uint8_t  dst_shutdown;  /* shutdown(dst, SHUT_WR) done */
    uint64_t bytes;         /* cumulative, for stats     */
};

struct conn {
    int                 client_fd;
    int                 upstream_fd;
    uint32_t            client_events;    /* last epoll mask installed */
    uint32_t            upstream_events;  /* last epoll mask installed */

    struct pump         c2u;              /* client   -> upstream */
    struct pump         u2c;              /* upstream -> client   */

    uint8_t             state;            /* enum conn_state */
    uint8_t             rule_idx;
    uint16_t            _pad;
    uint32_t            generation;       /* bumped on free; see 4.6  */
    uint32_t            slot;             /* index into the pool      */

    uint64_t            last_activity_ms; /* for optional idle timeout */
    struct conn        *free_next;        /* freelist / deferred queue */
};
```

`sizeof(struct conn)` ≈ 4×4 + 2×32 + 4 + 4 + 8 + 8 + 8 ≈ **112 字节**（x86_64；`struct pump` 为 4+4+4+1+1+2pad+8 = 24 B，两个 48 B）。加上池的对齐余量按 **128 字节/连接** 计。

### 4.5 userspace UDP 会话对象与哈希表

```c
/* us_udp.h */
struct udp_session {
    union sockaddr_inx  client;         /* hash key                       */
    union sockaddr_inx  local;          /* local addr from IP_PKTINFO     */
    int                 upstream_fd;    /* connect()ed to rule->remote    */
    uint8_t             rule_idx;
    uint8_t             _pad[3];
    uint32_t            generation;
    uint32_t            slot;
    uint64_t            last_activity_ms;
    uint64_t            pkts_in, pkts_out;
    struct udp_session *ht_next;        /* separate chaining              */
    struct udp_session *free_next;
};
```

`sizeof(struct udp_session)` ≈ 28+28（对齐到 32+32）+4+4+4+4+8+16+8+8 ≈ **120 字节**，按 **128 字节/会话** 计。

```c
struct udp_table {
    struct udp_session **buckets;   /* power-of-two sized                 */
    uint32_t             mask;      /* nbuckets - 1                       */
    uint32_t             nbuckets;
    uint32_t             count;
    uint32_t             seed;      /* per-worker random, anti-collision  */
    uint32_t             sweep_cursor;   /* incremental aging cursor      */
};
```

**哈希表规格**：
- 桶数 = `next_pow2(udp_max_sessions * 2)`，默认 `udp_max_sessions = 8192` → **16384 桶**，目标装载因子 ≤ 0.5。
- 冲突策略：**链地址法**（separate chaining），链表节点就是 `udp_session` 自身的 `ht_next` 字段，**不额外分配**。开放寻址在删除时需要墓碑标记，而 UDP 会话表是高频删除结构，链地址法更合适。
- 哈希函数：以 `(client_addr_bytes, client_port, rule_idx)` 为输入的 **SipHash-1-2**，per-worker 随机 seed。用带 key 的哈希而不是 FNV/DJB2，是为了防止攻击者用精心构造的源地址集合把所有会话打进同一个桶（算法复杂度攻击）。SipHash-1-2 单次调用约 20 ns，相对每包 recvmmsg 摊薄后的成本可以忽略。
- 桶数组内存：16384 × 8 B = **128 KiB/worker**。
- **不做动态 rehash**：会话数硬上限为 `udp_max_sessions`，达到上限后拒绝新会话并计数（`ERROR` 级别限速日志）。rehash 会在数据面引入一次 O(N) 停顿，与 [10.4](#104-udp-会话老化用增量遍历) 的设计意图（消除周期性尖刺）矛盾。

> **反面案例（必须避免）**：`rssnsj/portfwd` 中有 `#define CONN_TBL_HASH_SIZE (1 < 8)`——本意是 `1 << 8`，误写成 `<`，表达式求值为 `1`。结果哈希表退化为**单桶链表**，每个包的会话查找变成 O(N) 线性扫描，会话数上千后 UDP 转发性能塌方。
> 防御措施（写进代码，不只是写进文档）：
> ```c
> _Static_assert((UDP_HT_MIN_BUCKETS & (UDP_HT_MIN_BUCKETS - 1)) == 0,
>                "bucket count must be a power of two");
> _Static_assert(UDP_HT_MIN_BUCKETS >= 256, "bucket count too small");
> ```
> 并在 `tests/t_hash.c` 中断言：插入 N 个随机 key 后，最长链长度 < `8 * N / nbuckets + 8`。

### 4.6 对象池与 generation

```c
/* us_pool.h — one pool per worker, one for conns, one for udp_sessions */
struct pool {
    void       *slab;        /* single contiguous allocation, made at startup */
    void       *freelist;    /* intrusive singly-linked list                  */
    uint32_t   *generation;  /* parallel array, one uint32_t per slot         */
    uint32_t    nslots;
    uint32_t    nused;
    uint32_t    obj_size;
    uint32_t    gen_off;     /* offset of the generation field in the object  */
    uint32_t    next_off;    /* offset of the free_next field                 */
};
```

**关键约束：转发路径上不得调用 `malloc`。** 整个 slab 在 worker 启动时一次性分配（`calloc(nslots, obj_size)`），随后所有 `pool_alloc` / `pool_free` 都是 O(1) 的 freelist 摘挂。池耗尽时 `pool_alloc` 返回 `NULL`，调用方的处理是：TCP → `accept4` 后立即 `close`（相当于对客户端表现为连接被重置）；UDP → 丢弃该包并计数。**绝不动态扩容**——扩容意味着在数据面 `malloc`，而且在内存紧张的 OpenWrt 设备上，一个能无限增长的连接池就是一个 OOM 触发器。

### 4.7 epoll 事件的 fd → 对象映射

```c
/* Packed into epoll_event.data.u64 */
union ev_token {
    uint64_t u64;
    struct {
        uint32_t slot;          /* index into the pool                      */
        uint16_t generation16;  /* low 16 bits of the object's generation   */
        uint8_t  kind;          /* EV_LISTENER_TCP / EV_LISTENER_UDP /
                                   EV_CONN_CLIENT / EV_CONN_UPSTREAM /
                                   EV_UDP_UPSTREAM / EV_SIGNAL / EV_TIMER   */
        uint8_t  _pad;
    } f;
};
```

见 [10.2](#102-连接释放安全性与-use-after-free) 关于这个设计如何消除 use-after-free。

### 4.8 nftables backend 状态

```c
/* nft_backend.h */
struct nft_handle {
    struct mnl_socket *nl;
    uint32_t           portid;
    uint32_t           seq;
    char               table[64];
    unsigned           have_flowtable:1;
    unsigned           have_hw_offload:1;
    unsigned           table_installed:1;
};

struct sysctl_item {
    const char *path;
    long        orig_value;
    long        want_value;
    int         lock_fd;      /* flock refcount holder, -1 if unavailable */
    unsigned    owned:1;      /* we are the one who changed it            */
    unsigned    present:1;    /* path exists on this kernel               */
};

struct nft_state {
    struct nft_handle   h;
    struct sysctl_item  sysctls[4];
    unsigned            n_sysctls;
    const struct fwd_config *cfg;
};
```

---

## 5. 模块间接口

只列跨模块的公开签名。模块内静态函数不在此。

### 5.1 addr

```c
int      addr_parse(const char *s, union sockaddr_inx *out, int default_family);
int      addr_format(const union sockaddr_inx *sa, char *buf, size_t len);
int      addr_equal(const union sockaddr_inx *a, const union sockaddr_inx *b);
uint32_t addr_hash(const union sockaddr_inx *sa, uint32_t seed);
int      addr_is_wildcard(const union sockaddr_inx *sa);
int      addr_is_local(const union sockaddr_inx *sa);  /* for flowtable warning */
```

### 5.2 config

```c
int  config_parse_argv(int argc, char **argv, struct fwd_config *cfg);
void config_free(struct fwd_config *cfg);
int  config_validate(const struct fwd_config *cfg);   /* mode-independent checks */
void config_dump(const struct fwd_config *cfg, int level);
```

### 5.3 log

```c
enum { LOG_ERROR = 0, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_TRACE };

void log_init(int level, int target /* stderr|syslog */, const char *ident);
void log_emit(int level, const char *fmt, ...) __attribute__((format(printf,2,3)));
int  log_enabled(int level);          /* inlined level check */

#define LOG_E(...) log_emit(LOG_ERROR, __VA_ARGS__)
#define LOG_W(...) log_emit(LOG_WARN,  __VA_ARGS__)
#define LOG_I(...) log_emit(LOG_INFO,  __VA_ARGS__)
#ifdef NDEBUG_TRACE
#  define LOG_D(...) ((void)0)
#  define LOG_T(...) ((void)0)
#else
#  define LOG_D(...) do { if (log_enabled(LOG_DEBUG)) log_emit(LOG_DEBUG, __VA_ARGS__); } while (0)
#  define LOG_T(...) do { if (log_enabled(LOG_TRACE)) log_emit(LOG_TRACE, __VA_ARGS__); } while (0)
#endif
```

### 5.4 sig

```c
int  sig_setup(void);        /* returns a readable fd: signalfd or self-pipe read end */
int  sig_drain(int fd);      /* returns the signal number, or 0 if spurious */
void sig_teardown(int fd);
```

### 5.5 probe

```c
enum probe_severity { PROBE_OK, PROBE_WARN, PROBE_FATAL };

struct probe_entry {
    const char         *name;
    enum probe_severity sev;
    char                detail[256];   /* human-readable, English */
    char                hint[256];     /* what the user should do about it */
};

struct probe_report {
    struct probe_entry entries[32];
    unsigned           n;
    unsigned           n_fatal;
    unsigned           n_warn;
};

void probe_add(struct probe_report *r, const char *name,
               enum probe_severity sev, const char *detail, const char *hint);
int  probe_run_common(const struct fwd_config *cfg, struct probe_report *r);
void probe_report_print(const struct probe_report *r);
```

### 5.6 userspace backend

```c
/* us_loop */
struct us_loop;
struct us_loop *us_loop_new(unsigned max_events);
int  us_loop_add(struct us_loop *l, int fd, uint32_t events, union ev_token tok);
int  us_loop_mod(struct us_loop *l, int fd, uint32_t events, union ev_token tok);
int  us_loop_del(struct us_loop *l, int fd);
int  us_loop_run(struct us_loop *l, int timeout_ms);
void us_loop_defer_free(struct us_loop *l, void *obj, void (*fn)(void *));
void us_loop_flush_deferred(struct us_loop *l);   /* called after each batch */

/* us_tcp */
int  us_tcp_listener_open(const struct fwd_rule *r, const struct fwd_config *c);
int  us_tcp_on_listener(struct us_worker *w, int listen_fd, uint8_t rule_idx);
int  us_tcp_on_event(struct us_worker *w, struct conn *c, int is_upstream, uint32_t ev);
void us_tcp_conn_close(struct us_worker *w, struct conn *c);

/* us_udp */
int  us_udp_listener_open(const struct fwd_rule *r, const struct fwd_config *c);
int  us_udp_on_listener(struct us_worker *w, int listen_fd, uint8_t rule_idx);
int  us_udp_on_upstream(struct us_worker *w, struct udp_session *s);
void us_udp_age_step(struct us_worker *w, uint64_t now_ms, unsigned quota);

/* us_pool */
int   pool_init(struct pool *p, uint32_t nslots, uint32_t obj_size,
                uint32_t gen_off, uint32_t next_off);
void *pool_alloc(struct pool *p);                  /* NULL when exhausted */
void  pool_free(struct pool *p, void *obj);        /* bumps generation    */
void *pool_resolve(struct pool *p, uint32_t slot, uint16_t gen16);  /* NULL if stale */
```

### 5.7 nftables backend

```c
/* nft_batch — thin libmnl wrapper */
struct nft_batch;
struct nft_batch *nft_batch_new(struct nft_handle *h);
int  nft_batch_add_table_del(struct nft_batch *b, const char *table);
int  nft_batch_add_table(struct nft_batch *b, const char *table);
int  nft_batch_add_chain(struct nft_batch *b, const char *table, const char *chain,
                         int hook, int prio, int chain_type);
int  nft_batch_add_flowtable(struct nft_batch *b, const char *table, const char *ft,
                             const char *const *devs, unsigned ndevs, int hw_offload);
int  nft_batch_add_dnat_rule(struct nft_batch *b, const char *table, const char *chain,
                             const struct fwd_rule *r, int proto /* IPPROTO_* */);
int  nft_batch_add_snat_rule(struct nft_batch *b, const char *table, const char *chain,
                             const struct fwd_rule *r, int proto);
int  nft_batch_add_flow_rule(struct nft_batch *b, const char *table, const char *chain,
                             const char *ft);
int  nft_batch_commit(struct nft_batch *b);  /* single sendmsg, then read all acks */
void nft_batch_free(struct nft_batch *b);

/* nft_rules */
int  nft_install(struct nft_handle *h, const struct fwd_config *cfg);
int  nft_uninstall(struct nft_handle *h);

/* nft_stats */
int  nft_read_counters(struct nft_handle *h, struct fwd_stats *out);

/* sysctl */
int  sysctl_acquire(struct sysctl_item *items, unsigned n, const char *run_dir);
void sysctl_release(struct sysctl_item *items, unsigned n);
```

---

## 6. 状态机

### 6.1 TCP 连接状态机

每条连接有两个**独立的方向泵**（`c2u`、`u2c`），连接的整体状态由两个泵的 EOF/shutdown 状态派生。这里给出连接级状态转换表。

| 当前状态 | 事件 | 动作 | 新状态 |
|---|---|---|---|
| — | `accept4()` 成功，`pool_alloc()` 成功 | 创建 2 个 pipe；`socket()`+非阻塞 `connect()` 上游；epoll 注册 upstream `EPOLLOUT` | `CONNECTING` |
| — | `accept4()` 成功，`pool_alloc()` 失败 | `close(client_fd)`，计数 `conn_pool_exhausted++` | — |
| `CONNECTING` | upstream `EPOLLOUT`，`getsockopt(SO_ERROR)==0` | `TCP_NODELAY`；两个泵 `inflight=0`；重算并安装两端 epoll mask | `ESTABLISHED` |
| `CONNECTING` | upstream `EPOLLOUT`，`SO_ERROR != 0` | 记 `INFO` 级日志（限速）；关闭两端 | `CLOSING` |
| `CONNECTING` | upstream `EPOLLERR/EPOLLHUP` | 同上 | `CLOSING` |
| `CONNECTING` | client `EPOLLRDHUP`（客户端提前跑了） | 关闭两端 | `CLOSING` |
| `ESTABLISHED` | src 可读 且 pipe 未满 | `splice(src, pipe_w, SPLICE_F_MOVE\|SPLICE_F_NONBLOCK)`；`inflight += n` | `ESTABLISHED` |
| `ESTABLISHED` | dst 可写 且 `inflight > 0` | `splice(pipe_r, dst, ...)`；`inflight -= n` | `ESTABLISHED` |
| `ESTABLISHED` | 任一 splice 后 | 重算两端 mask；仅当 mask 变化时 `epoll_ctl(MOD)` | `ESTABLISHED` |
| `ESTABLISHED` | `splice(src→pipe)` 返回 0（src EOF） | `pump->src_eof = 1`；**不关闭连接** | `ESTABLISHED`（等排空） |
| `ESTABLISHED` | `src_eof && inflight == 0` （c2u 方向） | `shutdown(upstream_fd, SHUT_WR)`；`c2u.dst_shutdown=1`；关闭 client 的 `EPOLLIN` 关注 | `HALF_C2U` |
| `ESTABLISHED` | `src_eof && inflight == 0` （u2c 方向） | `shutdown(client_fd, SHUT_WR)`；`u2c.dst_shutdown=1` | `HALF_U2C` |
| `HALF_C2U` | u2c 方向仍有数据 | 继续正常泵送 u2c | `HALF_C2U` |
| `HALF_C2U` | u2c `src_eof && inflight == 0` | `shutdown(client_fd, SHUT_WR)` | `CLOSING` |
| `HALF_U2C` | c2u `src_eof && inflight == 0` | `shutdown(upstream_fd, SHUT_WR)` | `CLOSING` |
| 任意 | `EPOLLERR` 或 `splice` 返回 `ECONNRESET`/`EPIPE` | 立即关闭两端（不等排空，对端已经没了） | `CLOSING` |
| 任意 | 空闲超时（仅当 `--tcp-idle-timeout > 0`） | 关闭两端 | `CLOSING` |
| `CLOSING` | 进入 | `epoll_ctl(DEL)` × 2；`close()` × 4（2 socket + 2 pipe 共 4 个 pipe fd → 实际 6 个 fd）；`us_loop_defer_free()` 入队 | — |
| — | 本批 epoll 事件处理完毕 | `us_loop_flush_deferred()`：`pool_free()`，`generation++` | — |

**半关闭传播的必要性**：很多协议（`HTTP/1.0` 无 `Content-Length`、`rsync`、`git` 的部分模式、经典的 `cat | nc`）依赖"单向 EOF 后另一方向继续传输"的语义。如果在收到单向 EOF 时直接 `close()` 整条连接，这些协议会随机截断。**更隐蔽的错误是提前 shutdown**：`src_eof` 已经置位但 `inflight > 0` 时就 `shutdown(dst, SHUT_WR)`，会导致 pipe 中滞留的最后一批数据永远发不出去。所以条件必须是 `src_eof && inflight == 0`。

### 6.2 UDP 会话状态机

| 当前状态 | 事件 | 动作 | 新状态 |
|---|---|---|---|
| — | listener `recvmmsg` 返回一个包，`ht_lookup(client)` 未命中，池未满 | `pool_alloc()`；`socket(remote.family)`；`connect(remote)`；`ht_insert`；epoll 注册 upstream `EPOLLIN` | `ACTIVE` |
| — | 同上但池已满或会话数达上限 | 丢包；`udp_sess_exhausted++`；限速 `WARN` | — |
| — | 同上但 `connect()` 失败 | 丢包；`pool_free`；限速 `INFO` | — |
| `ACTIVE` | listener 收到该 client 的包 | 追加到该会话的发送批；记录 `local`（来自 `IP_PKTINFO` cmsg） | `ACTIVE` |
| `ACTIVE` | 一批 `recvmmsg` 处理完 | 对每个被触及的会话调用 `sendmmsg(upstream_fd, ...)`；`last_activity_ms = now` | `ACTIVE` |
| `ACTIVE` | upstream `EPOLLIN` | `recvmmsg(upstream_fd, batch)`；构造 `mmsghdr[]`，`msg_name = client`，`msg_control = pktinfo(local)`；`sendmmsg(listen_fd, ...)`；`last_activity_ms = now` | `ACTIVE` |
| `ACTIVE` | upstream `EPOLLERR`（ICMP port unreachable 经 connected socket 上报为 `ECONNREFUSED`） | 关闭会话（对 UDP 客户端表现为无响应，符合预期语义） | `EXPIRING` |
| `ACTIVE` | 老化扫描发现 `now - last_activity_ms > udp_timeout_s * 1000` | 从哈希表摘除 | `EXPIRING` |
| `EXPIRING` | 进入 | `epoll_ctl(DEL)`；`close(upstream_fd)`；`us_loop_defer_free()` 入队 | — |
| — | 本批事件处理完毕 | `pool_free()`，`generation++` | — |

**没有"半关闭"概念**：UDP 无连接，会话的唯一终止条件是超时或上游错误。

---

## 7. 启动期能力探测与错误处理策略

**原则**：所有探测在 `fork()` 之前、在建立任何全局副作用之前完成。`--check` 让用户单独跑一遍探测并打印报告后退出，不修改任何系统状态。

**报错格式**（严格遵守，便于 grep 和自动化）：

```
[FATAL] <probe-name>: <what went wrong>
        hint: <what the user should do>
[WARN]  <probe-name>: <what is degraded>
        hint: <what the user should do>
```

任何一条 `FATAL` 都导致 `exit(1)`，且**在退出前打印全部探测结果**（不要遇到第一个错误就退出——用户希望一次看到所有问题）。

### 7.1 通用探测（两模式共用）

| # | 探测项 | 检查方式 | 失败级别 | 错误文本 |
|---|---|---|---|---|
| C1 | `rule syntax` | `addr_parse` 成功；port 非 0 | FATAL | `invalid forward rule 'tcp/0.0.0.0:0->...': listen port must be non-zero` |
| C2 | `duplicate listeners` | 同 (proto, local addr, port) 出现两次 | FATAL | `duplicate listener tcp/0.0.0.0:1022 defined by rules #1 and #3` |
| C3 | `remote resolvable` | `getaddrinfo` 成功（仅当写的是域名） | FATAL | `cannot resolve upstream host 'foo.example': Name or service not known` / hint: `use a literal IP address, or ensure /etc/resolv.conf is populated before startup` |
| C4 | `privileged port` | `port < 1024` 且非 root 且无 `CAP_NET_BIND_SERVICE` | FATAL | `binding to port 80 requires root or CAP_NET_BIND_SERVICE` / hint: `run as root, or: setcap cap_net_bind_service=+ep /usr/sbin/portfwd` |
| C5 | `ipv6 available` | 规则含 IPv6 但 `socket(AF_INET6,...)` 返回 `EAFNOSUPPORT` | FATAL | `rule #2 requires IPv6 but the kernel has no AF_INET6 support` |
| C6 | `run dir writable` | `mkdir` + `open(O_CREAT)` 在 `--run-dir` | WARN | 见 [2.6](#26-sysctl-自动管理nftables-模式) |
| C7 | `pidfile writable` | 同上（仅当指定 `--pidfile`） | FATAL | `cannot create pid file '/run/portfwd.pid': Permission denied` |

### 7.2 `userspace` 模式专有探测

| # | 探测项 | 检查方式 | 失败级别 | 说明 |
|---|---|---|---|---|
| U1 | `fd budget` | `getrlimit(RLIMIT_NOFILE)` vs 计算所需（见 [9.1](#91-fd-预算)） | FATAL 若 hard limit 不足；否则自动 `setrlimit` 抬到 soft=hard 并记 `INFO` | `RLIMIT_NOFILE hard limit 1024 is below the required 24608 fds for max-conns=4096 + udp-max-sessions=8192` / hint: `raise the hard limit (ulimit -Hn) or lower --max-conns / --udp-max-sessions` |
| U2 | `pipe page budget` | 读 `/proc/sys/fs/pipe-user-pages-soft`，与 `max_conns × 2 × (pipe_size/PAGE_SIZE) × workers` 比较 | **FATAL** | 见下方专门说明 |
| U3 | `pipe max size` | 读 `/proc/sys/fs/pipe-max-size`，与 `--pipe-size` 比较 | FATAL | `--pipe-size 1048576 exceeds fs.pipe-max-size (65536)` / hint: `lower --pipe-size or raise fs.pipe-max-size` |
| U4 | `SO_REUSEPORT` | 仅当 `workers > 1`：试建一个 socket 并 `setsockopt` | FATAL | `SO_REUSEPORT is not supported by this kernel; --workers must be 1` |
| U5 | `accept4 / signalfd` | 编译期检测 + 运行时 `ENOSYS` fallback | WARN | 退化到 `accept()+fcntl` / self-pipe |
| U6 | `bind test` | 对每条规则真的 `bind()` 一次（然后保留这个 fd 给 worker 继承，或关闭） | FATAL | `cannot bind tcp/0.0.0.0:1022: Address already in use` |
| U7 | `IPV6_V6ONLY` | 监听 `[::]` 且未指定 `--v6only`：读 `/proc/sys/net/ipv6/bindv6only`，若为 1 则显式 `setsockopt(IPV6_V6ONLY, 0)` | INFO | 记录实际生效的行为 |

#### U2 —— pipe 页配额，一个会静默降级的陷阱

<cite index="23-1">自 Linux 2.6.35 起 pipe 默认容量为 16 页（64 KiB），可用 `fcntl` 的 `F_GETPIPE_SZ` / `F_SETPIPE_SZ` 查询和设置；**自 Linux 4.5 起，当 `pipe-user-pages-soft` 限制被超过时，新建 pipe 的默认容量会低于 16 页**。</cite>

这是本设计中最需要防范的一类失败：**内核不会返回错误，它会静默地把你的 pipe 缩到 1 页**。结果是 splice 的每次搬运量从 64 KiB 掉到 4 KiB，系统调用次数暴涨 16 倍，吞吐量塌方，而日志里什么都看不到。

因此 U2 是 `FATAL` 而非 `WARN`，并且探测方式必须是**实测**而不是算术：

```
create one pipe;
if (pipe_size != default) fcntl(F_SETPIPE_SZ, pipe_size);
actual = fcntl(F_GETPIPE_SZ);
if (actual < pipe_size) -> FATAL
close pipe;
```

再加上一个算术检查作为前置提示：

```
required_pages = workers × max_conns × 2 × (pipe_size / PAGE_SIZE)
soft           = read("/proc/sys/fs/pipe-user-pages-soft")   # default 16384
if required_pages > soft: FATAL
```

默认配置（`workers=1, max_conns=4096, pipe_size=64K`）需要 `4096 × 2 × 16 = 131072` 页，**远超默认 soft limit 16384 页**。这意味着**默认配置下 U2 就会触发**。这是设计上的有意选择：与其让用户在压测时遇到莫名其妙的性能悬崖，不如在启动时就说清楚。

错误文本：

```
[FATAL] pipe page budget: --max-conns 4096 with --pipe-size 65536 requires 131072
        pipe pages, but fs.pipe-user-pages-soft is 16384. The kernel would
        silently shrink new pipes to a single page, collapsing splice throughput.
        hint: raise it (sysctl -w fs.pipe-user-pages-soft=262144), or lower
              --max-conns to 512, or lower --pipe-size to 16384.
```

注意 `pipe-user-pages-soft` 是 **per-uid** 的，多 worker 共享同一个 uid 的配额，所以计算里必须乘 `workers`。

### 7.3 `nftables` 模式专有探测

| # | 探测项 | 检查方式 | 失败级别 | 说明 |
|---|---|---|---|---|
| N1 | **`cross-family`** | 任一规则 `local.family != remote.family` | **FATAL** | 见下方 |
| N2 | `CAP_NET_ADMIN` | `capget()`（或 `/proc/self/status` 的 `CapEff`）检查 bit 12 | FATAL | `nftables mode requires CAP_NET_ADMIN` / hint: `run as root, or: setcap cap_net_admin+ep /usr/sbin/portfwd, or use --mode userspace` |
| N3 | `netlink socket` | `mnl_socket_open(NETLINK_NETFILTER)` | FATAL | `cannot open NETLINK_NETFILTER socket: Protocol not supported` / hint: `kernel lacks nf_tables support; rebuild with CONFIG_NF_TABLES=y or use --mode userspace` |
| N4 | `nf_tables nat` | 提交一个只含 `add table inet <name>-probe` + `add chain type nat hook prerouting` 的事务，检查 ack，然后删除 | FATAL | `kernel does not support nat chains in the inet family` / hint: `CONFIG_NFT_NAT / CONFIG_NF_NAT is missing; use --mode userspace` |
| N5 | `conntrack` | `/proc/sys/net/netfilter/nf_conntrack_max` 存在 | FATAL | NAT 依赖 conntrack；不存在说明模块没加载或没编进内核 |
| N6 | `sysctl writable` | `access("/proc/sys/net/ipv4/ip_forward", W_OK)`（除非 `--no-sysctl`） | FATAL | `cannot write /proc/sys/net/ipv4/ip_forward: Read-only file system` / hint: `use --no-sysctl and enable forwarding yourself` |
| N7 | `flowtable support` | 试建一个 flowtable 对象再删除 | **WARN** | `flowtable not supported (kernel returned EOPNOTSUPP); falling back to the standard forwarding path` |
| N8 | `hw offload` | 带 `flags offload` 再试一次 | **WARN** | 见下方 |
| N9 | `flowtable devices` | `--nft-devices` 未指定时，从 `/proc/net/route` + `/sys/class/net` 推导出通往 local 和 remote 的出入接口 | WARN | 推导失败则不建 flowtable |
| N10 | `dnat target is local` | `addr_is_local(remote)` | WARN | `DNAT target 127.0.0.1:8080 is a local address; traffic will not traverse the forward path and the flowtable fast path will not apply` |
| N11 | `rp_filter` | 读 `/proc/sys/net/ipv4/conf/*/rp_filter`，若为 1（strict）且存在多出口 | INFO | 只提示，不自动改。改 `rp_filter` 的副作用远大于 `ip_forward` |
| N12 | `table name collision` | `--nft-table` 与已有的非本程序 table 同名（通过 dump 检查 comment/userdata 标记） | FATAL | `table inet filter already exists and was not created by portfwd; refusing to delete it` / hint: `pick another name with --nft-table` |

#### N1 —— 跨族在 nftables 模式下必须致命

```
[FATAL] cross-family: rule #1 (tcp/[::]:1701 -> 192.168.1.7:1701) forwards between
        IPv6 and IPv4. nftables DNAT rewrites the destination address within the
        same address family and cannot perform NAT64; there is no rule set that
        implements this. The rules would install successfully and then silently
        drop every packet.
        hint: use --mode userspace, which supports cross-family forwarding.
```

这条错误信息的写法是本设计的一个样板：**说明"为什么"、说明"会发生什么坏事"、给出可执行的替代方案**。"配置成功但流量不通"正是这里要杜绝的东西——如果只是拒绝安装 DNAT 规则而继续运行，用户会看到一个"运行中"的进程和一条不通的链路。

#### N8 —— 硬件 offload 的探测顺序

VyOS 社区总结出的可行判据是：<cite index="7-1">`ethtool -k ethX` 中 `hw-tc-offload` 显示为 `off [fixed]` 就说明网卡不支持硬件 flowtable；能成功 `ethtool -K ethX hw-tc-offload on` 则支持。</cite>

程序不 fork `ethtool`，走同样机制的 ioctl：

```
for each device in nft_devices:
    ETHTOOL_GFEATURES ioctl -> check 'hw-tc-offload' bit and its 'fixed' flag
if any device lacks it -> hw_offload = 0
else -> try installing flowtable with NFTA_FLOWTABLE_FLAGS = NF_FLOWTABLE_HW_OFFLOAD
        if the transaction is rejected -> retry without the flag, log WARN
```

```
[WARN]  hw offload: device eth0 does not support hw-tc-offload; using the
        software flowtable fast path instead.
```

**降级链**：硬件 offload → 软件 flowtable → 无 flowtable（普通 forward 路径）。三级全部只影响性能，不影响正确性，所以全部是 `WARN`。这与 N1/N2/N3 的 `FATAL` 形成清晰对比：**影响正确性的问题致命，影响性能的问题告警**。

### 7.4 `--check` 输出样例

```
$ portfwd --mode nftables -f 'tcp,udp/0.0.0.0:25->8.8.8.8:53' --check
probe: rule syntax                 OK
probe: duplicate listeners         OK
probe: remote resolvable           OK
probe: privileged port             OK    (running as uid 0)
probe: cross-family                OK    (all rules are same-family)
probe: CAP_NET_ADMIN               OK
probe: netlink socket              OK
probe: nf_tables nat               OK    (inet nat chains available)
probe: conntrack                   OK    (nf_conntrack_max=262144)
probe: sysctl writable             OK    (ip_forward=0, will be set to 1)
probe: flowtable support           OK
probe: flowtable devices           OK    (ingress: eth0, eth1)
probe: hw offload                  WARN  eth1 does not support hw-tc-offload
probe: dnat target is local        OK
probe: table name collision        OK
probe: run dir writable            OK    (/run/portfwd)

result: 0 fatal, 1 warning -- configuration is usable
```

---

## 8. 日志策略

### 8.1 级别划分

| 级别 | 语义 | 允许出现的位置 | 例子 |
|---|---|---|---|
| `ERROR` | 影响服务可用性，用户必须知道 | 启动、退出、资源耗尽 | `failed to bind tcp/0.0.0.0:1022: Address already in use` |
| `WARN` | 功能降级但仍工作 | 启动、退出 | `flowtable not supported; falling back to the standard forwarding path` |
| `INFO` | 生命周期事件，正常运行时应当稀疏 | 启动、退出、每 N 秒的统计快照 | `listening on tcp/0.0.0.0:1022 -> 192.168.1.7:22 (worker 0)` |
| `DEBUG` | 每连接/每会话级事件 | **不在包级路径上** | `conn #1234 established: 10.0.0.5:51234 -> 192.168.1.7:22` |
| `TRACE` | 每系统调用级 | 编译期可裁剪 | `splice c2u: 65536 bytes, inflight=65536` |

### 8.2 热路径禁止日志

**规则：`us_tcp_on_event` 和 `us_udp_on_listener` 的主体、以及所有 `splice`/`recvmmsg`/`sendmmsg` 调用点之后，不允许出现任何 `LOG_*` 调用，包括 `LOG_D` 和 `LOG_T`（后两者仅在编译期启用 trace 的调试构建中允许）。**

理由，具体到数字：

1. **每条日志至少一次 `write(2)`**。在 1 Mpps 的 UDP 转发下，每包一条日志 = 每秒 100 万次 `write` + 100 万次 `vsnprintf`。`vsnprintf` 单次约 300–800 ns（含 `inet_ntop` 则超过 1 µs），仅格式化就吃掉 30–80% 的一个 CPU 核，`write` 到磁盘/syslog 更是数量级更高。转发本身每包只花 200–500 ns，日志会成为绝对主导的成本。
2. **日志是被放大的 DoS 面**。攻击者只需用最小尺寸的包（64 字节）打满带宽，就能让程序按包速率写日志。1 Gbps 线速 = 1.48 Mpps = 每秒约 150 MB 日志。磁盘写满、syslog 阻塞、整机不可用——攻击成本极低，收益极高。
3. **日志是隐藏的阻塞点**。写 syslog 走 `/dev/log` 的 unix datagram socket，socket buffer 满时 `sendto` 会阻塞或丢弃；写文件时遇到 page cache writeback 会阻塞。任何阻塞都会传导到 epoll 循环，把一个无锁单线程事件循环变成一个抖动源。

**替代方案**：热路径只更新 `struct fwd_stats` 中的原子性无关计数器（单 worker 内无并发，普通 `uint64_t` 自增即可）。聚合输出通过三个渠道：
- `SIGUSR1` → 触发一次统计快照打印到当前日志目标；
- `--stats-interval SECONDS` → 定时打印 `INFO` 级快照（默认 0，关闭）；
- 退出时打印一次汇总。

### 8.3 限速

即使不在热路径，某些错误也可能高频出现（例如上游持续 `ECONNREFUSED`，每条新连接一条日志）。所有连接级和会话级的错误日志走**令牌桶限速器**：

```c
struct log_rl { uint64_t last_ms; uint32_t tokens; uint32_t suppressed; };
/* 10 tokens, refilled at 1/sec. On the next emitted message, append:
   " (%u similar messages suppressed)" */
```

### 8.4 输出目标

- 前台运行（无 `-d`）：默认 `stderr`，带时间戳与级别前缀。
- `-d`：默认 `syslog`（`LOG_DAEMON` facility，ident `portfwd`）。
- `--log-target` 可强制覆盖。
- **不实现日志文件轮转**。写文件的需求交给 `portfwd ... 2>> /var/log/portfwd.log` 加外部 logrotate，或者直接用 syslog。在程序里做轮转意味着 `stat`+`rename`+`open` 的竞态处理，收益不值。

---

## 9. 资源预算

### 9.1 fd 预算

| 用途 | 每单位 fd 数 | 说明 |
|---|---|---|
| TCP 连接 | **6** | client socket 1 + upstream socket 1 + c2u pipe 2 + u2c pipe 2 |
| UDP 会话 | **1** | connect() 过的上游 socket（listener 是共享的，不计入） |
| TCP listener | 1 × rules × workers | `SO_REUSEPORT` 下每 worker 一个 |
| UDP listener | 1 × rules × workers | 同上 |
| signalfd / self-pipe | 1 或 2 | |
| epoll | 1 | 每 worker |
| timerfd | 1 | 每 worker，驱动老化与统计 |
| netlink (nftables 模式) | 1 | 只在父进程 |

**默认配置下每 worker 的需求**：

```
max_conns        = 4096  →  4096 × 6 = 24576
udp_max_sessions = 8192  →  8192 × 1 =  8192
listeners        = 2 rules × 2 protos =    4
misc (epoll, timerfd, signalfd, stdio) =  8
                                       -------
                          total ≈ 32780 fds per worker
```

`RLIMIT_NOFILE` 的默认 soft limit 通常是 1024（glibc 系发行版）或 1024/4096（OpenWrt），远远不够。因此 U1 探测必须：
1. 读 `getrlimit(RLIMIT_NOFILE)`；
2. 若 `rlim_cur < needed` 且 `rlim_max >= needed`，自动 `setrlimit(rlim_cur = rlim_max)` 并记 `INFO`；
3. 若 `rlim_max < needed`，`FATAL`，并在 hint 中给出两条路：抬高硬上限，或降低 `--max-conns` / `--udp-max-sessions`。

文档中要说明的 `ulimit` 要求：

```
# systemd unit:   LimitNOFILE=65536
# /etc/security/limits.conf:
#   portfwd  soft  nofile  65536
#   portfwd  hard  nofile  65536
# OpenWrt procd:  respawn 段之外加 "limits" 配置，或在 init 脚本里 ulimit -n 65536
```

### 9.2 内存预算（userspace 模式）

**用户态（本进程 RSS 中可控的部分）**

| 项 | 单位大小 | 默认数量 | 合计 |
|---|---|---|---|
| `struct conn` 池 | 128 B | 4096 | 512 KiB |
| `struct udp_session` 池 | 128 B | 8192 | 1024 KiB |
| conn generation 数组 | 4 B | 4096 | 16 KiB |
| session generation 数组 | 4 B | 8192 | 32 KiB |
| UDP 哈希桶数组 | 8 B | 16384 | 128 KiB |
| `epoll_event` 数组 | 12 B | 1024 | 12 KiB |
| recvmmsg 批缓冲（rx） | 2048 B | 32 | 64 KiB |
| sendmmsg 批缓冲（tx） | 2048 B | 32 | 64 KiB |
| `mmsghdr`+`iovec`+`sockaddr`+cmsg 数组 | ~176 B | 64 | 11 KiB |
| 代码 + 静态数据（静态链接 musl，含 nft backend） | — | — | ~300 KiB |
| **每 worker 合计** | | | **≈ 2.2 MiB** |

`--workers 4` 时约 8.8 MiB。对于 128 MiB RAM 的 OpenWrt 设备完全可接受；对 32 MiB 的老设备需要把 `--max-conns` 降到 512、`--udp-max-sessions` 降到 1024，届时约 500 KiB/worker。

**内核态（不计入 RSS，但真实消耗内存）**

| 项 | 估算 |
|---|---|
| TCP socket 结构（`sock` + `tcp_sock`） | ~2 KiB × 2/连接 |
| TCP 收发缓冲（`net.ipv4.tcp_rmem` 默认 4K/128K/6M，autotuned） | 空闲 ~8 KiB，繁忙可达 数百 KiB–数 MiB / 连接 |
| pipe buffer（**惰性分配**，只有实际写入的页才占内存） | 峰值 `2 × pipe_size` = 128 KiB/连接，空闲时接近 0 |
| UDP socket 结构 | ~1.5 KiB / 会话 |
| `pipe_buffer` 数组（slab） | 16 槽 × 40 B = 640 B，落在 `kmalloc-1k` |

<cite index="26-1">默认 65536 字节容量对应 16 页，其 `pipe_buffer` 数组有 16 个元素、分配在 `kmalloc-1k` slab 中（16 × 40 = 640 字节）；内核会把 `F_SETPIPE_SZ` 请求的大小向上取整到 2 的幂页数，`fs/pipe-max-size` 默认 1048576 字节（256 页），最小容量为 1 页。</cite>

**关键结论**：4096 条满速运行的 TCP 连接，内核侧可能占用 `4096 × (4 KiB sock + ~128 KiB pipe + ~200 KiB socket buffer)` ≈ **1.3 GiB**。这不是本程序能控制的，但**必须写进文档**：`--max-conns` 的合理值由机器内存而不是 fd 上限决定。OpenWrt 上的推荐值是 `--max-conns 256 --pipe-size 16384`。

### 9.3 内存预算（nftables 模式）

进程本身几乎不占内存：一个 mnl socket + 配置结构，RSS < 1 MiB（静态链接 musl）。内核侧成本是 conntrack 表项：每条约 **300–400 字节**（`nf_conn` + `nf_conn_nat` + extensions）。`nf_conntrack_max` 默认按内存推算，典型 x86_64 服务器上是 262144，对应约 100 MiB。这是系统级配额，本程序不修改它（改动会影响机器上所有 netfilter 用户），只在 N5 探测时读出来并记入 `INFO`。

### 9.4 二进制体积

| 构建 | 链接 | 估算（stripped） |
|---|---|---|
| userspace only | 静态 musl | ~60 KiB |
| userspace only | 动态 glibc | ~35 KiB |
| 全功能 | 动态（libmnl + libnftnl 外部） | ~55 KiB + 依赖 205 KiB |
| 全功能 | 静态 musl（含 libmnl/libnftnl） | ~260 KiB |

OpenWrt package 建议 `DEPENDS:=+libnftnl`（走系统共享库），ipk 尺寸约 30 KiB。

---

## 10. 关键性能决策及其理由

### 10.1 splice + inflight 驱动的 epoll 掩码（最重要的一条）

每个方向泵维护 `inflight`（pipe 中滞留的字节数），epoll 事件掩码**完全由 inflight 派生**：

```
src_wants_read  = (!src_eof) && (inflight < pipe_capacity)
dst_wants_write = (inflight > 0)

client_mask   = EPOLLRDHUP
              | (c2u.src_wants_read  ? EPOLLIN  : 0)
              | (u2c.dst_wants_write ? EPOLLOUT : 0)
upstream_mask = EPOLLRDHUP
              | (u2c.src_wants_read  ? EPOLLIN  : 0)
              | (c2u.dst_wants_write ? EPOLLOUT : 0)
```

**不这样做会发生什么（必须理解的失败模式）**：

假设一直注册 `EPOLLIN | EPOLLOUT`，用水平触发（LT）。考虑客户端快速发送、上游读取缓慢的场景：

1. splice 把数据从 client 搬进 c2u pipe，pipe 满（`inflight == 65536`）。
2. client socket 的接收缓冲里还有数据 → epoll 仍然报告 `EPOLLIN`。
3. 处理 `EPOLLIN` → `splice(client, pipe_w)` 返回 `EAGAIN`（pipe 满）。
4. 回到 `epoll_wait` → 立即再次返回同一个 `EPOLLIN`（LT 语义：条件仍然成立）。
5. **回到第 3 步。**

这是一个纯粹的忙循环：`epoll_wait` 立即返回、`splice` 立即 `EAGAIN`、循环。**单条这样的连接就能把一个 CPU 核跑满 100%**。同样的情况对称地出现在 `EPOLLOUT` 上：pipe 空时如果还注册着 dst 的 `EPOLLOUT`，只要 dst 可写就会无限唤醒。

同一个坑对边缘触发（ET）来说形态不同但同样致命：ET 下如果没有正确处理"因为 pipe 满而没读干净 src"的情况，src 的可读边沿已经消费掉了，pipe 腾空后再没有新数据到达 → **连接永久挂死**。

**所以 inflight 驱动的掩码不是优化，是正确性要求。** 本设计用**水平触发 + 精确掩码**，因为 LT 的失败模式（烧 CPU）比 ET 的失败模式（静默挂死）更容易在测试中被发现，且 LT 下不需要"循环读到 EAGAIN"的额外逻辑。唯一的例外是 listener socket，那里用 `accept4` 循环到 `EAGAIN`（避免每次 `epoll_wait` 只处理一条新连接）。

**只在掩码变化时调用 `epoll_ctl`**：

```c
if (new_mask != conn->client_events) {
    epoll_ctl(epfd, EPOLL_CTL_MOD, conn->client_fd, &ev);
    conn->client_events = new_mask;
}
```

在大流量稳定传输时，掩码在连续多次 splice 之间通常不变（pipe 既不空也不满），这条判断把 `epoll_ctl` 的调用量减少一个数量级以上。`epoll_ctl` 要拿 `ep->mtx`、走红黑树查找、可能触发 `ep_modify` 的 wakeup 逻辑，单次约 200–400 ns——在每秒百万次 splice 的量级上不可忽略。

### 10.2 连接释放安全性与 use-after-free

**问题**：一次 `epoll_wait` 返回 N 个事件。事件 `i` 是连接 C 的 `client_fd` 出错，处理它时释放了 C。事件 `j > i` 恰好是 **同一个连接 C** 的 `upstream_fd`（同一批中两个 fd 同时就绪是完全正常的）。此时 `events[j].data.ptr` 指向已经被 `pool_free` 的对象——**use-after-free**。

如果 `pool_free` 之后立刻有新连接复用了同一个 slot，情况更糟：事件 `j` 会被错误地施加到一条**无关的新连接**上，造成串流（把 A 的数据写进 B 的 socket）。这是最难调试的一类 bug——不崩溃，只是偶尔数据错乱。

> 这是 `rssnsj/portfwd` 中存在的真实缺陷类别，必须在本项目中从第一行数据面代码起就防住。

**三种可选方案**：

| 方案 | 机制 | 优点 | 缺点 |
|---|---|---|---|
| A. 完整扫描同批事件 | 释放前遍历 `events[i+1..n]`，把指向 C 的项标记为已处理 | 直观 | O(N) 扫描/释放；短连接洪泛下 N=1024 时是每次释放 1024 次比较 |
| B. generation 计数 | `epoll_data` 存 `(slot, generation)`；`pool_free` 时 `generation++`；解析事件时校验 | O(1)；无额外内存；同时防住"slot 被新对象复用"的串流 | 需要把 `data.ptr` 改成 `data.u64` 并打包 |
| C. 延迟释放队列 | 释放时只入队，本批事件处理完后统一 `pool_free` | 简单；对象在整批期间保持有效 | 单独用它不够——入队后对象仍在，事件 `j` 会对一个"正在关闭"的对象执行 splice |

**决策：B + C 组合。**

```
on_event(tok):
    obj = pool_resolve(pool, tok.f.slot, tok.f.generation16);
    if (!obj) return;                    /* stale event, skip silently */
    if (obj->state == CONN_CLOSING) return;  /* queued for free this batch */
    ... handle ...

close_conn(c):
    epoll_ctl(DEL) × 2;  close() × 6;
    c->state = CONN_CLOSING;
    us_loop_defer_free(loop, c, conn_free_fn);   /* C: defer */

after the whole event batch:
    for each queued obj:  pool->generation[slot]++;  push to freelist;   /* B: bump */
```

- **C 保证**：同批内不会有新对象占用该 slot（因为对象还没回到 freelist），所以同批的陈旧事件最多命中"正在关闭"的对象，被 `state == CLOSING` 挡掉。
- **B 保证**：跨批次的陈旧事件（比如某些边角情况下 `epoll_ctl(DEL)` 之后仍有排队事件）被 generation 挡掉，且 slot 复用后不会串流。
- generation 只存低 16 位。16 位回绕需要同一个 slot 被复用 65536 次才可能碰撞，而碰撞窗口是"一批 epoll 事件"（微秒级）。在这个窗口内同一 slot 复用 65536 次在物理上不可能。用 16 位是为了把 token 塞进 64 位（32 slot + 16 gen + 8 kind + 8 pad），避免额外的间接寻址。

**方案 A 被否决的理由**：它是 O(N) 的，且只解决同批问题、不解决 slot 复用串流问题。B+C 是 O(1) 且覆盖面更广。

### 10.3 SO_REUSEPORT 与 worker 模型

**模型**：`fork()` 出 N 个 worker，每个 worker **各自** `socket()` + `setsockopt(SO_REUSEPORT)` + `bind()` + `listen()`，各自持有独立的 epoll、独立的对象池、独立的 UDP 会话表。**worker 之间零共享、零锁、零 IPC。** 父进程只负责 `waitpid` 和信号转发。

**`SO_REUSEPORT` 的前置条件（必须写进文档）**：

1. **必须在 `bind()` 之前 `setsockopt`**。已经 bind 过的 socket 上设置无效。
2. **所有共享同一端口的 socket 都必须设置该选项**——包括第一个。如果第一个 socket 忘了设，后续的会拿到 `EADDRINUSE`。
3. **effective UID 必须一致**。这是内核的安全检查：防止非特权用户"抢占"特权用户已经监听的端口。因此**如果程序要降权（`setuid`），必须在所有 worker 都创建完 socket 之后，或者所有 worker 用相同的目标 uid 降权后再创建**。本设计选择前者：父进程以启动 uid 创建所有 listener → `fork` → 每个 worker 继承并可选降权。实际上更简单的做法是：**每个 worker 在 `fork()` 之后、降权之前建立自己的 listener**，因为此时所有 worker 的 euid 都还等于父进程的 euid。
4. 内核 ≥ 3.9（TCP）/ ≥ 3.9（UDP）。所有目标平台满足，但仍在 U4 中显式探测。

**UDP + SO_REUSEPORT 的分发语义 —— 确认并说明其影响**：

内核对 `SO_REUSEPORT` 组内的 socket 使用基于**四元组**（源 IP、源端口、目的 IP、目的端口）的哈希来选择接收 socket。对同一个客户端 `(cip, cport)` 发往同一个 `(lip, lport)` 的所有包，哈希输入完全相同 → **稳定落到同一个 worker**。

**这一点对设计的影响是决定性的**：

- UDP 会话表可以是 **per-worker 的完全私有结构**，无锁、无原子操作、无 false sharing。
- 会话对象池同样 per-worker。
- 不需要任何跨 worker 的会话迁移、锁或消息传递。
- 每个 worker 的 `udp_max_sessions` 是**独立**的配额，总容量 = `workers × udp_max_sessions`。这要写进文档，否则用户会以为 `--udp-max-sessions 8192 --workers 4` 是总共 8192。

**但有两个必须记录的限制**：

1. **worker 增减会打乱哈希分发**。本设计不支持运行期改变 worker 数（无热重载），所以不受影响。但要写进文档：改 `--workers` 需要重启，重启期间已有 UDP 会话全部丢失。
2. **`SO_REUSEPORT` 组内某个 socket 关闭时**，内核会重新计算分发，已有流可能被重定向到另一个 socket。对 TCP 来说这意味着"某个 worker 崩溃时，其未 accept 的 SYN 队列里的连接会丢失"。本设计接受这一点：worker 崩溃是 bug，不是常规路径。

### 10.4 UDP 会话老化用增量遍历

**朴素做法**：每 `T` 秒扫描整张哈希表，比较 `last_activity_ms`。16384 个桶 + 8192 个会话 → 每次扫描约 24576 次内存访问，其中大部分是 cache miss（桶数组 128 KiB 已超 L2）。单次扫描约 200–500 µs。

**问题不在于总开销**（500 µs / 30 s = 0.002% CPU），**而在于它是一个周期性的、不可抢占的停顿**。在这 500 µs 里，epoll 循环不处理任何包。对 1 Mpps 的流量，这意味着每 30 秒有 500 个包排在 socket buffer 里等待——表现为**周期性的延迟尖刺**（p99.9 从 50 µs 跳到 500 µs）。对 VoIP、游戏、VPN 这类 UDP 的典型用户，周期性尖刺比平均延迟高更难受。

**设计**：静态游标 + 固定配额的增量遍历。

```c
void us_udp_age_step(struct us_worker *w, uint64_t now_ms, unsigned quota)
{
    struct udp_table *t = &w->udp_ht;
    for (unsigned i = 0; i < quota; i++) {
        uint32_t b = t->sweep_cursor;
        t->sweep_cursor = (t->sweep_cursor + 1) & t->mask;
        /* walk chain at bucket b, expire entries older than the timeout */
    }
}
```

- 由 `timerfd` 每 **100 ms** 触发一次，每次处理 `quota = nbuckets / 64` = 256 个桶。
- 全表扫描周期 = 64 × 100 ms = **6.4 秒**。会话的实际过期时间因此在 `[timeout, timeout + 6.4s]` 区间——对 60 秒的超时来说，最多 10.7% 的误差，完全可接受。
- 每次的停顿从 500 µs 降到 **~8 µs**，落在噪声水平以下。
- 游标是 worker 私有的 `uint32_t`，跨 timer tick 保持，天然做到"续扫"。

**为什么不用最小堆或时间轮**：都需要在**每个包**上做一次数据结构操作（更新会话的到期时间 → 堆调整 / 时间轮迁移）。增量扫描把成本从热路径（每包）转移到冷路径（每 100 ms），这正是我们想要的方向。8 µs/100 ms = 0.008% CPU。

### 10.5 不重试、不做健康检查（Q5）

**结论：userspace 模式下上游连接失败时不重试；转发器不提供健康检查。**

理由：

1. **重试会破坏 TCP 语义**。当上游 `connect()` 失败时，客户端**已经完成了与本程序的三次握手**——从客户端视角，连接是建立的。此时重试意味着客户端会经历一段"连接已建立但没有任何响应"的时间。如果重试最终也失败，我们只能发 RST，客户端看到的是"连接建立后被重置"而不是"连接被拒绝"。**后者是准确的信息，前者是误导。** 一个透明的 L4 管道应当尽可能忠实地传递失败语义：上游拒绝 → 我们 RST；上游超时 → 我们也让客户端超时。
2. **重试会引入放大**。一个不可达的上游 + 一批客户端重连 = 每个客户端连接产生 K 次上游 SYN。这把一个"上游挂了"的局部故障放大成对上游的 SYN flood。
3. **健康检查属于负载均衡器的职责**。健康检查的唯一用途是"从多个后端中剔除坏的"。本项目只有**一个**后端（见 N6），剔除它等于停止服务——那还不如让流量打过去，让客户端自己看到失败。做一个"检查完了发现挂了，然后仍然把流量发过去"的健康检查，是纯粹的复杂度。
4. **UDP 上更无意义**。UDP 无连接，`connect()` 只是设置默认目的地，几乎不会失败（除非路由不可达立即返回 `ENETUNREACH`）。此时丢包并计数是唯一正确的行为。

**唯一的例外：DNS 解析**。如果上游写的是域名，第一版**只在启动时解析一次**并固化到 `struct fwd_rule`。这是有意的简化，必须写进文档：

```
NOTE: The upstream host is resolved once at startup. If the address changes
      (DNS-based failover, dynamic DNS), restart portfwd to pick it up.
```

理由：运行期重解析需要处理"解析期间阻塞事件循环"（`getaddrinfo` 是同步阻塞的，且可能耗时秒级）——要么开线程，要么自己实现异步 DNS，两者都与"无重量级依赖、单线程无锁"的定位冲突。列入"未来演进"。

**TCP 空闲超时（Q4 的一半）：默认关闭（`--tcp-idle-timeout 0`）。**

理由同上：转发器不该比端点更聪明。一条空闲 12 小时的 SSH 连接是完全正常的；一个自作主张关掉它的转发器会激怒用户。但提供这个选项，因为 fd 是有限资源，某些部署（公网暴露、大量半死连接）需要兜底。

**同时默认开启 TCP keepalive**（`SO_KEEPALIVE` + `TCP_KEEPIDLE=600, TCP_KEEPINTVL=60, TCP_KEEPCNT=3`）。这是**不同性质的机制**：keepalive 检测的是"对端已经不存在了"（机器崩溃、网络中断，没有 FIN/RST 到达），而空闲超时杀的是"对端还在但没说话"的连接。前者回收的是真正的僵尸 fd，后者破坏正常语义。**回收僵尸，不杀活人。**

### 10.6 pipe 大小（Q3）

**结论：默认 65536 字节（内核默认值），不做自适应。**

参数空间：

| 场景 | pipe 越大 | pipe 越小 |
|---|---|---|
| 大带宽、少连接（如 10 Gbps 单流备份） | 每次 splice 搬运更多字节 → 系统调用次数下降 → CPU 下降。1 MiB pipe 相比 64 KiB，syscall 次数减少 16 倍 | syscall 密集，CPU 成为瓶颈 |
| 海量短连接（如 HTTP 代理，每连接几 KiB） | **纯浪费**：pipe 页配额按容量记账而非实际使用记账，`max_conns` 被 `pipe-user-pages-soft` 卡死；内核 `pipe_buffer` 数组也按容量分配 | 每连接只用 1–2 页，配额压力小 |
| 延迟敏感 | 无影响（splice 不引入缓冲延迟，pipe 只是中转，有数据就往下游推） | 无影响 |

关键约束来自 [7.2 U2](#u2--pipe-页配额一个会静默降级的陷阱)：`pipe-user-pages-soft` 默认 16384 页 = 64 MiB，而每连接需要 `2 × pipe_size / 4096` 页。

| pipe_size | 页/连接 | 默认 soft limit 下的最大连接数 |
|---|---|---|
| 4 KiB | 2 | 8192 |
| 16 KiB | 8 | 2048 |
| **64 KiB（默认）** | **32** | **512** |
| 256 KiB | 128 | 128 |
| 1 MiB | 512 | 32 |

**选择 64 KiB 作为默认值的理由**：
1. 它是内核默认值，意味着**不调用 `F_SETPIPE_SZ`** 就能拿到。少一次系统调用/连接，也少一个失败点。
2. 64 KiB 已经足以让 10 GbE 上的单流达到线速——每次 splice 搬 64 KiB，10 Gbps 需要约 19000 次/秒 splice pair，即约 38000 syscall/s，在现代 CPU 上不到一个核的 5%。继续加大到 1 MiB 只能把这个数字从 5% 降到 1%，收益递减。
3. 它把"用户必须调 sysctl"的门槛推迟到 512 连接以上，覆盖了绝大多数实际部署。

**关于自适应：不做。** 三个理由：
1. `F_SETPIPE_SZ` **不能缩小到低于 pipe 中现有数据量**，所以"先大后小"的自适应会在高负载时失败。
2. 每次调整都是一次系统调用 + 内核重新分配 `pipe_buffer` 数组（可能失败），在连接生命周期中做这件事引入了新的错误路径。
3. 用户比程序更清楚自己的场景。一个 `--pipe-size` 参数加上文档里那张表，比一个猜错了还很难调试的启发式算法更有价值。

**列入"未来演进"的折中方案**：单向"懒放大"——连接累计传输量首次超过 4 MiB 时，一次性把该方向的 pipe 放大到 `--pipe-size-max`，之后不再调整。这抓住了"少数大流连接 + 多数小流连接"的真实分布，且只放大不缩小，避开了上述第 1 点。但这是优化，不进第一版。

### 10.7 nftables 模式下的统计（Q7）

**结论：用 nftables 内建的 `counter` 表达式提供包/字节统计；不实现 ctnetlink 连接数统计。**

**做什么**：
- 每条 DNAT 规则和每条 SNAT 规则前挂一个 `counter` 表达式（在规则 expression 链里插入 `nft_expr("counter")`）。
- `SIGUSR1` 或 `--stats-interval` 触发时，通过 `NFT_MSG_GETRULE` dump 本程序自己的 table，解析每条规则的 counter 属性（`NFTA_COUNTER_PACKETS` / `NFTA_COUNTER_BYTES`），按规则聚合输出。
- 成本：一次 netlink dump，规则数固定（每规则每协议 3 条），返回数百字节。可以每秒做一次都不心疼。
- 输出与 userspace 模式的统计**格式一致**，用户切换模式时不用改监控脚本。

```
[INFO] stats rule#0 tcp/0.0.0.0:1022->192.168.1.7:22
       in: 1234567 pkts / 987654321 bytes   out: 1234000 pkts / 12345678 bytes
```

**不做什么：ctnetlink 连接数。**

代价分析：
- 通过 `NFNL_SUBSYS_CTNETLINK` 的 `IPCTNL_MSG_CT_GET` **dump 整张 conntrack 表**，然后在用户态过滤出目的地址等于我们 DNAT 目标的表项。
- 表项数是**全机器的**，不是我们的。`nf_conntrack_max` 默认 262144，在一台繁忙的网关上实际条目数可能是十万量级。每次 dump 要通过 netlink 传输数十 MiB 并逐条解析。
- 这个开销是 O(全机器连接数)，与我们关心的数据量（我们自己的连接数）完全无关。为了得到一个整数而遍历十万条记录，性价比是负的。
- 还需要 `nf_conntrack_netlink` 模块，OpenWrt 上默认不装（`kmod-nf-conntrack-netlink` 是单独的 package），会给"零依赖单二进制"的定位打洞。

**替代**：如果用户确实需要连接数，`conntrack -L -d <target> | wc -l` 或 `cat /proc/sys/net/netfilter/nf_conntrack_count`（全局值）已经足够，且是用户按需付费而不是我们无条件付费。文档里给出这两条命令即可。

**列入"未来演进"**：ctnetlink **事件订阅**（`NF_NETLINK_CONNTRACK_NEW` / `_DESTROY` 多播组）是 O(事件) 而非 O(表大小)，可以维护一个精确连接计数器而无需 dump。但它需要程序常驻处理事件流，且在高连接速率下事件本身就是负载。留待有明确需求时再评估。

### 10.8 两模式共享配置解析与地址抽象（Q8）

**结论：共享。边界画在 `struct fwd_rule`。**

共享的部分：
- `config.c` —— CLI 解析、默认值、`struct fwd_config` / `struct fwd_rule` 构造。
- `addr.c` —— `sockaddr_inx` 及其宏，地址解析与格式化。
- `log.c`、`sig.c`、`probe.c`（框架部分）、`util/`。
- `main.c` 的顶层生命周期：解析 → 通用探测 → backend 探测 → daemonize → setup → run → teardown → exit。

不共享的部分：
- 数据面代码（`us/` 与 `nft/` 互不 include）。
- backend 专有探测（`probe_userspace()` / `probe_nftables()`，各自实现，通过 `struct fwd_backend::probe` 挂进来）。
- 统计的**采集**方式（一个是进程内计数器，一个是 netlink dump），但统计的**输出格式**共享。

**为什么这个边界是对的**：`struct fwd_rule` 描述的是"把 X 转发到 Y"这一**意图**，它对两种实现方式都成立且完全相同。往下一层就分叉了：userspace 需要的是 listener fd 和 pipe，nftables 需要的是 chain 和 expression 链——这两者之间没有任何可复用的东西，强行抽象只会造出一层没有内容的间接。

**一个具体的好处**：因为地址解析是共享的，`--mode nftables` 下解析出的 `cross_family` 标志可以在 backend 探测中直接判定并给出"请用 `--mode userspace`"的提示。如果两个 backend 各解析各的，这条跨模式的建议就写不出来。

**一个具体的约束**：`struct fwd_rule` 里不允许出现任何 backend 专有字段。nftables 需要的 chain handle、userspace 需要的 listener fd，都存在各自的 backend state 里，用 `rule_idx` 关联。

### 10.9 UDP 批大小（`--batch-size`）

`recvmmsg`/`sendmmsg` 的批大小是**吞吐与延迟的直接权衡**：

| 批大小 | 每包摊薄的 syscall 成本 | 最坏情况附加延迟 | 内存 |
|---|---|---|---|
| 1（退化为 recvmsg） | ~600 ns/包 | 0 | 2 KiB |
| 8 | ~90 ns/包 | 7 包的到达间隔 | 16 KiB |
| **32（默认）** | **~30 ns/包** | 31 包的到达间隔 | 64 KiB |
| 128 | ~15 ns/包 | 127 包的到达间隔 | 256 KiB |
| 1024 | ~10 ns/包 | 1023 包的到达间隔 | 2 MiB |

**关键点：`recvmmsg` 在没有 `MSG_WAITFORONE`/超时的非阻塞模式下不会等待**——它返回**当前 socket buffer 里已有的**包，最多 `vlen` 个。所以批大小**不引入排队延迟**：低速率时每次返回 1–2 个包并立即转发，高速率时才真正批到 32 个。上表中的"最坏情况附加延迟"只在"内核 buffer 里已经积压了一批"时才出现，而那种情况下延迟已经由积压决定，与批大小无关。

因此选择 32 的理由是：
1. 收益曲线在 32 附近明显变平（30 ns → 15 ns 的改善不如 90 ns → 30 ns 显著）。
2. 64 KiB 的批缓冲刚好落在 L2 cache 内（典型 L2 是 256 KiB–1 MiB），rx + tx 共 128 KiB 仍然舒适。批到 1024 时 2 MiB 缓冲会把 L2 冲刷干净，反而变慢。
3. 缓冲区按 2048 字节/包分配，足以容纳标准 MTU 下的任何 UDP 载荷。**巨帧（jumbo frame）场景需要 `--mtu` 调整**——第一版不支持，超过 2048 字节的包会被 `recvmmsg` 截断并设置 `MSG_TRUNC`，此时**必须丢弃该包并计数**，绝不能转发一个被截断的 UDP 报文。这是必须显式处理的正确性问题。

### 10.10 `IP_PKTINFO` / `IPV6_RECVPKTINFO`（必须，不是可选）

**问题场景**：机器有两个 IP，`10.0.0.1` 和 `10.0.1.1`。程序监听 `0.0.0.0:1701`。客户端向 `10.0.1.1:1701` 发包。

**不设置 `IP_PKTINFO` 时**：程序用同一个 listener socket `sendto()` 回包，源地址由**路由表**决定——很可能是 `10.0.0.1`（默认路由的出口地址）。客户端收到一个来自 `10.0.1.1:1701` 的请求的响应，源地址却是 `10.0.0.1:1701`。**客户端的 socket 是 connect 到 `10.0.1.1:1701` 的，四元组不匹配，内核直接丢弃这个包。** 客户端表现为"超时"，抓包能看到响应确实到了——这是极难诊断的故障。

同样的问题也出现在：多网卡、VRRP/keepalived 的浮动 IP、anycast 部署、云上的多 ENI。

**解决**：
```
setsockopt(fd, IPPROTO_IP,   IP_PKTINFO,       1)   /* AF_INET  */
setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)   /* AF_INET6 */
```
- 收包时从 `recvmmsg` 的 `msg_control` 中解析 `IP_PKTINFO` cmsg，取出 `ipi_addr`（包的实际目的地址）和 `ipi_ifindex`，存入 `udp_session::local`。
- 回包时在 `sendmmsg` 的 `msg_control` 里放一个同类型的 cmsg，把 `ipi_spec_dst` 设为存下来的地址。内核会用它作为源地址。

**注意 v4-mapped 情况**：监听 `[::]` 且未设 `IPV6_V6ONLY` 时，IPv4 客户端的包会以 v4-mapped 形式（`::ffff:10.0.1.1`）出现，cmsg 类型是 `IPV6_PKTINFO` 而不是 `IP_PKTINFO`，其中的地址也是 v4-mapped。回包时同样用 `IPV6_PKTINFO`，内核会正确处理。这条要在代码里加注释，否则很容易写出"只处理 `IP_PKTINFO`"的分支从而在 dual-stack listener 上失效。

**cmsg 缓冲区大小**：每条消息需要 `CMSG_SPACE(sizeof(struct in6_pktinfo))` = 32 字节（`in6_pktinfo` 是 20 字节，`in_pktinfo` 是 12 字节，按大的算）。批大小 32 → 1 KiB 的 cmsg 缓冲。

### 10.11 其他 socket 选项

| 选项 | 何处 | 理由 |
|---|---|---|
| `TCP_NODELAY` | 两端 socket | 转发器**不知道**载荷的语义，不能替应用做"攒一攒再发"的决定。Nagle 与延迟 ACK 交互产生的 40 ms 停顿是经典故障。转发器必须是透明的：收到什么立刻发什么。 |
| `IP_BIND_ADDRESS_NO_PORT` | 上游 socket，仅当需要 `bind()` 到特定源地址时 | 不设置时，`bind(src_addr, port=0)` 会**立即**分配一个源端口，此时内核只知道源地址，必须保证 `(src_addr, sport)` 在所有可能的目的地上唯一 → 可用端口数 ≈ 28000。设置后端口分配推迟到 `connect()`，内核知道完整四元组，可以让同一个源端口对不同目的地复用 → 可用组合数暴增。**没有它，单目标转发在 3 万并发连接附近会开始 `EADDRNOTAVAIL`。** |
| `SO_REUSEADDR` | listener | 允许在 `TIME_WAIT` 状态残留时重启 |
| `SO_REUSEPORT` | listener，`workers > 1` 时 | 见 [10.3](#103-so_reuseport-与-worker-模型) |
| `SOCK_NONBLOCK\|SOCK_CLOEXEC` | 所有 socket，通过 `accept4`/`socket` 的 flags | 省掉两次 `fcntl`；`CLOEXEC` 避免 fd 泄漏到 `daemonize` 后可能的子进程 |
| `O_NONBLOCK\|O_CLOEXEC` | 所有 pipe，通过 `pipe2` | 同上。**pipe 必须非阻塞**，否则 `splice` 在 pipe 满时会阻塞整个事件循环 |
| `SO_KEEPALIVE` + `TCP_KEEP*` | 两端 socket | 见 [10.5](#105-不重试不做健康检查q5) |
| `IPV6_V6ONLY = 0` | `[::]` listener，除非 `--v6only` | 一个 listener 同时接受 IPv4（v4-mapped）与 IPv6。**必须显式设置为 0**，不能依赖默认值——`/proc/sys/net/ipv6/bindv6only` 在部分发行版上是 1 |

### 10.12 worker 进程数默认值（Q2）

**结论：默认 `--workers 1`。`--workers auto` 解析为 `min(nproc, 4)`。**

理由：

1. **绝大多数部署场景根本达不到单核瓶颈**。OpenWrt 路由器上转发的是家庭宽带流量（几百 Mbps）；小型 VPS 上转发的是几十到几百条连接。单个 splice 循环在这些负载下 CPU 占用在个位数百分比。默认开 4 个 worker 只是把 4 份内存池和 4 份会话表常驻内存里。
2. **多 worker 有实实在在的代价**：
   - 内存：每 worker ~2.2 MiB（见 [9.2](#92-内存预算userspace-模式)）。
   - fd：listener 数 × workers。
   - `pipe-user-pages-soft` 配额按 uid 计，worker 数直接乘上去。
   - UDP 会话配额被分片：`--udp-max-sessions 8192 --workers 4` 意味着**每个 worker** 8192，但如果流量分布不均（某个大客户端的所有会话都哈希到 worker 0），worker 0 会先耗尽，而其他 worker 还空着。**单 worker 没有这个问题。**
   - 统计需要跨 worker 聚合（第一版通过退出时各自打印 + 用户自行相加解决，很粗糙）。
3. **`nproc` 不是一个好的默认值**。在一台 64 核的服务器上 fork 64 个 worker 意味着 140 MiB 常驻内存和 64 × 32780 个 fd 预算——对一个"端口转发小工具"来说完全失调。而且超过网卡 RSS 队列数之后，多出来的 worker 只是在争抢同一批中断。
4. **`auto` 上限设为 4**：`min(nproc, 4)` 覆盖了"我确实需要多核但懒得算"的场景，同时避免了在大机器上的失控。用户真的需要 16 个 worker 时可以显式写 `--workers 16`——那时他知道自己在做什么。

**文档里给出的调优指引**：

```
Start with the default (1 worker). Raise it only when a single worker's CPU
usage approaches 100%:  top -H -p $(pidof portfwd)
Rule of thumb: one worker per ~5 Gbit/s of TCP throughput, or per ~500 Kpps
of UDP traffic. Never exceed the number of NIC RX queues (ls /sys/class/net/
eth0/queues/ | grep -c '^rx-').
```

### 10.13 UDP 会话超时默认值（Q4 的另一半）

**结论：`--udp-timeout 60`（秒）。**

参考点：
- `nf_conntrack_udp_timeout` 默认 **30 秒**（未见双向流量的"单向"UDP 流）。
- `nf_conntrack_udp_timeout_stream` 默认 **120 秒**（已见双向流量的流）。
- DNS 查询：单次往返，1 秒内结束，超时值对它无影响（只影响 fd 占用多久）。
- WireGuard：默认 keepalive 是 25 秒（`PersistentKeepalive`），需要 timeout > 25。
- L2TP/IPsec：keepalive 通常 30–60 秒。
- 在线游戏：包间隔通常 < 1 秒。
- SIP：注册刷新典型 60–3600 秒，但媒体流（RTP）是 20 ms 间隔。

60 秒的位置：
- 大于 WireGuard 的 25 秒 keepalive，不会误杀。
- 大于 conntrack 的 30 秒单向超时，与内核行为一致但更宽松（我们的会话对象比 conntrack 表项贵——一个 fd + 128 字节 vs 350 字节，所以我们不能比它更宽松太多）。
- 小于 120 秒，避免在纯 DNS 转发场景下囤积大量已死会话。一个 DNS 转发器每秒 1000 次查询，60 秒超时意味着峰值 60000 个会话；120 秒就是 120000，直接撞上默认的 `udp_max_sessions`。

**明确的局限**：单一超时值无法同时优化 DNS（希望 5 秒）和 VPN（希望 180 秒）。**不实现 per-rule 超时**——`--udp-timeout` 是全局的。理由：per-rule 超时需要每个会话记住自己的超时值，老化扫描要做逐会话比较而不是统一比较，复杂度增加而收益仅限于"一个进程同时转发 DNS 和 VPN"这个不常见的组合。需要不同超时的用户可以起两个实例。这一点写进"已知局限"。

---

## 11. 已知风险与权衡

### 11.1 被接受的功能局限

| # | 局限 | 影响 | 为什么接受 |
|---|---|---|---|
| L1 | 上游地址只在启动时解析一次 | DNS failover 不生效 | 运行期异步解析需要线程或自建 DNS 客户端，与"无重依赖、单线程无锁"冲突 |
| L2 | `--udp-timeout` 是全局的，不能 per-rule | 同时转发 DNS 和 VPN 时只能取折中值 | 见 [10.13](#1013-udp-会话超时默认值q4-的另一半) |
| L3 | 无热重载；改配置必须重启 | 重启期间 TCP 连接断开、UDP 会话丢失 | 热重载需要保留 listener fd 并优雅移交，是一个独立的大特性 |
| L4 | 后端只能有一个，无负载均衡、无 failover | | 见 N6、[10.5](#105-不重试不做健康检查q5) |
| L5 | UDP 包大于 2048 字节会被丢弃并计数 | 巨帧场景不可用 | 第一版固定缓冲；`--mtu` 列入未来演进 |
| L6 | nftables 模式不支持跨族 | | 内核 DNAT 无 NAT64 能力，物理限制 |
| L7 | nftables 模式下后端看到的源地址是本机（因为 SNAT） | 后端无法做基于源 IP 的访问控制/日志 | 省掉 SNAT 需要本机在回程路径上（作为后端的网关），这个前提太强，不能作为默认。可作为 `--no-snat` 选项列入未来演进 |
| L8 | 统计在多 worker 下不聚合 | 用户需要自行相加 | 聚合需要共享内存或 IPC；第一版不值 |
| L9 | 无 IPv6 流标签、TOS/DSCP 透传 | | userspace 模式下 splice 天然不透传这些；需要逐包处理才能做，与零拷贝冲突 |

### 11.2 SIGKILL / 断电下的残留

**这是明确声明并接受的局限。**

| 场景 | userspace 模式 | nftables 模式 |
|---|---|---|
| `SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP` | 干净退出 | 规则清除，sysctl 还原 |
| `SIGKILL` / OOM kill | 无残留（内核回收所有 fd） | **规则残留、sysctl 残留** |
| 断电 / 内核 panic | 无残留 | 规则不残留（在内存里）、**sysctl 不残留**（`/proc/sys` 也在内存里） |
| 进程段错误 | 无残留 | **规则残留、sysctl 残留** |

对残留的应对：

- **规则残留**：由"启动时无条件删除同名 table"自愈。这是**唯一的手段**，且它是充分的——只要用户再启动一次程序，残留规则就被清除。如果用户不再启动程序，残留规则会一直生效，这是需要在 README 中显式警告的，并给出手工清理命令 `nft delete table inet portfwd`。
- **sysctl 残留**：**无法自愈**。程序不能在下次启动时"还原上次的 sysctl"，因为**它无法知道上次的原值是什么**——原值存在已死进程的内存里。把原值持久化到 `/run` 也不解决问题：`/run` 是 tmpfs，重启就没了；写到 `/var` 则会在重启后拿一个陈旧的值去覆盖当前值，比不还原更糟。
  - 后果的严重性：残留的 `ip_forward=1` 意味着机器在用户不知情的情况下继续做 IP 转发。在网关设备上这本来就是常态（无影响）；在一台不该转发的服务器上，这是一个真实的安全暴露面。
  - **必须写进 README**：
    ```
    KNOWN LIMITATION: if portfwd is killed with SIGKILL, or the machine loses
    power, the nftables rules and the ip_forward sysctl are left in place.
    Rules are cleaned up automatically the next time portfwd starts. The sysctl
    is NOT: portfwd cannot know what the original value was. Check it manually:
        sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding
    If you need guaranteed cleanup, use --no-sysctl and manage forwarding yourself.
    ```
  - 明确排除的兜底手段：systemd `ExecStopPost=`（违背 [2.7](#27-规则清理策略nftables-模式)的设计决策，且不能覆盖 SIGKILL 之外的场景，systemd 在 `KillMode=mixed` 下也不保证 `ExecStopPost` 一定运行）、watchdog 进程（引入第二个进程，违背单二进制定位）、`atexit` / `__attribute__((destructor))`（`SIGKILL` 下不运行，毫无帮助）。

### 11.3 多实例 sysctl 干扰

见 [2.6](#26-sysctl-自动管理nftables-模式)。剩余风险：

- flock 引用计数在 `/run` 不可写时降级为保守还原，此时实例 A 退出可能把实例 B 需要的 `ip_forward` 关掉。降级时有 `WARN`，但用户可能没看。
- 同一台机器上另一个**非本程序**的 NAT 工具（Docker、libvirt、tailscale）也在管 `ip_forward`。它们通常只设不还原，所以我们退出时的"复查当前值"会看到 `1`（是它们设的还是我们设的？无法区分），我们会认为"值仍等于我设的"从而还原为 `0`——**掐断 Docker 的容器网络**。
  - 缓解：flock 引用计数只覆盖本程序的实例。跨程序的引用计数不存在通用协议。
  - **文档必须直说**：在运行 Docker / libvirt / tailscale / 任何做 NAT 的软件的机器上，**推荐使用 `--no-sysctl`**，让 `ip_forward` 由这些系统统一管理。
  - 一个可能的改进（列入未来演进）：只有当我们观察到的 `orig` 值是 `0` **且**当前值是 `1` **且** flock 显示我们是最后一个实例时才还原——这已经是当前设计；进一步的改进只能是"不还原"，即把默认改成 `--no-sysctl`。这个选择留给 M6 阶段根据实际反馈决定。

### 11.4 性能相关的风险

| # | 风险 | 触发条件 | 缓解 |
|---|---|---|---|
| P1 | pipe 静默降级到 1 页 | `pipe-user-pages-soft` 超限 | U2 探测（FATAL）+ 实测 `F_GETPIPE_SZ` |
| P2 | 哈希表退化为链表 | 桶数写错 | `_Static_assert` + `tests/t_hash.c` 的链长断言 |
| P3 | epoll 忙循环烧满 CPU | inflight 掩码逻辑写错 | M5 的压测必须包含"慢消费者"场景，用 `perf stat` 检查 `epoll_wait` 调用率 |
| P4 | 源端口耗尽 | 高并发单目标转发，未设 `IP_BIND_ADDRESS_NO_PORT` | 见 [10.11](#1011-其他-socket-选项)；M5 压测到 5 万并发 |
| P5 | 会话哈希碰撞攻击 | 攻击者构造源地址 | SipHash + per-worker 随机 seed |
| P6 | 老化扫描造成延迟尖刺 | 全表扫描 | 增量遍历，见 [10.4](#104-udp-会话老化用增量遍历) |
| P7 | flowtable 未生效导致性能远低于预期 | DNAT 目标是本机地址；或 flowtable 设备推导错误 | N9/N10 探测（WARN）；`--stats` 中包含 flowtable 命中情况 |
| P8 | 多 worker 下 UDP 会话分布不均 | 少量客户端产生大量会话 | 文档说明；建议此场景用 `--workers 1` |

### 11.5 安全相关

| # | 风险 | 缓解 |
|---|---|---|
| S1 | 本程序是一个**开放的转发点**。任何能连到 listener 的人都能访问 upstream | 这是工具的本质，不是缺陷。文档必须警告：**不要在公网接口上监听内网目标**，用防火墙限制来源，或绑定到具体的内网地址而不是 `0.0.0.0` |
| S2 | `CAP_NET_ADMIN`（nftables 模式）是很大的权限 | 文档推荐 `setcap cap_net_admin+ep` 而不是 root 运行；userspace 模式完全不需要它 |
| S3 | nftables 模式的 SNAT 让上游看不到真实源 IP，上游的 ACL 失效 | 见 L7；文档警告 |
| S4 | 连接池耗尽是一个 DoS 面（攻击者开满 `max_conns` 条连接） | 本设计不实现 per-IP 限流（属于 L7/防火墙范畴）。文档建议用 nftables `ct count` 或 `limit` 在上游做。列入未来演进 |
| S5 | 日志放大 DoS | 见 [8.2](#82-热路径禁止日志)：热路径无日志，错误日志限速 |

---

## 12. 分阶段实现里程碑

**贯穿所有阶段的硬约束**：每个阶段结束时代码必须**可编译、可运行、可验证**。不允许"这阶段写一半"。每个阶段结束时 `make && make test` 必须全绿。

工作量级别：**S** ≈ 1–2 人日，**M** ≈ 3–5 人日，**L** ≈ 1–2 人周。

---

### M0 — 骨架（S）

**目标**：一个能解析配置、打印探测报告、响应信号并干净退出的空壳。没有任何数据面。

**涉及文件**：`Makefile`、`main.c`、`config.c/.h`、`addr.c/.h`、`log.c/.h`、`sig.c/.h`、`probe.c/.h`、`backend.h`、`util/hash.c/.h`、`tests/t_addr.c`

**内容**：
- CLI 解析（`getopt_long`），全部选项就位（未实现的 backend 选项解析后报 "not implemented yet"）。
- `sockaddr_inx` + 解析/格式化 + 全套宏。
- 分级日志，stderr / syslog 两个 sink，限速器。
- `signalfd`（+ self-pipe fallback）+ 统一退出路径。
- 通用探测 C1–C7 + `--check`。
- 空的 `backend_userspace`：`setup()` 打开 listener 但不 accept，`run()` 只 park 在 signalfd 上。
- daemonize（double fork + setsid + chdir("/") + 重定向 stdio）+ pidfile。

**验收标准**：
- `portfwd --help` / `--version` 正常。
- 所有非法配置在启动期报错，格式符合 [7](#7-启动期能力探测与错误处理策略) 的规范。
- `portfwd -m userspace -f 'tcp/0.0.0.0:1022->1.2.3.4:22'` 能启动、`ss -tlnp` 能看到 listener、`kill -TERM` 后 3 秒内退出且 pidfile 被删除。
- ASAN + UBSAN 构建下 `tests/t_addr` 全绿。

**测试方法**：
```bash
# address parsing round-trip
./tests/t_addr                 # asserts: parse->format->parse is idempotent
                               # covers 0.0.0.0:80, [::]:80, [2001:db8::2]:80,
                               #        127.0.0.1:1, 255.255.255.255:65535

# error message format
./portfwd -m userspace -f 'tcp/0.0.0.0:0->1.2.3.4:22'   ; echo "exit=$?"
# expect: [FATAL] rule syntax: ... ; exit=1

./portfwd -m userspace -f 'tcp/0.0.0.0:22->1.2.3.4:22' \
                       -f 'tcp/0.0.0.0:22->5.6.7.8:22' ; echo "exit=$?"
# expect: [FATAL] duplicate listeners: ... ; exit=1

# listener + signal handling
./portfwd -m userspace -f 'tcp/0.0.0.0:1022->1.2.3.4:22' -P /tmp/pf.pid &
sleep 0.3; ss -tlnp | grep ':1022' || exit 1
test -f /tmp/pf.pid || exit 1
kill -TERM $(cat /tmp/pf.pid); sleep 0.5
test ! -f /tmp/pf.pid || exit 1
ss -tlnp | grep ':1022' && exit 1 || true

# same for INT, QUIT, HUP
for s in INT QUIT HUP; do ... done
```

---

### M1 — userspace TCP 可用（M）

**目标**：单 worker、splice 零拷贝的 TCP 转发，含正确的半关闭与防 UAF 机制。**这一阶段结束时程序已经是一个可用的 TCP 端口转发器。**

**涉及文件**：`us/us_backend.c`、`us/us_loop.c/.h`、`us/us_tcp.c/.h`、`us/us_pool.c/.h`

**内容**：
- 对象池 + generation + `union ev_token` 打包（**从第一天就做**，理由见下）。
- `accept4` 循环到 `EAGAIN`；非阻塞 `connect`；`TCP_NODELAY`、`SO_KEEPALIVE`、`IP_BIND_ADDRESS_NO_PORT`。
- `pipe2` × 2；`splice` 双向泵；`inflight` 追踪；掩码派生 + 变化才 `epoll_ctl`。
- 完整的半关闭状态机（[6.1](#61-tcp-连接状态机)）。
- 延迟释放队列（`us_loop_flush_deferred` 在每批事件末尾调用）。
- U1/U2/U3 探测。
- IPv4 ↔ IPv6 跨族转发（因为地址抽象已就位，这几乎是免费的）。

> **为什么 generation/延迟释放不推迟到"健壮性"阶段**：它决定了 `epoll_data` 的表示（`u64` 打包 vs `ptr`）和每个事件处理入口的第一行代码。事后引入会波及全部数据面代码，且在此之前写的所有测试都跑在一个有 UAF 的实现上——ASAN 会随机报错，浪费的调试时间远超提前做的成本。**结构性的防御要在结构确定时做，不能事后补。**

**验收标准**：
- 1 GiB 随机数据双向传输，两端 SHA-256 一致。
- 半关闭正确传播（客户端关写后仍能收到服务端的尾部数据）。
- 慢消费者场景下 CPU 占用 < 5%（验证 inflight 掩码逻辑）。
- ASAN 构建下 1000 次连接建立/关闭无报错。
- 跨族转发（`[::]:1022 -> 127.0.0.1:22` 和 `0.0.0.0:1022 -> [::1]:22`）通。

**测试方法**：
```bash
# --- data integrity, both directions ---
# server echoes back
socat -b65536 TCP-LISTEN:9000,reuseaddr,fork EXEC:'/bin/cat' &
./portfwd -m userspace -f 'tcp/127.0.0.1:1080->127.0.0.1:9000' &
head -c 1073741824 /dev/urandom > /tmp/in.bin
socat -b65536 -T60 FILE:/tmp/in.bin TCP:127.0.0.1:1080 > /tmp/out.bin
cmp /tmp/in.bin /tmp/out.bin || echo "FAIL: data corruption"
sha256sum /tmp/in.bin /tmp/out.bin

# --- half-close propagation ---
# The server writes a trailer AFTER seeing EOF from the client.
# If the forwarder tears the connection down on one-way EOF, TAIL never arrives.
socat TCP-LISTEN:9001,reuseaddr,fork SYSTEM:'cat >/dev/null; echo TAIL' &
printf 'hello' | socat -T5 - TCP:127.0.0.1:1081 | grep -q TAIL \
  && echo "half-close OK" || echo "FAIL: half-close broken"

# --- the reverse direction, too ---
socat TCP-LISTEN:9002,reuseaddr,fork SYSTEM:'echo HEAD; sleep 1' &
socat -T5 - TCP:127.0.0.1:1082 </dev/null | grep -q HEAD

# --- slow consumer: must NOT burn CPU ---
# reader pauses; pipe fills; epoll must go quiet
socat TCP-LISTEN:9003,reuseaddr,fork SYSTEM:'sleep 30; cat >/dev/null' &
head -c 500000000 /dev/urandom | socat - TCP:127.0.0.1:1083 &
sleep 5
top -bn1 -p $(pidof portfwd) | tail -1        # expect %CPU < 5
perf stat -p $(pidof portfwd) -e syscalls:sys_enter_epoll_wait sleep 5
# expect: a few hundred calls over 5s, NOT millions

# --- cross-family ---
./portfwd -m userspace -f 'tcp/[::1]:1084->127.0.0.1:9000' &
echo ping | socat -T5 - TCP6:[::1]:1084 | grep -q ping && echo "v6->v4 OK"
./portfwd -m userspace -f 'tcp/127.0.0.1:1085->[::1]:9004' &
socat TCP6-LISTEN:9004,reuseaddr,fork EXEC:'/bin/cat' &
echo ping | socat -T5 - TCP:127.0.0.1:1085 | grep -q ping && echo "v4->v6 OK"

# --- throughput baseline ---
iperf3 -s -p 9005 & ; ./portfwd -m userspace -f 'tcp/127.0.0.1:1086->127.0.0.1:9005' &
iperf3 -c 127.0.0.1 -p 1086 -t 30 -P 4

# --- fd leak check ---
for i in $(seq 1000); do echo x | socat -T1 - TCP:127.0.0.1:1080 >/dev/null; done
ls /proc/$(pidof portfwd)/fd | wc -l    # must return to the idle baseline
```

---

### M2 — userspace UDP 可用（M）

**目标**：完整的 UDP 数据面。**这一阶段结束时 userspace 模式功能完整。**

**涉及文件**：`us/us_udp.c/.h`、`util/hash.c/.h`、`tests/t_hash.c`

**内容**：
- `recvmmsg`/`sendmmsg` 批量收发，批缓冲预分配。
- SipHash-1-2 会话哈希表（链地址法，2 的幂桶数，`_Static_assert` 保护）。
- 每会话一个 `connect()` 过的上游 socket，注册进 epoll。
- `IP_PKTINFO` / `IPV6_RECVPKTINFO` 收发两侧的 cmsg 处理，含 v4-mapped 情况。
- 增量老化（timerfd 100 ms，配额 `nbuckets/64`）。
- `MSG_TRUNC` 检测与丢弃。
- 会话上限与耗尽计数。

**验收标准**：
- DNS 转发正常（`dig` 通过转发器解析成功）。
- 多 IP 环境下回包源地址正确（这是 `IP_PKTINFO` 的核心验证）。
- 会话在超时后被回收，fd 数回落。
- 哈希分布测试：10000 个随机 key 插入 16384 桶，最长链 < 8。
- 跨族 UDP 转发通。

**测试方法**：
```bash
# --- basic UDP forwarding ---
./portfwd -m userspace -f 'udp/127.0.0.1:5353->8.8.8.8:53' &
dig @127.0.0.1 -p 5353 example.com +short   # must return an A record
dig @127.0.0.1 -p 5353 example.com +tcp     # must FAIL (udp-only rule)

# --- payload integrity for large-ish datagrams ---
socat -T5 UDP-RECVFROM:9100,fork EXEC:'/bin/cat' &
./portfwd -m userspace -f 'udp/127.0.0.1:1100->127.0.0.1:9100' &
head -c 1400 /dev/urandom > /tmp/u.bin
socat -T2 FILE:/tmp/u.bin UDP:127.0.0.1:1100 > /tmp/u.out
cmp /tmp/u.bin /tmp/u.out

# --- IP_PKTINFO: the critical test. needs two local addresses. ---
ip addr add 10.99.0.1/32 dev lo
ip addr add 10.99.0.2/32 dev lo
./portfwd -m userspace -f 'udp/0.0.0.0:1101->127.0.0.1:9100' &
# send TO 10.99.0.2, and verify the reply comes FROM 10.99.0.2
tcpdump -ni lo -c 4 'udp port 1101' &
socat -T3 UDP4-DATAGRAM:10.99.0.2:1101,bind=10.99.0.1:0 - <<< 'probe'
# In the tcpdump output the reply MUST read: 10.99.0.2.1101 > 10.99.0.1.*
# Without IP_PKTINFO it will read 127.0.0.1.1101 > ... and socat will time out.
# A socat timeout here is the failure signal.

# --- v4-mapped path (dual-stack listener) ---
./portfwd -m userspace -f 'udp/[::]:1102->127.0.0.1:9100' &
socat -T3 UDP4:127.0.0.1:1102 - <<< 'v4mapped'   # must echo back
socat -T3 UDP6:[::1]:1102   - <<< 'v6native'     # must echo back

# --- session aging ---
./portfwd -m userspace -f 'udp/127.0.0.1:1103->127.0.0.1:9100' \
          --udp-timeout 5 -l debug &
BASE=$(ls /proc/$(pidof portfwd)/fd | wc -l)
for i in $(seq 200); do
    socat -T1 UDP4-DATAGRAM:127.0.0.1:1103,bind=127.0.0.1:$((20000+i)) - <<< x &
done
sleep 1; ls /proc/$(pidof portfwd)/fd | wc -l     # expect ~ BASE + 200
sleep 15; ls /proc/$(pidof portfwd)/fd | wc -l    # expect back to ~ BASE

# --- hash distribution ---
./tests/t_hash          # asserts max chain length and bucket occupancy

# --- packet rate, and check for aging latency spikes ---
nping --udp -p 1103 --rate 100000 -c 1000000 --data-length 64 127.0.0.1
# in another terminal, watch for periodic stalls:
perf stat -p $(pidof portfwd) -e sched:sched_stat_runtime -I 100 sleep 30
# runtime per 100ms window must be flat, no periodic spikes
```

---

### M3 — nftables 模式可用（L）

**目标**：完整的 nftables backend，含规则生命周期、sysctl 管理、flowtable。**这一阶段结束时两种模式都可用。**

**涉及文件**：`nft/nft_backend.c`、`nft/nft_batch.c/.h`、`nft/nft_rules.c/.h`、`nft/sysctl.c/.h`、`tests/netns/*.sh`

**内容**：
- libmnl batch 事务封装（begin/end、seq 管理、ack 解析、`nlmsgerr` 到人类可读错误的映射）。
- table / chain（prerouting-nat、output-nat、postrouting-nat、forward-filter）/ rule 构造。
- DNAT + masquerade 规则的 expression 链：`meta l4proto` → `payload`(daddr) → `cmp` → `payload`(dport) → `cmp` → `counter` → `nat`。
- flowtable 创建（含设备推导）+ forward 链的 `flow add` 规则。
- 硬件 offload 探测（ETHTOOL_GFEATURES ioctl）与降级链。
- **删旧 + 建新在同一事务原子提交**。
- sysctl 管理：读原值、条件写、flock 引用计数、退出复查后还原。
- 探测 N1–N12。

**验收标准**：
- 转发功能通（TCP + UDP）。
- `nft list ruleset` 显示且仅显示我们的 table。
- 跨族配置被拒绝，错误信息符合 [7.3 N1](#n1--跨族在-nftables-模式下必须致命)。
- 无 `CAP_NET_ADMIN` 时被拒绝。
- `SIGTERM` 后 table 消失、sysctl 还原到原值。
- `SIGKILL` 后重启，旧 table 被自动清除（幂等自愈）。
- 运行期第三方改动 sysctl 后，退出时不覆盖。
- 多实例并发下 flock 引用计数正确。

**测试方法**：
```bash
# --- netns harness (isolates from the host firewall) ---
ip netns add pfw
ip link add veth0 type veth peer name veth1 netns pfw
# ... set up addressing, then run everything with: ip netns exec pfw ...

# --- functional ---
ip netns exec pfw ./portfwd -m nftables -f 'tcp,udp/10.0.0.1:1022->10.0.1.2:22' &
sleep 0.5
ip netns exec pfw nft list ruleset            # must show exactly table inet portfwd
ssh -p 1022 10.0.0.1                          # must reach 10.0.1.2:22
ip netns exec pfw conntrack -L -p tcp --dport 22   # must show a DNAT entry

# --- cross-family must be refused ---
./portfwd -m nftables -f 'tcp/[::]:1701->192.168.1.7:1701'; echo "exit=$?"
# expect: [FATAL] cross-family: ... hint: use --mode userspace ; exit=1
nft list tables | grep portfwd && echo "FAIL: table installed despite fatal error"

# --- missing capability ---
setpriv --inh-caps=-all --bounding-set=-net_admin ./portfwd -m nftables -f '...'
# expect: [FATAL] CAP_NET_ADMIN: ...

# --- clean shutdown: rules AND sysctl ---
sysctl -w net.ipv4.ip_forward=0
ORIG=$(cat /proc/sys/net/ipv4/ip_forward)     # 0
./portfwd -m nftables -f 'tcp/10.0.0.1:1022->10.0.1.2:22' &
sleep 0.5
cat /proc/sys/net/ipv4/ip_forward             # must be 1
nft list tables | grep -q 'inet portfwd'      || echo FAIL
kill -TERM %1; sleep 0.5
nft list tables | grep -q 'inet portfwd'      && echo "FAIL: rules leaked"
test "$(cat /proc/sys/net/ipv4/ip_forward)" = "$ORIG" || echo "FAIL: sysctl not restored"

# --- SIGKILL then idempotent self-heal ---
./portfwd -m nftables -f 'tcp/10.0.0.1:1022->10.0.1.2:22' &
PID=$!; sleep 0.5; kill -KILL $PID; sleep 0.2
nft list tables | grep -q 'inet portfwd' || echo "FAIL: expected leftover rules"
cat /proc/sys/net/ipv4/ip_forward             # expect 1 -- documented limitation
./portfwd -m nftables -f 'tcp/10.0.0.1:1023->10.0.1.2:22' &   # different port
sleep 0.5
nft list ruleset | grep -c 'dport 1022'       # must be 0: old rules were purged
nft list ruleset | grep -c 'dport 1023'       # must be > 0

# --- third-party sysctl change during runtime: must NOT be clobbered ---
sysctl -w net.ipv4.ip_forward=0
./portfwd -m nftables -f 'tcp/10.0.0.1:1022->10.0.1.2:22' &
sleep 0.5
sysctl -w net.ipv4.ip_forward=0               # simulate an admin turning it off
kill -TERM %1; sleep 0.5
# portfwd must have logged: "current value differs from what we set; not restoring"
# and must NOT have written anything.

# --- concurrent instances: A must not cut off B ---
sysctl -w net.ipv4.ip_forward=0
./portfwd -m nftables --nft-table pf_a -f 'tcp/10.0.0.1:1022->10.0.1.2:22' &  A=$!
./portfwd -m nftables --nft-table pf_b -f 'tcp/10.0.0.1:1023->10.0.1.2:22' &  B=$!
sleep 0.5
kill -TERM $A; sleep 0.5
test "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" \
  || echo "FAIL: instance A restored ip_forward while B is still running"
kill -TERM $B; sleep 0.5
test "$(cat /proc/sys/net/ipv4/ip_forward)" = "0" || echo "FAIL: B did not restore"

# --- flowtable ---
nft list flowtables
nft list ruleset | grep 'flow add'
# under load, verify the fast path is hit: forward-chain counters should stop
# growing while throughput stays high
nft list ruleset | grep counter    # watch packets in the forward chain
ethtool -k eth0 | grep hw-tc-offload

# --- atomicity of delete+create: no traffic gap ---
# run a continuous ping through the forward, restart portfwd, count losses
```

---

### M4 — 性能优化（M）

**目标**：多 worker、批量与掩码优化落地并被量化验证。**功能不变，只提升数字。**

**涉及文件**：`main.c`（fork/waitpid）、`us/us_backend.c`、`us/us_loop.c`、`us/us_tcp.c`、`us/us_udp.c`

**内容**：
- `SO_REUSEPORT` 多 worker fork 模型；父进程 `waitpid` + 信号转发（`SIGTERM` 转发给所有 worker，等待全部退出）。
- worker 崩溃时父进程记 `ERROR` 并**整体退出**（不自动重启——重启交给 procd/systemd，见 [11.1](#111-被接受的功能局限) L3 的同样理由）。
- `--workers auto` 解析。
- 掩码去抖（`epoll_ctl` 仅在变化时调用）的 A/B 量化。
- `recvmmsg` 批大小调优验证。
- （可选）`--pipe-size` 的实际影响量化。

**验收标准**：
- 4 worker 下 4 个核负载均衡（各核偏差 < 20%）。
- 同一硬件上 TCP 吞吐相比 M1 有可测量的提升。
- `epoll_ctl` 调用次数相比未优化版本下降 ≥ 5 倍。
- UDP 会话稳定落在同一 worker（验证 `SO_REUSEPORT` 四元组哈希的稳定性）。

**测试方法**：
```bash
# --- worker balance ---
./portfwd -m userspace --workers 4 -f 'tcp/0.0.0.0:1080->10.0.1.2:9000' &
iperf3 -c 127.0.0.1 -p 1080 -P 32 -t 60 &
mpstat -P ALL 1 60          # per-core %usr+%sys should be within 20% of each other
for p in $(pgrep -f 'portfwd'); do
    echo "$p $(awk '{print $14+$15}' /proc/$p/stat)"     # utime+stime per worker
done

# --- epoll_ctl call rate: before vs after ---
perf stat -p $(pidof portfwd) -e syscalls:sys_enter_epoll_ctl \
                              -e syscalls:sys_enter_splice sleep 30
# ratio epoll_ctl/splice should be well below 0.2 on a steady large transfer

# --- UDP worker affinity ---
./portfwd -m userspace --workers 4 -f 'udp/0.0.0.0:1101->10.0.1.2:9100' -l debug &
# send 100 packets from one fixed source port; grep the debug log:
# all "session created"/"packet forwarded" lines must come from the SAME worker pid
for i in $(seq 100); do
    socat -T1 UDP4-DATAGRAM:127.0.0.1:1101,bind=127.0.0.1:33333 - <<< x
done
grep 'session' /tmp/pf.log | awk '{print $2}' | sort -u | wc -l   # expect 1

# --- throughput regression vs M1 ---
# same box, same iperf3 invocation, record and compare
iperf3 -c 127.0.0.1 -p 1080 -t 60 -P 8 --json > m4.json
```

---

### M5 — 健壮性（M）

**目标**：把所有已识别的失败模式转化为测试。**这一阶段不加功能，只加信心。**

**涉及文件**：全部；`tests/` 大幅扩充

**内容**：
- ASAN / UBSAN / TSAN（虽然单线程，但检查 signal handler 交互）构建纳入 CI。
- 短连接洪泛、连接池耗尽、会话池耗尽的行为验证。
- 源端口耗尽验证（`IP_BIND_ADDRESS_NO_PORT` 的实际效果）。
- 慢消费者 / 快消费者 / 单向大流 / 双向大流 的组合矩阵。
- 上游拒绝连接、上游中途 RST、上游黑洞（丢弃 SYN）三种失败路径。
- 信号在各种时机到达（连接建立中、大流传输中、池耗尽时）。
- `--check` 在各种残缺内核配置下的输出（用 netns + 卸载模块模拟）。
- 交叉编译到 OpenWrt（mipsel、aarch64）并在真机或 QEMU 上跑一遍 M1–M3 的验收。
- 日志限速器在错误洪泛下的行为。

**验收标准**：
- ASAN 下 24 小时混合负载无报错。
- 5 万并发连接下无 `EADDRNOTAVAIL`。
- 池耗尽时行为正确（拒绝新连接，已有连接不受影响），日志被限速。
- 所有失败路径下无 fd 泄漏（`ls /proc/PID/fd | wc -l` 回到基线）。
- mipsel 与 aarch64 上 M1–M3 的验收标准全部通过。

**测试方法**：
```bash
# --- ASAN long-run mixed load ---
make ASAN=1
./portfwd -m userspace --workers 1 -f 'tcp/127.0.0.1:1080->127.0.0.1:9000' \
                                   -f 'udp/127.0.0.1:1101->127.0.0.1:9100' &
# run wrk (TCP short connections) + iperf3 (long flow) + nping (UDP) for 24h
wrk -t4 -c200 -d24h http://127.0.0.1:1080/ &
iperf3 -c 127.0.0.1 -p 1080 -t 86400 &
nping --udp -p 1101 --rate 20000 -c 0 127.0.0.1 &

# --- short-connection flood + fd leak ---
BASE=$(ls /proc/$(pidof portfwd)/fd | wc -l)
ab -n 500000 -c 500 http://127.0.0.1:1080/
sleep 5; test $(ls /proc/$(pidof portfwd)/fd | wc -l) -le $((BASE + 20))

# --- source port exhaustion ---
sysctl -w net.ipv4.ip_local_port_range="32768 60999"   # ~28k ports
# open 50000 concurrent connections through the forwarder
./tests/many_conns 50000 127.0.0.1 1080
# without IP_BIND_ADDRESS_NO_PORT this fails around 28k with EADDRNOTAVAIL
grep -c 'EADDRNOTAVAIL\|Cannot assign' /tmp/pf.log     # must be 0

# --- pool exhaustion ---
./portfwd -m userspace --max-conns 100 -f 'tcp/127.0.0.1:1080->127.0.0.1:9000' &
./tests/many_conns 500 127.0.0.1 1080
# expect: 100 succeed, 400 are reset immediately, existing 100 keep working,
#         the log shows the rate-limited "connection pool exhausted" message
#         with a "(N similar messages suppressed)" suffix

# --- upstream failure paths ---
./portfwd -m userspace -f 'tcp/127.0.0.1:1080->127.0.0.1:9999' &   # nothing listens
time nc -w5 127.0.0.1 1080 </dev/null   # must fail fast (RST), not hang
# blackhole: DROP the SYN, verify the client eventually times out and fd is freed
nft add rule inet t out ip daddr 10.0.1.2 tcp dport 9000 drop

# --- signal at awkward moments ---
for phase in connecting streaming pool-full; do
    ./tests/signal_race.sh $phase       # kills -TERM at a specific point 100x
done
# every run must exit 0 within 3s with no leaked fds and no ASAN reports

# --- cross-compile + run ---
make CROSS_COMPILE=mipsel-openwrt-linux- STATIC=1
file portfwd; ls -l portfwd            # verify size budget from 9.4
scp portfwd router: && ssh router 'cd /tmp && ./run-m1-m3-acceptance.sh'
```

---

### M6 — 文档与打包（S）

**目标**：README、man page、OpenWrt package。**这是第一个也是唯一一个写用户文档的阶段。**

**涉及文件**：`README.md`、`portfwd.8`、`openwrt/Makefile`、`contrib/portfwd.service`、`contrib/portfwd.init`

**内容**：
- README：安装、快速开始、两种模式的选择指引、全部 CLI 选项、**[11](#11-已知风险与权衡) 中的每一条局限**（尤其是 SIGKILL 后的 sysctl 残留和多实例干扰）、故障排查（含 `--check` 的用法）、调优表（pipe 大小 vs 连接数、worker 数）。
- man page（从 README 提炼，或反过来）。
- OpenWrt package Makefile（`DEPENDS:=+libnftnl`，`PKG_BUILD_FLAGS:=no-mips16`）+ procd init 脚本 + UCI 配置样例。
- systemd unit 样例（**注意：不含 `ExecStopPost=`**，与 [2.7](#27-规则清理策略nftables-模式) 的设计决策一致；只设 `LimitNOFILE=65536` 和 `KillSignal=SIGTERM`）。
- CHANGELOG。

**为什么 README 放在最后**：前面五个阶段中，默认值、错误信息措辞、探测项、局限清单都还在变。提前写文档意味着每个阶段都要回头改文档，而且几乎必然会有一处忘了改——一份和实现不一致的 README 比没有 README 更糟。到了 M6，所有行为都被测试固定下来，此时写出的文档是准确的。

**验收标准**：
- README 中的每一条命令都能复制粘贴执行成功（用脚本逐条验证）。
- `--help` 输出与 README 的选项表一致（用脚本对拍）。
- OpenWrt package 在 SDK 中编译通过，ipk 尺寸符合 [9.4](#94-二进制体积) 的预算。
- 一个从未见过本项目的人，照 README 能在 10 分钟内完成两种模式的部署。

**测试方法**：
```bash
# --- every command in the README must actually work ---
./tests/doc_check.sh README.md     # extracts ```console blocks and runs them

# --- option table vs --help ---
./portfwd --help | grep -oE '^\s+-[a-zA-Z-]+' | sort > /tmp/help.txt
grep -oE '^\| `-[a-zA-Z-]+' README.md | sort > /tmp/doc.txt
diff /tmp/help.txt /tmp/doc.txt

# --- OpenWrt package ---
cd openwrt-sdk && make package/portfwd/compile V=s
ls -l bin/packages/*/base/portfwd_*.ipk        # size must be < 40 KiB
```

---

### 里程碑总览

| 阶段 | 产出 | 工作量 | 累计可用性 |
|---|---|---|---|
| M0 | 骨架、CLI、探测框架、信号 | S | 能启动、能报错、能退出 |
| M1 | userspace TCP（splice、半关闭、防 UAF） | M | **TCP 转发可用** |
| M2 | userspace UDP（recvmmsg、哈希表、PKTINFO、老化） | M | **userspace 模式功能完整** |
| M3 | nftables backend（规则、sysctl、flowtable、清理） | L | **两种模式都可用** |
| M4 | 多 worker、掩码去抖、批量调优 | M | 性能达标 |
| M5 | 压测、ASAN、失败路径、交叉编译验证 | M | 可以上生产 |
| M6 | README、man、OpenWrt package | S | 可以发布 |

总计约 **5–7 人周**。

---

## 13. 未来演进（不进入里程碑）

以下条目**明确不在第一版范围内**，此处记录是为了避免它们以"顺手做一下"的形式渗进当前设计。

| 条目 | 触发条件 | 备注 |
|---|---|---|
| pipe 懒放大 | 有明确的"少数大流"场景性能报告 | 见 [10.6](#106-pipe-大小q3) |
| `--mtu` / 巨帧支持 | 有用户在 9000 MTU 环境下部署 | 需要按 MTU 分配 UDP 批缓冲 |
| 上游地址运行期重解析 | 有 DNS failover 需求 | 需要异步 DNS，不能用 `getaddrinfo` |
| per-rule UDP 超时 | 有单进程混合转发 DNS + VPN 的需求 | 见 [10.13](#1013-udp-会话超时默认值q4-的另一半) |
| `--no-snat`（nftables） | 用户确认本机在回程路径上 | 保留客户端真实源 IP，见 L7 |
| ctnetlink 事件订阅统计 | 有精确连接数需求 | O(事件) 而非 O(表大小)，见 [10.7](#107-nftables-模式下的统计q7) |
| 多 worker 统计聚合 | `--workers > 1` 成为常见用法 | 需要共享内存或 IPC |
| 热重载 | 有不可中断的部署 | 需要 listener fd 移交 |
| per-IP 连接数限制 | 有公网暴露的部署 | 或建议用 nftables `ct count` 在外围做 |
| eBPF / XDP / AF_XDP 模式 | flowtable 无法满足的极端场景 | 见 N2；代价是整条工具链 |
| iptables 兼容层 | 有必须运行在 legacy 内核的部署 | 见 N1；基本不会发生 |
| systemd `ExecStopPost` 兜底 | — | **明确拒绝**，见 [2.7](#27-规则清理策略nftables-模式) 和 [11.2](#112-sigkill--断电下的残留) |

---

## 附录 A：从 iptables 命令到本项目的映射

用户提供的现有做法：

```
iptables -t nat -A PREROUTING  -p tcp --dport 25            -j DNAT --to-destination 8.8.8.8:53
iptables -t nat -A POSTROUTING -p tcp -d 8.8.8.8 --dport 53 -j SNAT --to-source 192.168.1.10
iptables -t nat -A PREROUTING  -p udp --dport 25            -j DNAT --to-destination 8.8.8.8:53
iptables -t nat -A POSTROUTING -p udp -d 8.8.8.8 --dport 53 -j SNAT --to-source 192.168.1.10
```

这组规则的结构（**PREROUTING 做 DNAT 改目的、POSTROUTING 做 SNAT 改源**）正是 `nftables` 模式的数据面模型，直接确认了 [2.5](#25-nftables-模式数据面概览) 的设计方向。以下逐条分析差异，这些差异都已反映在本手册的相应章节中。

### A.1 SNAT 是必需的，理由要写进文档

如果只有 DNAT 没有 SNAT：包到达 `8.8.8.8:53` 时源地址仍是**原始客户端**的地址。`8.8.8.8` 的响应会按路由直接发回客户端，而不经过本机——本机的 conntrack 因此永远看不到回程包，无法把源地址反向翻译回 `本机:25`。客户端收到一个来自 `8.8.8.8:53` 的包，而它期待的是来自 `本机:25`，四元组不匹配，**直接丢弃**。

所以 SNAT/masquerade 在"本机不在回程路径上"的场景下是**强制**的。这条被记录为 [11.1](#111-被接受的功能局限) 的 L7：代价是上游看不到真实客户端 IP。只有当本机是客户端到上游的网关（回程包必经本机）时才能省掉 SNAT——那时才有 `--no-snat` 的意义，已列入 [13](#13-未来演进不进入里程碑)。

### A.2 缺 OUTPUT 链：本机自己发起的流量不会被转发

`nat/PREROUTING` 只处理**从网卡进入**的包。本机上跑 `dig @127.0.0.1 -p 25` 或 `dig @192.168.1.10 -p 25` 时，包由本机协议栈生成，走的是 `OUTPUT` 而不是 `PREROUTING`，**完全不会被这条规则匹配**。

这是端口转发规则最常见的困惑来源："我在别的机器上测通了，在本机上测就不通"。

**本项目的处理**：在 [2.5](#25-nftables-模式数据面概览) 的规则模板中**同时安装 `prerouting` 和 `output` 两条 nat 链**，两条链装同一组匹配条件。用户不需要知道这个区别。

### A.3 `-j SNAT --to-source` vs `masquerade`

| | `SNAT --to-source 192.168.1.10` | `masquerade` |
|---|---|---|
| 源地址来源 | 硬编码 | 运行时按路由查出口接口的主地址 |
| IP 变化时 | **规则失效，流量断**（改 IP、DHCP 续租拿到新地址、多出口切换） | 自动跟随 |
| 每包成本 | 略低 | 略高（首包查一次路由，后续走 conntrack 缓存，实际差异可忽略） |
| 接口 down 时 | conntrack 表项保留，接口回来后可能用错地址 | 内核在接口 down 时主动清除相关 conntrack 表项 |

**本项目选 `masquerade` 作为默认**。理由：本程序的定位是"用户自行部署的工具"，不能假设用户的出口地址稳定。硬编码源地址在 OpenWrt（PPPoE 拨号，IP 每次都变）上几乎必然出错。`SNAT --to-source` 的确定性优势只在"多个出口地址、需要固定用某一个"的场景下才有意义，那属于策略路由的范畴，超出本项目定位。

### A.4 匹配条件过宽：缺 `-d` 或 `-i` 限定

`-p tcp --dport 25 -j DNAT` **没有限定目的地址**。这意味着 `PREROUTING` 上所有目的端口为 25 的包都会被劫持——**包括经过本机转发的、目的地根本不是本机的包**。如果这台机器是网关，内网里任何人给外网发的 SMTP 流量都会被改道到 `8.8.8.8:53`。

这大概率不是本意。

**本项目的处理**：`struct fwd_rule` 中的 `local` 是一个**完整的地址+端口**，规则模板里始终生成 `ip daddr <local-addr> tcp dport <port>` 的匹配。当用户写 `0.0.0.0:25`（通配）时，才退化为只匹配端口——此时启动阶段输出一条 `INFO`：

```
[INFO] rule #0 listens on the wildcard address 0.0.0.0:25; in nftables mode this
       intercepts every packet with destination port 25 traversing this host,
       including forwarded traffic. Bind to a specific address to narrow it.
```

这条提示直接来自对上述 iptables 规则的分析。

### A.5 缺 `ip_forward`

DNAT 的目标是 `8.8.8.8`（非本机地址），包在 DNAT 之后需要走**转发路径**才能出去。`net.ipv4.ip_forward=0` 时内核会直接丢弃它。上面的命令组里没有这一步——如果这台机器本来就是路由器（`ip_forward` 已经是 1），规则能用；换到一台普通服务器上就静默不通。

**本项目的处理**：这正是 [2.6](#26-sysctl-自动管理nftables-模式) 存在的原因——启动时自动开启、退出时条件还原，并且在 `--check` 中把当前值和将要设置的值都打印出来。

### A.6 端口 25 → 53 的跨端口转发没有问题

DNAT 可以同时改地址和端口，`--dport 25 -j DNAT --to-destination 8.8.8.8:53` 是合法且常用的写法。本项目的规则语法 `tcp/0.0.0.0:25->8.8.8.8:53` 表达同样的意思。

（顺带一提：把 25 端口转到 8.8.8.8:53 看起来像是一个测试用例而不是生产配置——25 是 SMTP、53 是 DNS。如果目的是绕过运营商对 53 端口的封锁，可以直接用；如果是复制粘贴时改错了端口，值得再确认一下。）

### A.7 SNAT 源地址 `192.168.1.10` 与目标 `8.8.8.8` 的组合

`192.168.1.10` 是 RFC1918 私有地址，`8.8.8.8` 是公网地址。SNAT 成私有源地址后，包发往公网需要**再经过一次上游 NAT**（家用路由器）才能回来。这在家庭网络里能工作（本机 → 路由器 → 公网，路由器做第二次 NAT），但它意味着有两层 NAT，且 `8.8.8.8` 的回包路径依赖上游 NAT 的表项。

**本项目的处理**：`masquerade` 会自动选出口接口的地址，在这种拓扑下选出的仍然是 `192.168.1.10`，行为一致。但 N11 探测中可以顺带检查"SNAT 后的源地址是私有地址而 DNAT 目标是公网地址"，输出一条 `INFO` 提示存在多层 NAT。这属于锦上添花，可选。

### A.8 最大的差异：没有生命周期管理

上面四条 `iptables -A` 命令**会一直留在内核里**，直到有人手工 `-D` 掉，或者机器重启。重复执行会**累积重复规则**（`-A` 是追加，不是幂等）。这正是本项目要解决的核心问题：

| | 手工 iptables | 本项目 nftables 模式 |
|---|---|---|
| 规则何时消失 | 手工删除或重启 | 进程退出即清除 |
| 重复执行 | 累积重复规则 | 幂等（先删同名 table 再建） |
| 上次异常退出的残留 | 手工清理 | 下次启动自动清除 |
| 应用/回滚的原子性 | 每条命令一次事务，中间有窗口 | 全部规则一个 netlink 事务 |
| `ip_forward` | 用户自己记得改、自己记得改回来 | 自动、条件还原 |
| 出错时 | 逐条 `echo $?` | 启动期统一探测 + 结构化错误信息 |

**等价的本项目命令**（修正了 A.2 的 OUTPUT 缺失和 A.4 的匹配过宽）：

```
portfwd --mode nftables -f 'tcp,udp/192.168.1.10:25->8.8.8.8:53'
```

如果只想验证配置而不实际生效：

```
portfwd --mode nftables -f 'tcp,udp/192.168.1.10:25->8.8.8.8:53' --check
```

如果不希望程序碰 `ip_forward`（例如机器上跑着 Docker）：

```
portfwd --mode nftables --no-sysctl -f 'tcp,udp/192.168.1.10:25->8.8.8.8:53'
```

---

## 附录 B：开放性设计问题结论索引

| # | 问题 | 结论 | 详见 |
|---|---|---|---|
| Q1 | 单二进制多规则，还是每条规则一个进程？ | **单二进制、单进程、多规则**；协议用规则前缀区分，不拆二进制 | [2.3](#23-cli-形态) |
| Q2 | worker 进程数的默认值？ | **默认 1**；`auto` = `min(nproc, 4)` | [10.12](#1012-worker-进程数默认值q2) |
| Q3 | pipe 大小默认值？是否自适应？ | **默认 65536**（内核默认值，免一次 syscall）；**不自适应**；懒放大列入未来演进 | [10.6](#106-pipe-大小q3) |
| Q4 | UDP 会话超时默认值？TCP 是否需要空闲超时？ | UDP **60 秒**；TCP 空闲超时**默认关闭**，但**默认开启 keepalive**（回收僵尸而不杀活人） | [10.13](#1013-udp-会话超时默认值q4-的另一半)、[10.5](#105-不重试不做健康检查q5) |
| Q5 | 上游连接失败是否重试？是否要健康检查？ | **都不做**。重试破坏 TCP 失败语义并放大故障；健康检查属于 LB 范畴，单后端下无意义 | [10.5](#105-不重试不做健康检查q5) |
| Q6 | sysctl 多实例并发采用哪个方案？ | **flock 引用计数 + 无条件的还原前复查**；`/run` 不可写时降级为保守还原并 WARN；`--no-sysctl` 作为逃生舱 | [2.6](#26-sysctl-自动管理nftables-模式)、[11.3](#113-多实例-sysctl-干扰) |
| Q7 | nftables 模式如何做统计？ctnetlink 值得吗？ | 用规则内建 **counter**（包/字节），netlink dump 读回；**ctnetlink dump 不值得**（O(全机器连接数)，还要额外内核模块）；事件订阅列入未来演进 | [10.7](#107-nftables-模式下的统计q7) |
| Q8 | 两模式共享配置解析和地址抽象吗？边界在哪？ | **共享**。边界是 `struct fwd_rule`：其上（CLI、地址、日志、信号、探测框架）共享，其下（数据面）零共享 | [10.8](#108-两模式共享配置解析与地址抽象q8) |
| — | nftables 交互方式？ | **libmnl + libnftnl**。libnftables 拖进 gmp + jansson，体积翻三倍；纯手写 netlink 开发量与维护成本过高；**禁止 fork/exec `nft`** | [2.8](#28-nftables-交互方式选型q三方案对比) |
| — | 连接释放的 use-after-free 怎么解决？ | **generation 计数 + 延迟释放队列**（B+C 组合）。完整扫描同批事件（方案 A）是 O(N) 且不解决 slot 复用串流 | [10.2](#102-连接释放安全性与-use-after-free) |
