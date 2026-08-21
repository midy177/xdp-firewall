# 开源 | xdp-firewall:用 Rust 写的分布式 XDP/eBPF 内核级防火墙(单二进制,内置 Web 控制台)

> 项目地址:<https://github.com/midy177/xdp-firewall>(镜像同步中,欢迎 issue/PR)
> crates.io:`cargo install xdp-firewall`(搜索 xdp-firewall)

**一句话介绍:把"放行还是丢弃"的判断从应用层/日志层前移到网卡驱动层——一个 Rust 单二进制同时提供控制面(REST API + 内嵌 Vue 控制台 + gRPC xDS)和数据面 agent(Aya 加载 XDP 程序写 BPF map),策略存在 SQLite/PostgreSQL/MySQL 里,一次配置、全集群秒级生效。**

## 为什么又造了一个轮子

服务器入口防护的传统拼图是"云安全组 + fail2ban",两者都有结构性缺陷:

**云安全组是静态 ACL,不是防御系统。** 没有限流、没有自动封禁、没有威胁情报;规则数有硬配额(几十到一两百条),按"封 IP"运营根本不可持续;多环境/多区域割裂,同一次封禁要在研发、测试、生产各来一遍;变更走云 API 有速率限制,紧急处置时最要命。

**fail2ban 防护位置太深。** 数据包要先走完 网卡中断 → 内核协议栈 → conntrack → 应用 → 写日志,fail2ban 才能"看见"它;即使用 iptables 拉黑,攻击流量仍在消耗中断、软中断、skb 分配和协议栈资源。它只能保护"有日志且日志可解析"的服务,每个服务要单独写正则,日志一变就漏报误报;单机作战,100 台机器就是 100 份配置;iptables 线性匹配,封禁列表上千后每个包都要遍历长规则链,封得越多主机越慢。

**xdp-firewall 的答案:**

- **native XDP 在驱动收包后、skb 分配前执行**,`XDP_DROP` 直接把包丢在网卡层——不分配 skb、不走协议栈、不进 conntrack、不唤醒应用、不产生日志。云网卡不支持 native 时自动回退 skb 模式,依然早于 netfilter。
- 判定全部是**内核态查表**(LPM 前缀树,复杂度只与前缀长度相关,与规则数量无关),默认 26 万条前缀级容量,比安全组配额高三个数量级。
- **集中控制面**:策略进数据库,单调递增版本号,gRPC xDS 服务端流秒级推送到所有节点;agent 不持有数据库凭据、不外联,只订阅策略、回报心跳。

## 控制台长这样

![防火墙规则](https://raw.githubusercontent.com/midy177/xdp-firewall/master/docs/rules.jpeg)

![实时丢包事件](https://raw.githubusercontent.com/midy177/xdp-firewall/master/docs/drops.jpeg)

![节点管理](https://raw.githubusercontent.com/midy177/xdp-firewall/master/docs/nodes.jpeg)

更多截图(信任网段、临时封禁、威胁情报、国家规则、动态防御、API 文档)见 README。

## 每个包在内核里走一遍的判定链

```
1. trusted_cidrs   白名单,最高优先级,保证运维/控制面永远可达
2. temp_bans       临时封禁,BPF 单调时钟自动到期解除,无需再推送
3. rule_cidrs      静态规则 + 威胁情报 deny(LPM 最长前缀,数值小者优先)
4. country_rules   国家级 allow/deny
5. 自定义限流      按协议/端口的令牌桶(TCP/22、UDP/5060、443 各自独立)
6. 全局限流/flood  每源 IP 令牌桶 + flood 超限自动临时封堵(动态防御)
7. 默认放行
```

威胁情报内置三个源:**ipsum**、**spamhaus-drop**、**voipbl**(VoIP 场景),控制面每日自动刷新,agent 零外联。Geo 国家列表从 IPdeny 自动抓取聚合。每个被丢的包都可以通过 perf 事件上报:节点、源 IP、协议、端口、命中原因(规则/威胁情报/国家/限流/临时封禁)、国家归属——前端 SSE 实时订阅,**无订阅者时 agent 完全不读 perf buffer,零开销**。

## Rust 技术栈与工程细节

- **单二进制**:控制面 `api` 一个进程同时起 Axum HTTP(API/UI/SSE)和 tonic gRPC xDS;前端 `include_bytes!` 进二进制,部署不需要静态文件目录。`clap` 子命令分发:`migrate / api / xds / agent / sync-once / monitor / policy / xdp`。
- **SeaORM** 一套实体映射 SQLite/PostgreSQL/MySQL 三库;迁移是启动时全量重放的幂等 DDL,无版本表。
- **Aya** 管理 XDP 生命周期;BPF map 固定 pin 在 `/sys/fs/bpf/xdp-firewall/<iface>/`,dispatcher 模式与已有 XDP 程序共存,`monitor` 命令可离线重开 map 看统计/临时封禁。
- **Rust↔BPF ABI 对齐是 load-bearing 的**:`data_plane/xdp/encoding/` 的结构与 `bpf/xdp_firewall.c` 逐字段对齐,统计计数器枚举两侧同步。
- **多数据库幂等迁移的三个坑**(都已在 MySQL 8 真机验证修复,值得同类项目参考):
  1. MySQL 不支持 `CREATE INDEX IF NOT EXISTS`,sea-query 渲染时会静默丢弃该标志——第二次启动迁移必报 1061。解法:先查 `information_schema` 再建;
  2. sea-orm 的 `OnConflict::do_nothing()` 在 MySQL 后端被渲染成语句末尾追加 `" IGNORE"`(非法 SQL,1064)。解法:对冲突目标列自赋值 `update_columns`,三库通吃;
  3. 实体裸 `String` 在 MySQL 是 `varchar(255)`,聚合 CIDR JSON(大国 ~150KB)直接 1406,且 `TEXT` 64KB 也不够——按容量等级只升不降地提升到 `MEDIUMTEXT`。
- **非 Linux 开发体验**:XDP 模块 `cfg` 门控,macOS 上编译为 no-op,`make check` 本地全绿。
- **安全默认**:非回环绑定强制 token(API 与 xDS 分开);xDS 可选 TLS/mTLS(自动生成 100 年证书,或自带 PEM);standby 只读模式支持双控制面。

## 快速上手

```bash
export DATABASE_URL='sqlite://xdp-firewall.db?mode=rwc'
cargo install xdp-firewall
xdp-firewall migrate
xdp-firewall policy seed-example
XDP_FIREWALL_API_TOKEN=change-this-token \
XDP_FIREWALL_AGENT_TOKEN=change-this-agent-token \
xdp-firewall api            # HTTP :8080(控制台)+ gRPC :50051

# 每台服务器(agent 需要 Linux + XDP 支持):
XDP_FIREWALL_XDS_URL=http://控制面:50051 xdp-firewall agent
```

打开 `http://控制面:8080`,输入 API token 即可看到控制台。PostgreSQL/MySQL 换个 `DATABASE_URL` 即可,多节点共享同一配置库。Docker 与 Kubernetes(DaemonSet + Deployment)清单在 `deploy/` 下。

## 链接

- GitHub:<https://github.com/midy177/xdp-firewall>
- crates.io:搜索 `xdp-firewall`
- 内置威胁源:ipsum / Spamhaus DROP / VoIPBL
- BPF 程序源码:`bpf/xdp_firewall.c`(README 有完整的 map 容量表与判定优先级文档)

欢迎使用、提 issue、贡献规则思路——特别是在你们真实业务里跑过 XDP 防火墙的同学,欢迎交流 dispatcher 共存、map 扩容、Geo 规模等方面的经验。
