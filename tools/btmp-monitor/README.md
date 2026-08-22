# btmp-monitor

监控 `/var/log/btmp` 失败登录记录,对暴力破解 IP 自动调用 [xdp-firewall](../../README.md) 的 `temp-bans` API 封禁。

Rust 实现,独立 Cargo 项目,不依赖主防火墙二进制。**无配置文件**——参数全部通过命令行参数与环境变量提供;直接解析 btmp 的二进制 utmp 记录,不调用外部 `lastb` 命令(新版 util-linux 已移除 last/lastb)。

## 工作原理

1. 读取 `/var/log/btmp`(需 root)中的 384 字节定长 utmp 记录,解析来源 IP(`ut_host`,与 `lastb` 显示同源)与时间戳(`ut_tv`);尾部的半条记录(崩溃导致)会被跳过。
2. 按 **offset + inode 增量游标**读取:daemon 每轮只处理新增记录(轮询成本 O(新增) 而非全量重扫),logrotate 轮转(inode 变化或文件变短)自动从头读新文件。
3. 按时间窗口(默认 24h)在内存中维护每 IP 失败计数,超过阈值(默认 5 次)的 IP 成为封禁候选。
4. 跳过:落入可信网段(`--trusted-cidr`)的 IP、已在 xdp-firewall 中未过期封禁的 IP。
5. 剩余 IP 通过 `POST /temp-bans/batch` 提交封禁,封禁时长、协议、端口等由参数决定;超过 API 单次上限(500 条)时自动分块提交。

幂等与失败语义:每轮先 `GET /temp-bans` 拉取未过期封禁集合,未过期的 IP 不会重复提交;该请求失败时本轮直接中止(不带着空集合重复提交),daemon 模式下轮重试,`--once` 模式以非零退出码暴露给 cron。`--dry-run` **完全不发起任何 API 请求**(包括上面的去重拉取),只解析 btmp 并打印候选 IP 与将提交的封禁参数。

## 前置条件:确认 sshd 在写 btmp

`btmp` 记账本身无需"开启"——主流发行版的 sshd 认证失败会自动写入 btmp。部署前确认链路是通的:

```bash
# 1. 文件存在且权限正确(root:utmp 0600 或 0660)
ls -l /var/log/btmp

# 2. 实测:故意输错一次密码后确认文件在增长
ls -l /var/log/btmp

# 3. sshd 走 PAM(主流发行版默认 yes)
grep -i usepam /etc/ssh/sshd_config
```

如果 ssh 失败不进 btmp,按现象对号:

| 现象 | 原因 | 修法 |
|------|------|------|
| 文件不存在 | 最小化安装/容器环境未创建该文件 | `sudo install -o root -g utmp -m 0600 /dev/null /var/log/btmp` |
| 文件在,但 ssh 失败不记录 | 权限/属组不对(应为 `root:utmp`) | 同上一条修正 |
| Alpine/musl 环境 | musl 无 utmp 记账体系,sshd 写不了 btmp | 换 glibc 发行版,或改用其他数据源(本工具不覆盖 journalctl 解析) |
| 改用密钥登录后 btmp 一直空 | `PasswordAuthentication no` 时攻击到不了密码认证阶段,属正常 | 无需处理;爆破防护由 xdp-firewall 的按服务限流兜底 |

两个口径边界:

- **btmp 只记录走到认证阶段的失败**。端口扫描、banner 探测等 pre-auth 噪音不进 btmp(只在 auth.log/journal)。本工具只能封"真爆破";扫描类流量由 xdp-firewall 的地理封禁/每源 IP 限流/flood 拦截。
- **btmp 按月轮转**(`/etc/logrotate.d/btmp`)。本工具只读当前文件,轮转前的记录已并入内存计数、随窗口滑出,无需跨文件聚合。

## 构建

```bash
cd tools/btmp-monitor
cargo build --release
# 产物:target/release/btmp-monitor
```

跨平台与镜像(与主仓库同款工具链,依赖 cargo-zigbuild + Zig):

```bash
make zig-build-all        # 交叉编译 linux-amd64 + linux-arm64(musl 静态)到 dist/
make docker-build         # 单平台镜像(默认 linux/amd64)
make docker-buildx-push   # 多平台镜像构建并推送
make docker-run           # 容器运行:host 网络 + 只读挂载 /var/log/btmp + token 环境变量
```

镜像内入口即 `btmp-monitor`,参数照常透传(`make docker-run-once` 等价 `--once`);`API_TOKEN=xxx make docker-run` 可覆盖注入的 token。

## 参数

所有参数命令行与环境变量二选一,命令行优先:

| 参数 | 环境变量 | 默认 | 说明 |
|------|----------|------|------|
| `--api-url` | `BTMP_MONITOR_API_URL` | `http://127.0.0.1:8080` | xdp-firewall 控制平面 API 地址 |
| `--api-token` | `XDP_FIREWALL_API_TOKEN` | —(必需) | 与 xdp-firewall 的 `XDP_FIREWALL_API_TOKEN` 一致;仅 `--dry-run` 可省略 |
| `--threshold` | `BTMP_MONITOR_THRESHOLD` | `5` | 触发封禁的失败次数 |
| `--window-seconds` | `BTMP_MONITOR_WINDOW_SECONDS` | `86400` | 统计窗口(秒) |
| `--duration-seconds` | `BTMP_MONITOR_DURATION_SECONDS` | `600` | 封禁时长(秒),默认 10 分钟;API 上限 31_536_000 |
| `--protocol` | `BTMP_MONITOR_PROTOCOL` | `any` | `any` / `tcp` / `udp` |
| `--port` | `BTMP_MONITOR_PORT` | `0` | 仅 `protocol != any` 时生效,1..=65535 |
| `--comment` | `BTMP_MONITOR_COMMENT` | `btmp auto-ban: ...` | 写入 temp-ban 记录的备注 |
| `--btmp-path` | `BTMP_MONITOR_BTMP_PATH` | `/var/log/btmp` | btmp 文件路径 |
| `--trusted-cidr` | `BTMP_MONITOR_TRUSTED_CIDRS` | `127.0.0.0/8,::1/128` | 永不封禁的网段;参数可多次指定,环境变量逗号分隔(如内网:`10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`) |
| `--interval` | `BTMP_MONITOR_INTERVAL` | `60` | daemon 轮询间隔(秒) |
| `--once` | — | — | 单次运行后退出(cron 场景) |
| `--dry-run` | — | — | 只解析并打印候选 IP 与封禁参数,**零 API 请求**(无需 token/API 可用) |

示例——只封 SSH、阈值 3 次、封 7 天、信任内网:

```bash
btmp-monitor --protocol tcp --port 22 --threshold 3 --duration-seconds 604800 \
    --trusted-cidr 10.0.0.0/8 --trusted-cidr 172.16.0.0/12
```

## 运行

```bash
# 单次扫描后退出(cron 场景;进程全新,全量读一次 btmp 再按窗口过滤)
sudo ./target/release/btmp-monitor --once

# 常驻 daemon(systemd 场景,默认模式;增量游标,每轮只读新增记录)
sudo ./target/release/btmp-monitor

# 仅观察,不实际封禁(首次部署推荐;无 API/token 也可跑)
sudo ./target/release/btmp-monitor --once --dry-run
```

`RUST_LOG=debug` 可开启更详细日志。

## 调度示例

### systemd(daemon)

`/etc/systemd/system/btmp-monitor.service`:

```ini
[Unit]
Description=xdp-firewall btmp brute-force monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=XDP_FIREWALL_API_TOKEN=change-this-token
Environment=BTMP_MONITOR_API_URL=http://127.0.0.1:8080
Environment=BTMP_MONITOR_TRUSTED_CIDRS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
ExecStart=/usr/local/bin/btmp-monitor
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### cron(--once)

```cron
*/5 * * * * root XDP_FIREWALL_API_TOKEN=change-this-token /usr/local/bin/btmp-monitor --once
```

### Docker Compose(daemon)

模板在 `deploy/docker-compose/`,与主仓库部署方式同构:改好 `compose-env` 里的 token 与参数后,

```bash
# 先构建镜像(或把 compose-env 的 BTMP_MONITOR_IMAGE 指向registry镜像)
make zig-build-amd64 && make docker-build

# 起停
make compose-up
make compose-down
```

等价的裸命令:

```bash
docker compose --env-file tools/btmp-monitor/deploy/docker-compose/compose-env \
    -f tools/btmp-monitor/deploy/docker-compose/compose.yml up -d
```

两个容器化特有的设计:

- **挂载 `/var/log` 整个目录(只读)而不是单个 btmp 文件**:单文件 bind mount 会把旧 inode 钉死,logrotate 轮转后容器里看到的永远是旧文件,增量游标的轮转检测也就失效了;挂目录让容器内每次 open 都解析到当前文件。
- `network_mode: host` + `read_only: true`:工具只读 btmp、只调 API,无监听端口、无写盘需求;同机部署 xdp-firewall api 时 `BTMP_MONITOR_API_URL` 保持 `127.0.0.1:8080` 即可。

### Docker Compose 全家桶(api + agent + btmp-monitor)

目标服务器上**没有**现成 xdp-firewall 时,用 `compose.full.yml` 一把起整套(合并了主仓库 `deploy/docker-compose/compose.sqlite.yml`):SQLite 控制平面 + 宿主机 XDP agent + btmp-monitor,token 两个(`XDP_FIREWALL_API_TOKEN` / `XDP_FIREWALL_AGENT_TOKEN`)填在 `compose-env.full` 里即可。

```bash
# 需要两个镜像:主仓库 make docker-build 产出 XDP_FIREWALL_IMAGE,
# 本目录 make zig-build-amd64 && make docker-build 产出 BTMP_MONITOR_IMAGE
make compose-full-up
make compose-full-down
```

与单独模板的差异:

- btmp-monitor 与 agent 均 `depends_on: api (service_healthy)`,api 健康检查通过后才启动。
- SQLite 数据落在 compose 文件旁的 `deploy/docker-compose/sqlite-data/`(与主仓库布局一致)。
- btmp-monitor 的日志过滤用独立变量 `BTMP_MONITOR_RUST_LOG`(默认 `btmp_monitor=info`);栈级 `RUST_LOG=xdp_firewall=info` 会把它的日志整个过滤掉,两者不可共用。
- 修改 `XDP_FIREWALL_API_PORT` / `XDP_FIREWALL_XDS_PORT` 时需同步改 `BTMP_MONITOR_API_URL` / `XDP_FIREWALL_XDS_URL`(btmp-monitor 与 agent 走 host 网络拨已发布端口)。

## 注意

- 需以 root 运行才能读取 `/var/log/btmp`。
- token 与 xdp-firewall 控制平面的 `XDP_FIREWALL_API_TOKEN` 不一致时封禁请求返回 401。
- xdp-firewall 自身会拒绝封禁其节点接口 IP(`reject_temp_ban_node_ip`);本工具额外用 `--trusted-cidr` 在前端跳过,避免无谓请求。
- btmp 的 `ut_tv.tv_sec` 是 32 位秒(2038 溢出,utmp 体系因此被逐步弃用);2038 年前使用没有问题。
