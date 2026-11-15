# RansomGuard — 终端侧勒索软件早期检测

一个用 Rust 编写的终端侧（endpoint）早期检测程序。针对"文件被批量加密后才发现"的
问题，它在勒索行为发生的**几秒内**从四个独立维度识别异常，并能自动冻结可疑进程、
固化取证现场。

## 检测能力（四类信号）

| 信号 | 触发条件 | 级别 |
|------|----------|------|
| **熵激增 `entropy_surge`** | 60 秒滚动窗口内，≥8 个文件被改写成高熵内容（绝对熵 ≥7.4 bits/byte，或相对基线跃升 ≥1.5），且高熵写入占比 ≥60% | Critical |
| **扩展名批量变更 `extension_churn`** | 窗口内 ≥6 次换扩展名的重命名，且占所有变更事件 ≥40% | 计入评分 |
| **可疑后缀爆发 `suspicious_extensions`** | ≥5 个文件出现 `.locked/.encrypted/.crypt/.locky/...` 等已知勒索后缀 | 加分 |
| **勒索信 `ransom_note_*`** | 文件名命中 `readme/decrypt/ransom/...` 且内容含 bitcoin/wallet/decryption key 等标记 → 确认；仅文件名命中 → 预警 | Critical / Warning |
| **诱饵文件 `canary_touched`** | canary 目录内任何文件被创建/修改/重命名/删除，**立即**触发，无需等待窗口 | Critical |

多信号评分叠加：熵激增 85 分（单项即 Critical），扩展名变更 60 分，可疑后缀 25 分；
阈值 `score_critical=80`、`score_warning=60`。

## 为什么压缩/备份软件不会误报

这是设计时的硬约束，通过三层机制保证：

1. **格式白名单**：`.gz/.zip/.zst/.7z/.tar/.dmg/.jpg/.mp4/.pdf/...` 等高熵格式的
   新文件被排除在熵计数器之外（`entropy.rs::TRUSTED_HIGH_ENTROPY_EXTENSIONS`），
   但仍参与扩展名分析。
2. **进程白名单**：`tar/gzip/rsync/restic/borg/tmutil/rclone/...` 等备份压缩工具
   即使被 lsof 归因命中，也不会被挂起（`config.rs::DEFAULT_TRUSTED_PROCESSES`，可在
   配置文件扩展）。
3. **基线对比**：判定不只看绝对熵，还看"同一文件相对磁盘基线的熵跃升"——编译器输出
   的 `.o`/二进制是新建文件、没有低熵基线突变，也没有批量换扩展名，因此不触发。

## 响应闭环

Critical 告警触发后（每 10 秒最多一次完整响应，避免单个加密器刷出几十个事件夹）：

1. **归因**：后台 `lsof +D` 采样线程（250ms 轮询）持续记录监控目录下的打开句柄，
   告警时直接读取最新快照，精确定位到 PID + 当前打开的文件，不阻塞事件循环。
2. **挂起**：对非可信进程发送 `SIGSTOP` 冻结（可用 `kill -CONT <pid>` 恢复）。
   带安全护栏：绝不挂起自身、祖先进程、PID 1 以及 `launchd/kernel_task/WindowServer`
   等系统关键进程。
3. **取证**：在 `state_dir/incidents/incident-<时间戳>/` 写入
   - `scene.json`：告警详情、归因结果、被挂起进程
   - `lsof_snapshot.tsv`：打开句柄快照
   - `process_<pid>.txt`：`ps` 进程详情
   - `openfiles_<pid>.txt`：该进程的完整打开文件表
4. **审计**：所有告警以 JSONL 追加到 `ransomguard-events.jsonl`。

## 架构

```
 FSEvents (notify crate)
      │  递归监控 + 120ms 去抖 + rename 两半配对
      ▼
  watcher.rs ──FsEvent──▶ engine.rs（单线程事件循环，无锁）
                              │
            ┌─────────────────┼──────────────────┐
            ▼                 ▼                  ▼
      canary 即时判定    note 内容/文件名     滚动窗口评分
                                          （熵/扩展名/后缀）
                                                            │ Critical
                                                            ▼
            sampler.rs（后台 lsof 轮询）──▶ main.rs 归因 → SIGSTOP + 取证
```

关键工程细节：
- **路径规范化**：FSEvents 上报真实路径（`/private/var/...`）而调用方可能给软链路径
  （`/var/...`），引擎入口统一 `canonicalize`，保证 canary 和基线查找不失效。
- **启动宽限期**：部署 canary 产生的 FSEvents 在 watcher 安装后才送达，启动后
  1.5 秒内的事件被丢弃，检测器不会抓自己。
- **熵采样**：对文件头+尾各 32KiB 采样算 Shannon 熵，避免大文件全量读取；小于 64
  字节的文件不参与分类。

## 阈值取值依据

熵阈值 `7.4` 不是拍脑袋——在 `tests/integration.rs::calibrates_entropy_threshold_*`
中用真实内容类别标定：

| 内容 | 实测熵 (bits/byte) | 判定 |
|------|------------------|------|
| 随机/加密数据（多种大小） | 7.9+ | 高熵 ✓ |
| 256 符号均匀分布 | ≈8.0（理论上限） | 高熵 ✓ |
| 纯 ASCII 文本 | 4.5–5.5 | 低熵 ✓ |
| 重复字符 | <1.0 | 低熵 ✓ |
| gzip 压缩文本 | ≥7.4 | 高熵，但走格式白名单豁免 |

窗口/计数阈值（8 文件、60% 占比、60 秒窗口）则在端到端演示中校准：既能在加密
~8 个文件（约 4 秒）时触发，又让 30+ 文件的正常编辑、单次备份、编译输出全部不告警。

## 使用方法

```bash
# 编译
cargo build --release

# 监控目录（首次会自动在每个目录部署 .ransomguard-canary/ 诱饵）
./target/release/ransomguard --watch /path/to/docs --state-dir ./.rg-state

# 仅部署诱饵不监控
./target/release/ransomguard --watch /data --deploy-canaries-only

# 用配置文件 + 多目录
./target/release/ransomguard -c ransomguard.example.toml -w /data/a -w /data/b

# 只取证不挂起进程（观察模式）
./target/release/ransomguard --watch /data --no-suspend

# 生成示例配置
./target/release/ransomguard --print-default-config > my-config.toml
```

## 测试用模拟加密器

`sim_encryptor` 是**只碰指定目录**的测试程序，带多层防误伤护栏：目标必须是已存在的
目录、拒绝根目录和 `$HOME`、不跟随软链。用确定性 xoshiro256++ PRNG 生成随机密钥流
XOR 改写文件，然后批量重命名加后缀、投放勒索信。

```bash
# 完整攻击模拟（加密 + 换后缀 + 勒索信）
./target/release/sim_encryptor --target /tmp/testdir

# 只测熵信号（不碰 canary、不重命名、不投放勒索信）
./target/release/sim_encryptor --target /tmp/testdir --skip-hidden --no-rename --no-note

# 慢速 + 保持句柄打开，便于观察 lsof 归因
./target/release/sim_encryptor --target /tmp/testdir --delay-ms 250 --hold-open-ms 300
```

## 测试

```bash
cargo test
```

15 个测试覆盖：熵阈值标定、压缩格式识别、四类信号各自的引擎级单测、正常编辑/归档
零误报、可信进程与挂起黑名单、以及两个真实 FSEvents 端到端用例（真实子进程 +
真实 SIGSTOP，验证进程进入 `T` 停止态后自动清理）。

## 平台说明与局限

- 当前基于 macOS（FSEvents / `lsof +D` / SIGSTOP）。核心检测逻辑与平台无关，
  移植 Linux 时把 `watcher.rs`（inotify/kqueue 由 notify 抽象）和 `process.rs`
  （`/proc/<pid>/fd` 可替代 lsof）适配即可。
- 无参数全局 `lsof` 在 macOS 上不列出其他进程在共享临时目录的普通文件句柄，因此
  归因使用目录作用域的 `lsof +D`，而非全局扫描。
- 若恶意进程在两次 250ms 采样之间完成全部操作且不保持句柄，归因可能落空——此时
  四类内容信号仍会告警并固化现场，只是无法自动挂起（日志会明确说明）。
- canary 基于数据变更事件（FSEvents 不报告纯读取），因此捕获的是对诱饵的写入/
  重命名/删除；只读访问不产生事件。
