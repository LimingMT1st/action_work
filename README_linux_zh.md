# GHA-Cascade-Analyzer Linux 部署说明

## 1. 服务器准备

建议环境：

- Ubuntu 22.04 / Debian 12 / CentOS Stream 9
- Python 3.11+
- Git
- systemd

安装基础依赖：

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

检查版本：

```bash
python3 --version
git --version
```

## 2. 拉取项目

```bash
cd /opt
sudo git clone <your-repo-url> gha-cascade-analyzer
sudo chown -R "$USER":"$USER" /opt/gha-cascade-analyzer
cd /opt/gha-cascade-analyzer
```

## 3. 创建虚拟环境并安装

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

## 4. 配置 `.env`

复制模板：

```bash
cp .env.example .env
```

建议至少配置这些字段：

```env
GITHUB_TOKENS=ghp_xxx1,ghp_xxx2
GITHUB_MAX_CONCURRENCY=3
GITHUB_TIMEOUT_SECONDS=120

GHA_TOP_REPOSITORIES=300
GHA_MIN_STARS=50
GHA_MAX_WORKFLOWS_PER_REPOSITORY=20
GHA_MAX_HISTORY_COMMITS_PER_WORKFLOW=50
GHA_HISTORY_FETCH_CONCURRENCY=3

GHA_OUTPUT_DIR=data
GHA_CHECKPOINT_DB=data/checkpoints.sqlite3
GHA_STATE_DIR=data/state
GHA_SKIP_MARKETPLACE=true

GHA_ANALYSIS_ONLINE_RECURSIVE_EXPAND=true
GHA_ANALYSIS_REQUIRE_COMPLETE_LOCAL_DATA=true
GHA_ANALYSIS_RECURSIVE_FETCH_CONCURRENCY=4
GHA_ANALYSIS_RECURSIVE_MAX_DEPTH=4
GHA_ANALYSIS_PROGRESS_REPORT_INTERVAL=10

GHA_GIT_BIN=git
```

说明：

- 漂移事件实验需要多轮运行，请保持同一个 `data/` 目录。
- 不要在中途删除 `data/refs/` 和 `data/checkpoints.sqlite3`。

## 5. 首次手动预检查

```bash
source .venv/bin/activate
export PYTHONPATH=src
python -m gha_cascade_analyzer.preflight_main
```

## 6. 首次手动运行

先采集：

```bash
source .venv/bin/activate
export PYTHONPATH=src
python -m gha_cascade_analyzer.main
```

再分析：

```bash
source .venv/bin/activate
export PYTHONPATH=src
python -m gha_cascade_analyzer.analysis_main
```

## 7. 定时运行脚本

仓库内已提供：

- `scripts/linux/run_collection.sh`
- `scripts/linux/run_analysis.sh`
- `scripts/linux/install_systemd_timer.sh`
- `scripts/linux/cron_example.txt`
- `scripts/linux/start_analysis_detached.sh`
- `scripts/linux/start_collection_detached.sh`
- `scripts/linux/check_analysis_status.sh`
- `scripts/linux/stop_analysis_detached.sh`

先赋予执行权限：

```bash
chmod +x scripts/linux/run_collection.sh
chmod +x scripts/linux/run_analysis.sh
chmod +x scripts/linux/install_systemd_timer.sh
chmod +x scripts/linux/start_analysis_detached.sh
chmod +x scripts/linux/start_collection_detached.sh
chmod +x scripts/linux/check_analysis_status.sh
chmod +x scripts/linux/stop_analysis_detached.sh
```

## 7.1 长时间在线分析的推荐启动方式

不要直接在 VSCode 远程终端里运行：

```bash
python -m gha_cascade_analyzer.analysis_main
```

因为 VSCode 断线、窗口关闭或 SSH 会话异常时，交互终端上的长任务很容易中断。

推荐改用 detached 方式启动：

```bash
./scripts/linux/start_analysis_detached.sh
```

该脚本会自动选择可用的后台运行方式：

- 优先 `systemd-run`
- 若当前环境没有 `systemd-run`，则回退到 `tmux`
- 若 `tmux` 也不可用，则回退到 `nohup`

查看状态：

```bash
./scripts/linux/check_analysis_status.sh
```

查看实时日志：

```bash
journalctl --user -u gha-cascade-analysis -f
tail -f logs/analysis.log
```

停止任务：

```bash
./scripts/linux/stop_analysis_detached.sh
```

同理，采集阶段也建议使用：

```bash
./scripts/linux/start_collection_detached.sh
```

如需任务完成通知，可在 `.env` 或当前 shell 中配置：

```bash
export GHA_NOTIFY_WEBHOOK_URL="https://your-webhook-endpoint"
```

后台任务在启动、成功结束或失败时会尝试发送一条简单 webhook 通知。

## 8. 使用 systemd 定时

安装用户级 timer：

```bash
./scripts/linux/install_systemd_timer.sh
```

默认计划：

- 每天 `00:00 / 06:00 / 12:00 / 18:00` 执行采集
- 每天 `02:30` 执行分析

查看状态：

```bash
systemctl --user list-timers | grep gha-cascade
systemctl --user status gha-cascade-collect.timer
systemctl --user status gha-cascade-analyze.timer
```

查看日志：

```bash
tail -f logs/collection.log
tail -f logs/analysis.log
```

如果希望用户退出登录后 timer 仍继续运行，可开启 linger：

```bash
sudo loginctl enable-linger "$USER"
```

## 9. 使用 cron 定时

如果服务器没有可用的 user systemd，也可以用 cron：

```bash
crontab -e
```

将 `scripts/linux/cron_example.txt` 中的内容按实际路径调整后粘进去。

## 10. 结果文件

重点关注：

- `data/refs/ref_observations.jsonl`
- `data/drift_events.jsonl`
- `data/analysis/drift_events_enriched.csv`
- `data/analysis/drift_distribution.csv`
- `data/analysis/drift_observation_coverage.csv`
- `data/analysis/exposure_windows.csv`
- `data/analysis/exposure_window_summary.csv`

## 11. 运行建议

为了回答漂移相关 RQ，建议：

1. 至少连续运行 3 到 7 天
2. 采集保持 6 小时间隔
3. 使用固定 `.env`
4. 不要频繁更换输出目录
