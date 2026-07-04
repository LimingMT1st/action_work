# GHA-Cascade-Analyzer 使用说明

本文档介绍如何从零开始运行 `GHA-Cascade-Analyzer`，包括环境准备、数据采集、分析执行、结果查看和常见问题处理。

## 1. 工具用途

`GHA-Cascade-Analyzer` 用于研究 GitHub Actions 供应链中的级联风险，主要分为两个阶段：

1. 数据采集阶段
2. 安全分析阶段

数据采集阶段会：

- 采样高价值消费者仓库
- 下载 Workflow 文件
- 回溯 Workflow 演进历史
- 抓取 GitHub Marketplace Action 元数据
- 跟踪 Tag 到 SHA 的映射变化并识别漂移事件

安全分析阶段会：

- 构建递归级联依赖图 CDG
- 计算隐式依赖占比
- 统计版本漂移分布
- 评估爆炸半径
- 估算风险暴露窗口

## 2. 运行前准备

请先确保本机具备以下环境：

- Python `3.11` 或更高版本
- Git 已安装并可在终端中使用
- PowerShell 或其他终端
- 至少一个 GitHub Token

你可以先检查版本：

```powershell
python --version
git --version
```

如果这两个命令都能正常输出版本号，说明基础环境已经具备。

## 3. 进入项目目录

在 PowerShell 中进入项目根目录：

```powershell
cd E:\actionwork
```

如果你的项目目录不在这里，请替换成你自己的实际路径。

## 4. 创建虚拟环境

建议使用虚拟环境，避免和系统 Python 依赖冲突：

```powershell
python -m venv .venv
```

创建完成后，激活虚拟环境：

```powershell
.venv\Scripts\Activate.ps1
```

如果 PowerShell 阻止脚本执行，可以先执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
```

激活成功后，命令行前面通常会出现 `(.venv)`。

## 5. 安装依赖

先升级 `pip`，再安装项目依赖：

```powershell
python -m pip install --upgrade pip
pip install -e .
```

这里的 `-e .` 表示以开发模式安装当前项目，方便你后续继续修改代码。

## 6. 准备 GitHub Token

该工具会频繁调用 GitHub API，因此强烈建议准备多个 Token 轮询使用，以降低速率限制的影响。

你可以在 GitHub 中创建 Personal Access Token，然后在当前 PowerShell 会话中设置：

```powershell
$env:GITHUB_TOKENS="token1,token2"
```

说明：

- 多个 Token 使用英文逗号分隔
- 至少放一个有效 Token
- 这个环境变量只对当前终端会话生效

如果你只准备了一个 Token，也可以这样写：

```powershell
$env:GITHUB_TOKENS="your_github_token"
```

你也可以直接把项目根目录下的 `.env.example` 复制为 `.env`，然后把 Token 和其他动态参数写进去。程序启动时会自动读取 `.env`，这样就不需要每次手动设置环境变量。

## 7. 设置 Python 模块搜索路径

运行前请设置：

```powershell
$env:PYTHONPATH="src"
```

这样 Python 才能正确找到 `gha_cascade_analyzer` 包。

## 8. 开始执行数据采集

执行以下命令：

```powershell
python -m gha_cascade_analyzer.main
```

如果你想先做启动前检查，建议先执行：

```powershell
python -m gha_cascade_analyzer.preflight_main
```

或者：

```powershell
python -m gha_cascade_analyzer.main --preflight
```

预检查会验证：

- `.env` 是否成功加载了有效 Token
- `git` 是否可用
- GitHub API 是否可达
- 当前并发、超时、采样数量是否偏激进

这一步会自动完成以下工作：

- 采样 Star 数大于 50 的高价值非 Fork 仓库
- 拉取 `.github/workflows/` 下的 YAML 文件
- 提取 Workflow 历史 Commit
- 识别每次 `uses:` 的变化时间
- 抓取 Marketplace Actions 元数据
- 对发现的 Action 执行 Tag 漂移追踪
- 在终端打印当前实际配置和阶段性进度
- 将不中断主流程的异常记录到 `data/errors.jsonl`

如果数据量较大，这一步可能会运行很久，这是正常现象。

## 9. 断点续传说明

本工具支持断点续传。

断点信息保存在：

- `data/checkpoints.sqlite3`

因此，如果采集中断了，不需要删除数据重来，只要重新激活虚拟环境并再次执行：

```powershell
python -m gha_cascade_analyzer.main
```

它会尽量从上次状态继续执行。

## 10. 开始执行安全分析

当采集阶段完成后，执行：

```powershell
python -m gha_cascade_analyzer.analysis_main
```

分析阶段会读取 `data/` 目录中的采集结果，并输出研究问题 RQ1-RQ4 所需的统计结果。

分析阶段默认是“纯本地离线模式”，只读取 `data/` 下已经采集好的文件，不会主动联网补抓数据。

只有当你显式设置：

```env
GHA_ANALYSIS_ONLINE_RECURSIVE_EXPAND=true
```

分析阶段才会继续联网递归解析 Composite Action 和 Reusable Workflow 的嵌套依赖。

如果你保持默认配置：

```env
GHA_ANALYSIS_REQUIRE_COMPLETE_LOCAL_DATA=true
```

那么只要本地采集文件不完整，分析就会直接报出缺失项，而不会边采边分析。

## 11. 推荐完整执行顺序

你可以严格按下面步骤操作：

1. 打开 PowerShell
2. 进入项目目录 `E:\actionwork`
3. 创建虚拟环境 `python -m venv .venv`
4. 激活虚拟环境 `.venv\Scripts\Activate.ps1`
5. 安装依赖 `pip install -e .`
6. 设置 Token：`$env:GITHUB_TOKENS="token1,token2"`
7. 设置模块路径：`$env:PYTHONPATH="src"`
8. 运行采集：`python -m gha_cascade_analyzer.main`
9. 运行分析：`python -m gha_cascade_analyzer.analysis_main`
10. 查看 `data/analysis/` 目录中的结果文件

## 12. 结果文件说明

### 采集结果

- `data/repositories.jsonl`
  高价值消费者仓库列表

- `data/workflows/*.jsonl`
  当前采集到的 Workflow 快照

- `data/workflow_history/*.jsonl`
  Workflow 中 `uses:` 字段的演进历史

- `data/marketplace/actions.jsonl`
  Marketplace Action 元数据身份库

- `data/actions/discovered.jsonl`
  识别出的 Action 节点集合

- `data/refs/tag_observations.jsonl`
  每次观测到的 Tag 到 SHA 映射

- `data/drift_events.jsonl`
  检测到的版本漂移事件

- `data/errors.jsonl`
  采集过程中出现的非致命错误记录，方便后续补跑和排障

### 分析结果

- `data/analysis/report.json`
  总体分析报告

- `data/analysis/cdg_edges.json`
  级联依赖图边数据，JSON 格式

- `data/analysis/cdg_edges.csv`
  级联依赖图边数据，CSV 格式

- `data/analysis/workflow_implicit_ratio.csv`
  RQ1：每个 Workflow 的隐式依赖占比

- `data/analysis/drift_distribution.csv`
  RQ2：按 Action 类型和作者验证等级统计的漂移事件分布

- `data/analysis/blast_radius.csv`
  RQ3：每个 Action 的影响力和高价值下游覆盖范围

- `data/analysis/exposure_windows.csv`
  RQ4：上游事件到下游更新之间的时间窗口

## 13. 可选环境变量

如果你想调整规模或性能，可以设置这些变量：

```powershell
$env:GHA_TOP_REPOSITORIES="2000"
$env:GHA_MIN_STARS="50"
$env:GITHUB_MAX_CONCURRENCY="20"
$env:GITHUB_TIMEOUT_SECONDS="30"
$env:GHA_OUTPUT_DIR="data"
$env:GHA_CHECKPOINT_DB="data/checkpoints.sqlite3"
$env:GHA_STATE_DIR="data/state"
$env:GHA_SKIP_MARKETPLACE="false"
$env:GHA_GIT_BIN="git"
```

说明：

- `GHA_TOP_REPOSITORIES`
  要采样的仓库数量上限

- `GHA_MIN_STARS`
  仓库最低 Star 阈值

- `GITHUB_MAX_CONCURRENCY`
  并发请求数，过高可能更容易触发限流

- `GITHUB_TIMEOUT_SECONDS`
  单个请求超时时间

- `GHA_OUTPUT_DIR`
  输出目录

- `GHA_CHECKPOINT_DB`
  断点数据库路径

- `GHA_GIT_BIN`
  Git 可执行文件路径

- `GHA_SKIP_MARKETPLACE`
  是否跳过 Marketplace 爬取；当 `github.com/marketplace` 连通性较差时建议设为 `true`

## 14. 常见问题

### 14.1 `git` 找不到

如果运行时报 `git` 不存在，请先确认：

```powershell
git --version
```

如果命令失败，说明 Git 未安装或未加入环境变量。

你也可以手动指定 Git 路径，例如：

```powershell
$env:GHA_GIT_BIN="C:\Program Files\Git\bin\git.exe"
```

### 14.2 PowerShell 不允许激活虚拟环境

执行：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

然后重新激活：

```powershell
.venv\Scripts\Activate.ps1
```

### 14.3 GitHub API 速率限制

如果你遇到限流问题，可以这样处理：

- 增加 Token 数量
- 降低并发数：`$env:GITHUB_MAX_CONCURRENCY="10"`
- 分批执行采集

### 14.6 访问 `github.com/marketplace` 超时

如果你遇到类似下面的错误：

- `Cannot connect to host github.com:443`
- `WinError 121`

通常说明当前网络到 `github.com/marketplace` 的连接不稳定。你可以先在 `.env` 中设置：

```env
GHA_SKIP_MARKETPLACE=true
```

然后重新运行：

```powershell
python -m gha_cascade_analyzer.main
```

这样会跳过 Marketplace 身份库抓取，但不会阻塞仓库采样、Workflow 历史追踪和 Tag 漂移检测。

### 14.4 分析阶段没有递归展开 Composite Action

这通常是因为分析时没有设置 `GITHUB_TOKENS`。

请确保在运行分析前重新设置：

```powershell
$env:GITHUB_TOKENS="token1,token2"
$env:PYTHONPATH="src"
python -m gha_cascade_analyzer.analysis_main
```

### 14.5 中断后如何继续

直接重新执行同一条命令即可：

```powershell
python -m gha_cascade_analyzer.main
```

不要先删除 `data/checkpoints.sqlite3`，否则会丢失断点状态。

## 15. 最简运行示例

如果你只想快速跑通一遍，可以直接按下面执行：

```powershell
cd E:\actionwork
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
$env:GITHUB_TOKENS="your_token"
$env:PYTHONPATH="src"
python -m gha_cascade_analyzer.main
python -m gha_cascade_analyzer.analysis_main
```

## 16. 建议

第一次运行时，建议先把规模调小做验证，例如：

```powershell
$env:GHA_TOP_REPOSITORIES="50"
$env:GITHUB_MAX_CONCURRENCY="5"
$env:GITHUB_TIMEOUT_SECONDS="60"
```

这样可以先确认流程、Token、输出目录和网络都正常，然后再扩大到正式规模。
目录清除指令
Remove-Item data\workflows -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item data\workflow_history -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item data\actions -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item data\refs -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item data\drift_events.jsonl -Force -ErrorAction SilentlyContinue
Remove-Item data\errors.jsonl -Force -ErrorAction SilentlyContinue
