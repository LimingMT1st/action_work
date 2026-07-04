# GHA Cascade Analyzer 中文说明

GHA Cascade Analyzer 是一个面向研究场景的 GitHub Actions 生态测量与安全分析工具，重点关注工作流复用、依赖传播、可变引用漂移，以及上游 Action 变化对下游仓库的级联影响。

## 项目内容

- `src/gha_cascade_analyzer/`：核心采集与分析代码
- `scripts/`：实验辅助脚本和绘图脚本
- `tests/`：研究指标和分析逻辑的测试用例
- `docs/`：论文草稿和阶段性文档
- `.env.example`：运行配置示例

公开仓库默认不包含本地采集数据、检查点、日志、虚拟环境和私密令牌。

## 主要能力

- 采样使用 GitHub Actions 的仓库
- 收集工作流文件、工作流历史和 Marketplace 元数据
- 跟踪 tag 到 commit 的映射变化并重建漂移事件
- 构建级联依赖图用于信任传播分析
- 导出面向研究报告的 CSV 和 JSON 结果
- 生成论文图表所需的中间结果和绘图输入

## 研究问题方向

当前代码主要支持以下分析主题：

- GitHub Actions 工作流中的隐式依赖
- 可变引用带来的信任不稳定性
- 复用 Action 的高权限影响范围
- 上游漂移到下游更新之间的暴露窗口
- 跨 owner 复用带来的级联放大效应

## 运行要求

- Python `3.11+`
- `git` 已安装并可在命令行使用
- 至少一个 GitHub Personal Access Token

## 快速开始

### 1. 克隆仓库

```bash
git clone https://github.com/LimingMT1st/action_work.git
cd action_work
```

### 2. 创建虚拟环境

```bash
python -m venv .venv
```

激活方式：

- Windows PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

- Linux 或 macOS

```bash
source .venv/bin/activate
```

### 3. 安装依赖

```bash
python -m pip install --upgrade pip
pip install -e .
```

### 4. 配置令牌

复制环境变量模板：

```bash
cp .env.example .env
```

最少需要配置：

```env
GITHUB_TOKENS=token1,token2
```

## 运行采集

```bash
python -m gha_cascade_analyzer.main
```

可选预检查：

```bash
python -m gha_cascade_analyzer.preflight_main
```

## 运行分析

```bash
python -m gha_cascade_analyzer.analysis_main
```

分析输出通常位于 `data/analysis/`，包括：

- 工作流风险汇总
- 漂移事件统计
- 级联依赖图导出
- blast radius 指标
- 暴露窗口统计
- 绘图输入文件

## 漂移实验建议

如果你要分析可变引用漂移，建议进行多轮采集：

1. 先运行一次 `python -m gha_cascade_analyzer.main`
2. 间隔数小时或数天后再次运行同一命令
3. 最后运行 `python -m gha_cascade_analyzer.analysis_main`

这样工具才能基于不同时刻的快照重建漂移事件和暴露窗口。

## 常用路径

- `scripts/linux/run_collection.sh`
- `scripts/linux/run_analysis.sh`
- `scripts/linux/run_analysis_and_figures.sh`
- `scripts/plot_paper_figures.py`
- `docs/section_iv_icse_draft.md`

## 说明

- 这个仓库以代码为主，不直接附带完整采集数据
- 私密配置和本地运行状态已被排除
- 部分脚本默认假设 `data/` 下已经有预先采集的研究数据
