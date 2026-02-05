# GitHub Actions 供应链分析工具

一个全面的工具，用于分析 GitHub Actions 的依赖关系和供应链安全风险。

## 功能特性

### 数据收集
- 爬取 GitHub 热门仓库（按星数排名）
- 提取仓库中的 workflows 和 Actions
- 分析 Action 之间的嵌套依赖关系

### 依赖分析
- 构建仓库-Action 依赖图
- 构建 Action-Action 依赖图
- 检测循环依赖和关键路径
- 分析依赖复杂度和维护性

### 安全分析
- 检测未固定版本的 Actions
- 识别过宽的权限设置
- 发现硬编码的秘密
- 分析供应链攻击风险

### 可视化
- 交互式依赖关系图
- 时间序列趋势分析
- 安全风险仪表板
- 供应链漏洞热图

### 报告生成
- 供应链风险报告
- 安全建议和最佳实践
- 合规框架
- 执行摘要

## 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt

##################
使用方法:
python clear_data.py --all              # 清理所有数据
python clear_data.py --crawled          # 仅清理爬取的数据
python clear_data.py --analysis         # 仅清理分析结果
python clear_data.py --logs             # 仅清理日志
python clear_data.py --status           # 查看存储使用情况
python clear_data.py --help             # 显示帮助信息