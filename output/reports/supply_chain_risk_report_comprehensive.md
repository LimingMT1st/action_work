# GitHub Actions 供应链风险分析报告

## 报告信息
- **报告ID**: SCR-20260202-200829
- **生成时间**: 2026-02-02T20:08:29.011839
- **分析范围**: GitHub Actions 供应链安全分析

## 执行摘要

### 关键发现
- 发现 75 个高风险 workflows
- 85.2% 的 workflows 存在安全问题
- 最常见的问题：未固定 action 版本和过宽的权限设置

### 总体风险级别: CRITICAL

### 立即关注的问题
- **.github/workflows/main.yml**: 发现 2 个安全问题 (风险级别: high)
- **Tests of push & pull**: 发现 2 个安全问题 (风险级别: high)
- **Tests of validate package**: 发现 2 个安全问题 (风险级别: high)

## 详细分析

### 依赖分析
- 总依赖数量: 0
- 最大依赖深度: 0

### 安全分析
发现的高风险模式:
- unpinned_actions: 10 次
- high_risk_actions: 7 次

## 建议

### 立即行动
1. **审查并固定所有未固定版本的 actions** (优先级: high, 工作量: low)
1. **限制高权限 workflow 的 GITHUB_TOKEN 权限** (优先级: high, 工作量: medium)
1. **移除 workflow 中的硬编码秘密** (优先级: critical, 工作量: medium)

### 案例研究
#### tj-actions/changed-files 供应链攻击
- 影响: 影响数千个仓库，泄露 CI/CD secrets
- 根本原因: 未固定 action 版本 + 过宽的权限
#### CodeCov 供应链攻击
- 影响: 泄露环境变量和 secrets
- 根本原因: 下载脚本时未验证完整性

---
*报告生成于 2026年02月02日 20:08:29*
