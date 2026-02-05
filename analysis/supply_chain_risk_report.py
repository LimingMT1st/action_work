# 生成供应链风险分析报告
# analysis/supply_chain_risk_report.py
import pandas as pd
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import markdown
from jinja2 import Template

from utils.file_utils import load_json, save_json, ensure_dir

class SupplyChainRiskReport:
    """供应链风险报告生成器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
        self.output_dir = Path("output/reports")
        ensure_dir(self.output_dir)
    
    def generate_report(self, report_type: str = 'comprehensive') -> Dict:
        """生成供应链风险报告"""
        self.logger.info(f"生成{report_type}供应链风险报告...")
        
        report_data = {
            'metadata': self._generate_metadata(),
            'executive_summary': {},
            'risk_assessment': {},
            'detailed_analysis': {},
            'recommendations': {},
            'appendix': {}
        }
        
        try:
            # 生成执行摘要
            report_data['executive_summary'] = self._generate_executive_summary()
            
            # 生成风险评估
            report_data['risk_assessment'] = self._generate_risk_assessment()
            
            # 生成详细分析
            report_data['detailed_analysis'] = self._generate_detailed_analysis(report_type)
            
            # 生成建议
            report_data['recommendations'] = self._generate_recommendations()
            
            # 生成附录
            report_data['appendix'] = self._generate_appendix()
            
            # 保存报告
            self._save_report(report_data, report_type)
            
            # 生成可视化报告
            self._generate_visual_report(report_data, report_type)
            
            return report_data
            
        except Exception as e:
            self.logger.error(f"生成报告失败: {e}")
            return report_data
    
    def _generate_metadata(self) -> Dict:
        """生成报告元数据"""
        return {
            'report_id': f"SCR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'analysis_period': '2024-2025',
            'scope': 'GitHub Actions 供应链安全分析',
            'version': '1.0',
            'methodology': '基于依赖图分析、静态代码分析和模式检测'
        }
    
    def _generate_executive_summary(self) -> Dict:
        """生成执行摘要"""
        summary = {
            'key_findings': [],
            'overall_risk_level': 'medium',
            'impact_assessment': {},
            'immediate_concerns': []
        }
        
        try:
            # 加载安全分析数据
            security_analysis = load_json(
                str(self.processed_data_path / "security_analysis.json")
            )
            
            # 加载依赖指标
            dependency_metrics = load_json(
                str(self.processed_data_path / "dependency_metrics.json")
            )
            
            if security_analysis:
                security_summary = security_analysis.get('summary', {})
                
                # 关键发现
                summary['key_findings'] = [
                    f"发现 {security_summary.get('risky_workflows', 0)} 个高风险 workflows",
                    f"{security_summary.get('risk_percentage', 0):.1f}% 的 workflows 存在安全问题",
                    "最常见的问题：未固定 action 版本和过宽的权限设置"
                ]
                
                # 总体风险级别
                risk_percentage = security_summary.get('risk_percentage', 0)
                if risk_percentage > 30:
                    summary['overall_risk_level'] = 'critical'
                elif risk_percentage > 15:
                    summary['overall_risk_level'] = 'high'
                elif risk_percentage > 5:
                    summary['overall_risk_level'] = 'medium'
                else:
                    summary['overall_risk_level'] = 'low'
                
                # 影响评估
                summary['impact_assessment'] = {
                    'potential_impact': 'high',
                    'attack_surface': 'large',
                    'remediation_effort': 'medium',
                    'business_impact': 'significant'
                }
                
                # 立即关注的问题
                if security_analysis.get('high_risk_workflows'):
                    high_risk_workflows = security_analysis['high_risk_workflows'][:3]
                    summary['immediate_concerns'] = [
                        {
                            'issue': workflow.get('workflow_name', 'unknown'),
                            'risk_level': workflow.get('risk_level', 'medium'),
                            'description': f"发现 {len(workflow.get('issues', []))} 个安全问题"
                        }
                        for workflow in high_risk_workflows
                    ]
            
            return summary
            
        except Exception as e:
            self.logger.error(f"生成执行摘要失败: {e}")
            return summary
    
    def _generate_risk_assessment(self) -> Dict:
        """生成风险评估"""
        risk_assessment = {
            'risk_matrix': {},
            'threat_model': {},
            'vulnerability_analysis': {},
            'impact_analysis': {}
        }
        
        try:
            # 加载安全分析数据
            security_analysis = load_json(
                str(self.processed_data_path / "security_analysis.json")
            )
            
            if security_analysis:
                # 风险矩阵
                risk_matrix = {
                    'likelihood': ['rare', 'unlikely', 'possible', 'likely', 'certain'],
                    'impact': ['negligible', 'minor', 'moderate', 'major', 'critical'],
                    'high_risk_scenarios': [
                        {
                            'scenario': '供应链攻击（如 tj-actions 事件）',
                            'likelihood': 'likely',
                            'impact': 'critical',
                            'risk_level': 'high'
                        },
                        {
                            'scenario': 'Secrets 泄露',
                            'likelihood': 'possible',
                            'impact': 'major',
                            'risk_level': 'high'
                        },
                        {
                            'scenario': '权限提升',
                            'likelihood': 'unlikely',
                            'impact': 'critical',
                            'risk_level': 'medium'
                        }
                    ]
                }
                
                risk_assessment['risk_matrix'] = risk_matrix
                
                # 威胁模型
                threat_model = {
                    'attack_vectors': [
                        '第三方 action 篡改',
                        '依赖链攻击',
                        'Secrets 窃取',
                        '权限滥用',
                        '构建环境污染'
                    ],
                    'threat_actors': [
                        '外部攻击者',
                        '恶意内部人员',
                        '供应链攻击者',
                        '自动化攻击工具'
                    ],
                    'assets_at_risk': [
                        '源代码',
                        '构建制品',
                        '部署凭证',
                        '云服务凭证',
                        'API 密钥'
                    ]
                }
                
                risk_assessment['threat_model'] = threat_model
                
                # 漏洞分析
                vulnerability_analysis = {
                    'common_vulnerabilities': [],
                    'vulnerability_distribution': {},
                    'exploit_complexity': 'low',
                    'remediation_complexity': 'medium'
                }
                
                # 统计漏洞类型
                if security_analysis.get('high_risk_workflows'):
                    vulnerability_counts = {}
                    for workflow in security_analysis['high_risk_workflows']:
                        for issue in workflow.get('issues', []):
                            issue_type = issue.get('type', 'unknown')
                            vulnerability_counts[issue_type] = vulnerability_counts.get(issue_type, 0) + 1
                    
                    vulnerability_analysis['common_vulnerabilities'] = [
                        {'type': vuln_type, 'count': count}
                        for vuln_type, count in sorted(
                            vulnerability_counts.items(), 
                            key=lambda x: x[1], 
                            reverse=True
                        )[:10]
                    ]
                
                risk_assessment['vulnerability_analysis'] = vulnerability_analysis
                
                # 影响分析
                impact_analysis = {
                    'potential_impacts': [
                        '代码注入和执行',
                        '敏感数据泄露',
                        '构建环境破坏',
                        '部署凭证失窃',
                        '云资源滥用'
                    ],
                    'business_impact': {
                        'financial': 'high',
                        'reputational': 'high',
                        'operational': 'medium',
                        'compliance': 'high'
                    },
                    'worst_case_scenario': '完整的供应链攻击导致大规模数据泄露和系统破坏'
                }
                
                risk_assessment['impact_analysis'] = impact_analysis
            
            return risk_assessment
            
        except Exception as e:
            self.logger.error(f"生成风险评估失败: {e}")
            return risk_assessment
    
    def _generate_detailed_analysis(self, report_type: str) -> Dict:
        """生成详细分析"""
        detailed_analysis = {
            'dependency_analysis': {},
            'security_analysis': {},
            'trend_analysis': {},
            'case_studies': []
        }
        
        try:
            # 依赖分析
            dependency_metrics = load_json(
                str(self.processed_data_path / "dependency_metrics.json")
            )
            
            if dependency_metrics:
                detailed_analysis['dependency_analysis'] = {
                    'graph_metrics': dependency_metrics.get('basic_metrics', {}),
                    'depth_analysis': dependency_metrics.get('dependency_depth_metrics', {}),
                    'complexity_metrics': dependency_metrics.get('complexity_metrics', {}),
                    'critical_paths': dependency_metrics.get('critical_path_analysis', {})
                }
            
            # 安全分析
            security_analysis = load_json(
                str(self.processed_data_path / "security_analysis.json")
            )
            
            if security_analysis:
                detailed_analysis['security_analysis'] = {
                    'workflow_security': security_analysis.get('summary', {}),
                    'high_risk_patterns': self._extract_high_risk_patterns(security_analysis),
                    'supply_chain_risks': self._extract_supply_chain_risks()
                }
            
            # 趋势分析
            trend_analysis = load_json(
                str(self.processed_data_path / "trend_analysis.json")
            )
            
            if trend_analysis:
                detailed_analysis['trend_analysis'] = {
                    'usage_trends': trend_analysis.get('summary', {}),
                    'emerging_risks': self._identify_emerging_risks()
                }
            
            # 案例研究
            detailed_analysis['case_studies'] = self._generate_case_studies()
            
            return detailed_analysis
            
        except Exception as e:
            self.logger.error(f"生成详细分析失败: {e}")
            return detailed_analysis
    
    def _generate_recommendations(self) -> Dict:
        """生成建议"""
        recommendations = {
            'immediate_actions': [],
            'short_term_improvements': [],
            'long_term_strategy': [],
            'priority_matrix': {}
        }
        
        # 立即行动
        recommendations['immediate_actions'] = [
            {
                'action': '审查并固定所有未固定版本的 actions',
                'priority': 'high',
                'effort': 'low',
                'impact': 'high'
            },
            {
                'action': '限制高权限 workflow 的 GITHUB_TOKEN 权限',
                'priority': 'high',
                'effort': 'medium',
                'impact': 'high'
            },
            {
                'action': '移除 workflow 中的硬编码秘密',
                'priority': 'critical',
                'effort': 'medium',
                'impact': 'high'
            },
            {
                'action': '审查高风险第三方 actions',
                'priority': 'medium',
                'effort': 'high',
                'impact': 'medium'
            }
        ]
        
        # 短期改进
        recommendations['short_term_improvements'] = [
            {
                'action': '实施 action 依赖的安全审查流程',
                'priority': 'medium',
                'effort': 'medium',
                'impact': 'high'
            },
            {
                'action': '建立供应链风险监控机制',
                'priority': 'medium',
                'effort': 'high',
                'impact': 'high'
            },
            {
                'action': '对高风险 actions 制定迁移计划',
                'priority': 'low',
                'effort': 'high',
                'impact': 'medium'
            },
            {
                'action': '实施自动化安全扫描',
                'priority': 'high',
                'effort': 'medium',
                'impact': 'high'
            }
        ]
        
        # 长期策略
        recommendations['long_term_strategy'] = [
            {
                'action': '建立完整的安全开发生命周期（SDLC）',
                'priority': 'medium',
                'effort': 'high',
                'impact': 'high'
            },
            {
                'action': '实施自动化合规检查',
                'priority': 'low',
                'effort': 'high',
                'impact': 'medium'
            },
            {
                'action': '建立供应链安全审计流程',
                'priority': 'medium',
                'effort': 'high',
                'impact': 'high'
            },
            {
                'action': '开发安全培训计划',
                'priority': 'low',
                'effort': 'medium',
                'impact': 'low'
            }
        ]
        
        # 优先级矩阵
        recommendations['priority_matrix'] = {
            'high_priority_high_impact': [
                '固定 action 版本',
                '限制权限',
                '移除硬编码秘密'
            ],
            'high_priority_low_impact': [
                '实施基础安全扫描'
            ],
            'low_priority_high_impact': [
                '建立完整的安全流程'
            ],
            'low_priority_low_impact': [
                '开发安全培训'
            ]
        }
        
        return recommendations
    
    def _generate_appendix(self) -> Dict:
        """生成附录"""
        appendix = {
            'glossary': {
                '供应链攻击': '通过攻击软件依赖链来影响最终用户的攻击方式',
                'CI/CD': '持续集成/持续部署',
                'GITHUB_TOKEN': 'GitHub Actions 自动创建的访问令牌',
                'Secrets': '存储在 GitHub 中的敏感信息',
                'Dependency Graph': '显示组件之间依赖关系的图',
                'Action Pinning': '使用完整 commit SHA 固定 action 版本',
                'Least Privilege': '最小权限原则'
            },
            'references': [
                'GitHub Actions Security Hardening',
                'OWASP Top 10 CI/CD Security Risks',
                'NIST Cybersecurity Framework',
                'tj-actions/changed-files 供应链攻击分析报告'
            ],
            'tools_used': [
                'GitHub API',
                'NetworkX (图分析)',
                'Plotly (可视化)',
                '自定义分析脚本'
            ],
            'methodology_details': {
                'data_collection': '通过 GitHub API 收集仓库和 workflow 数据',
                'analysis_methods': ['静态代码分析', '依赖图分析', '模式匹配', '风险评估'],
                'limitations': ['仅分析公开仓库', '依赖 GitHub API 限制', '时间序列数据有限']
            }
        }
        
        return appendix
    
    def _extract_high_risk_patterns(self, security_analysis: Dict) -> List[Dict]:
        """提取高风险模式"""
        high_risk_patterns = []
        
        try:
            if security_analysis.get('high_risk_workflows'):
                for workflow in security_analysis['high_risk_workflows'][:10]:
                    for issue in workflow.get('issues', []):
                        if issue.get('severity') in ['critical', 'high']:
                            high_risk_patterns.append({
                                'pattern': issue.get('type', 'unknown'),
                                'workflow': workflow.get('workflow_name', 'unknown'),
                                'severity': issue.get('severity', 'medium'),
                                'description': issue.get('description', '')
                            })
            
            # 去重并统计
            pattern_counts = {}
            for pattern in high_risk_patterns:
                pattern_type = pattern['pattern']
                pattern_counts[pattern_type] = pattern_counts.get(pattern_type, 0) + 1
            
            # 转换为列表并排序
            result = [
                {'pattern': pattern, 'count': count}
                for pattern, count in sorted(
                    pattern_counts.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )
            ]
            
            return result
            
        except Exception:
            return []
    
    def _extract_supply_chain_risks(self) -> List[Dict]:
        """提取供应链风险"""
        supply_chain_risks = []
        
        try:
            # 加载 action 安全分析
            action_security = load_json(
                str(self.processed_data_path / "action_security_analysis.json")
            )
            
            if action_security:
                risks = action_security.get('supply_chain_risks', [])
                supply_chain_risks = risks[:10]  # 只取前10个
            
            return supply_chain_risks
            
        except Exception:
            return []
    
    def _identify_emerging_risks(self) -> List[Dict]:
        """识别新兴风险"""
        emerging_risks = [
            {
                'risk': 'AI/ML action 的快速采用',
                'description': 'AI 相关的 actions 快速流行，但安全审查不足',
                'trend': 'increasing',
                'potential_impact': 'high'
            },
            {
                'risk': '复杂依赖链的增长',
                'description': 'Actions 之间的依赖关系越来越复杂',
                'trend': 'increasing',
                'potential_impact': 'medium'
            },
            {
                'risk': '自动化攻击工具的普及',
                'description': '针对供应链攻击的自动化工具越来越普及',
                'trend': 'increasing',
                'potential_impact': 'high'
            },
            {
                'risk': '多云部署的复杂性',
                'description': '跨云平台的部署增加安全配置的复杂性',
                'trend': 'stable',
                'potential_impact': 'medium'
            }
        ]
        
        return emerging_risks
    
    def _generate_case_studies(self) -> List[Dict]:
        """生成案例研究"""
        case_studies = [
            {
                'title': 'tj-actions/changed-files 供应链攻击',
                'date': '2025年3月',
                'impact': '影响数千个仓库，泄露 CI/CD secrets',
                'attack_vector': '通过篡改 action 标签注入恶意代码',
                'root_cause': '未固定 action 版本 + 过宽的权限',
                'lessons_learned': [
                    '必须固定所有第三方 actions 的版本',
                    '遵循最小权限原则',
                    '实施供应链安全监控'
                ],
                'prevention_measures': [
                    '使用完整 commit SHA 固定版本',
                    '限制 GITHUB_TOKEN 权限',
                    '定期审查第三方依赖'
                ]
            },
            {
                'title': 'CodeCov 供应链攻击',
                'date': '2021年4月',
                'impact': '泄露环境变量和 secrets',
                'attack_vector': '篡改 CodeCov 的 bash uploader 脚本',
                'root_cause': '下载脚本时未验证完整性',
                'lessons_learned': [
                    '验证下载文件的完整性',
                    '监控外部依赖的变化',
                    '建立软件物料清单（SBOM）'
                ],
                'prevention_measures': [
                    '使用 checksum 验证文件完整性',
                    '实施供应链安全扫描',
                    '建立软件供应链安全框架'
                ]
            },
            {
                'title': 'SolarWinds 供应链攻击',
                'date': '2020年12月',
                'impact': '影响18000个组织，大规模数据泄露',
                'attack_vector': '在软件构建过程中注入恶意代码',
                'root_cause': '构建环境安全控制不足',
                'lessons_learned': [
                    '保护构建环境的完整性',
                    '实施代码签名和验证',
                    '建立端到端的供应链安全'
                ],
                'prevention_measures': [
                    '实施代码签名',
                    '保护 CI/CD 管道',
                    '定期进行供应链安全审计'
                ]
            }
        ]
        
        return case_studies
    
    def _save_report(self, report_data: Dict, report_type: str):
        """保存报告数据"""
        # 保存 JSON 格式
        json_file = self.output_dir / f"supply_chain_risk_report_{report_type}.json"
        save_json(report_data, str(json_file))
        
        # 保存 Markdown 格式
        md_file = self.output_dir / f"supply_chain_risk_report_{report_type}.md"
        self._save_markdown_report(report_data, md_file)
        
        # 保存 HTML 格式
        html_file = self.output_dir / f"supply_chain_risk_report_{report_type}.html"
        self._save_html_report(report_data, html_file)
        
        self.logger.info(f"报告已保存: {json_file}, {md_file}, {html_file}")
    
    def _save_markdown_report(self, report_data: Dict, filepath: Path):
        """保存 Markdown 报告"""
        md_content = f"""# GitHub Actions 供应链风险分析报告

## 报告信息
- **报告ID**: {report_data['metadata']['report_id']}
- **生成时间**: {report_data['metadata']['generated_at']}
- **分析范围**: {report_data['metadata']['scope']}

## 执行摘要

### 关键发现
{chr(10).join(f"- {finding}" for finding in report_data['executive_summary'].get('key_findings', []))}

### 总体风险级别: {report_data['executive_summary'].get('overall_risk_level', 'unknown').upper()}

### 立即关注的问题
{chr(10).join(f"- **{concern['issue']}**: {concern['description']} (风险级别: {concern['risk_level']})" 
              for concern in report_data['executive_summary'].get('immediate_concerns', []))}

## 详细分析

### 依赖分析
- 总依赖数量: {report_data['detailed_analysis'].get('dependency_analysis', {}).get('graph_metrics', {}).get('total_dependencies', 0)}
- 最大依赖深度: {report_data['detailed_analysis'].get('dependency_analysis', {}).get('depth_analysis', {}).get('max_depth', 0)}

### 安全分析
发现的高风险模式:
{chr(10).join(f"- {pattern['pattern']}: {pattern['count']} 次" 
              for pattern in report_data['detailed_analysis'].get('security_analysis', {}).get('high_risk_patterns', [])[:5])}

## 建议

### 立即行动
{chr(10).join(f"1. **{action['action']}** (优先级: {action['priority']}, 工作量: {action['effort']})" 
              for action in report_data['recommendations'].get('immediate_actions', [])[:3])}

### 案例研究
{chr(10).join(f"#### {case['title']}\n- 影响: {case['impact']}\n- 根本原因: {case['root_cause']}" 
              for case in report_data['detailed_analysis'].get('case_studies', [])[:2])}

---
*报告生成于 {datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')}*
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
    
    def _save_html_report(self, report_data: Dict, filepath: Path):
        """保存 HTML 报告"""
        html_template = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Actions 供应链风险分析报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .section { margin: 30px 0; padding: 20px; border-left: 4px solid #007acc; }
        .risk-high { color: #d9534f; font-weight: bold; }
        .risk-medium { color: #f0ad4e; font-weight: bold; }
        .risk-low { color: #5cb85c; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .recommendation { background: #e7f3fe; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .case-study { background: #f9f9f9; padding: 15px; margin: 10px 0; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GitHub Actions 供应链风险分析报告</h1>
        <p><strong>报告ID:</strong> {{ metadata.report_id }}</p>
        <p><strong>生成时间:</strong> {{ metadata.generated_at }}</p>
        <p><strong>分析范围:</strong> {{ metadata.scope }}</p>
    </div>
    
    <div class="section">
        <h2>执行摘要</h2>
        <h3>关键发现</h3>
        <ul>
            {% for finding in executive_summary.key_findings %}
            <li>{{ finding }}</li>
            {% endfor %}
        </ul>
        
        <h3>总体风险级别: 
            <span class="risk-{{ executive_summary.overall_risk_level }}">
                {{ executive_summary.overall_risk_level|upper }}
            </span>
        </h3>
        
        {% if executive_summary.immediate_concerns %}
        <h3>立即关注的问题</h3>
        <ul>
            {% for concern in executive_summary.immediate_concerns %}
            <li><strong>{{ concern.issue }}</strong>: {{ concern.description }} 
                (风险级别: <span class="risk-{{ concern.risk_level }}">{{ concern.risk_level }}</span>)</li>
            {% endfor %}
        </ul>
        {% endif %}
    </div>
    
    <div class="section">
        <h2>详细分析</h2>
        
        <h3>依赖分析</h3>
        <table>
            <tr>
                <th>指标</th>
                <th>值</th>
            </tr>
            <tr>
                <td>总依赖数量</td>
                <td>{{ detailed_analysis.dependency_analysis.graph_metrics.total_dependencies|default(0) }}</td>
            </tr>
            <tr>
                <td>最大依赖深度</td>
                <td>{{ detailed_analysis.dependency_analysis.depth_analysis.max_depth|default(0) }}</td>
            </tr>
        </table>
        
        {% if detailed_analysis.security_analysis.high_risk_patterns %}
        <h3>高风险模式</h3>
        <table>
            <tr>
                <th>模式类型</th>
                <th>出现次数</th>
            </tr>
            {% for pattern in detailed_analysis.security_analysis.high_risk_patterns[:5] %}
            <tr>
                <td>{{ pattern.pattern }}</td>
                <td>{{ pattern.count }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>
    
    <div class="section">
        <h2>建议</h2>
        
        <h3>立即行动</h3>
        {% for action in recommendations.immediate_actions[:3] %}
        <div class="recommendation">
            <h4>{{ action.action }}</h4>
            <p>优先级: <span class="risk-{{ action.priority }}">{{ action.priority|upper }}</span> | 
               工作量: {{ action.effort }} | 影响: {{ action.impact }}</p>
        </div>
        {% endfor %}
    </div>
    
    {% if detailed_analysis.case_studies %}
    <div class="section">
        <h2>案例研究</h2>
        {% for case in detailed_analysis.case_studies[:2] %}
        <div class="case-study">
            <h3>{{ case.title }}</h3>
            <p><strong>日期:</strong> {{ case.date }}</p>
            <p><strong>影响:</strong> {{ case.impact }}</p>
            <p><strong>根本原因:</strong> {{ case.root_cause }}</p>
            <p><strong>经验教训:</strong></p>
            <ul>
                {% for lesson in case.lessons_learned %}
                <li>{{ lesson }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    <div class="section">
        <p><em>报告生成于 {{ current_time }}</em></p>
    </div>
</body>
</html>
"""
        
        template = Template(html_template)
        current_time = datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')
        
        html_content = template.render(
            metadata=report_data['metadata'],
            executive_summary=report_data['executive_summary'],
            detailed_analysis=report_data['detailed_analysis'],
            recommendations=report_data['recommendations'],
            current_time=current_time
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_visual_report(self, report_data: Dict, report_type: str):
        """生成可视化报告"""
        # 这里可以调用可视化模块生成图表并嵌入报告中
        pass