# processors/security_analyzer.py
import re
import yaml
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from pathlib import Path
import pandas as pd

from utils.file_utils import load_json, save_json
from utils.validation import is_sensitive_variable

class SecurityAnalyzer:
    """安全分析器 - 检测潜在的安全风险"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 安全配置
        self.sensitive_patterns = config['analysis']['security']['sensitive_patterns']
        self.high_risk_actions = config['analysis']['security']['high_risk_actions']
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
    
    def analyze_workflow_security(self, workflows_data: Dict) -> Dict:
        """分析 workflow 安全风险"""
        self.logger.info("分析 workflow 安全风险...")
        
        security_findings = {
            'high_risk_workflows': [],
            'sensitive_variables': [],
            'insecure_permissions': [],
            'external_action_risks': [],
            'summary': {}
        }
        
        total_workflows = 0
        risky_workflows = 0
        
        for repo_full_name, workflows in workflows_data.items():
            for workflow in workflows:
                if not isinstance(workflow, dict):
                    continue
                
                total_workflows += 1
                workflow_name = workflow.get('name', 'unknown')
                workflow_path = workflow.get('path', '')
                content = workflow.get('content', '')
                parsed_yaml = workflow.get('parsed_yaml', {})
                
                # 分析单个 workflow
                findings = self._analyze_single_workflow(
                    repo_full_name, workflow_name, workflow_path, content, parsed_yaml
                )
                
                if findings['risk_level'] != 'low':
                    risky_workflows += 1
                    security_findings['high_risk_workflows'].append(findings)
        
        # 生成摘要
        security_findings['summary'] = {
            'total_workflows_analyzed': total_workflows,
            'risky_workflows': risky_workflows,
            'risk_percentage': (risky_workflows / total_workflows * 100) if total_workflows > 0 else 0,
            'common_risks': self._summarize_common_risks(security_findings['high_risk_workflows'])
        }
        
        # 保存结果
        self._save_security_analysis(security_findings)
        
        self.logger.info(f"安全分析完成:")
        self.logger.info(f"  分析 workflows: {total_workflows}")
        self.logger.info(f"  高风险 workflows: {risky_workflows}")
        
        return security_findings
    
    def analyze_action_security(self, action_dependencies: Dict) -> Dict:
        """分析 action 安全风险"""
        self.logger.info("分析 action 安全风险...")
        
        action_risks = {
            'critical_actions': [],
            'supply_chain_risks': [],
            'permission_risks': [],
            'dependency_risks': [],
            'summary': {}
        }
        
        # 分析高频 action 的风险
        usage_file = self.processed_data_path / "action_usage_stats.csv"
        if usage_file.exists():
            df = pd.read_csv(usage_file)
            
            for _, row in df.iterrows():
                action = row['action']
                usage_count = row['usage_count']
                
                # 检查是否为高风险 action
                risk_level = self._assess_action_risk(action, usage_count)
                
                if risk_level['overall_risk'] != 'low':
                    action_risks['critical_actions'].append({
                        'action': action,
                        'usage_count': int(usage_count),
                        'risk_assessment': risk_level
                    })
        
        # 分析供应链风险
        supply_chain_risks = self._analyze_supply_chain_risks(action_dependencies)
        action_risks['supply_chain_risks'] = supply_chain_risks
        
        # 分析权限风险
        permission_risks = self._analyze_permission_risks()
        action_risks['permission_risks'] = permission_risks
        
        # 生成摘要
        action_risks['summary'] = {
            'critical_actions_count': len(action_risks['critical_actions']),
            'supply_chain_risks_count': len(action_risks['supply_chain_risks']),
            'permission_risks_count': len(action_risks['permission_risks'])
        }
        
        # 保存结果
        self._save_action_security_analysis(action_risks)
        
        return action_risks
    
    def detect_secrets_in_workflows(self, workflows_data: Dict) -> List[Dict]:
        """检测 workflow 中的潜在秘密"""
        self.logger.info("检测 workflow 中的潜在秘密...")
        
        secrets_found = []
        
        for repo_full_name, workflows in workflows_data.items():
            for workflow in workflows:
                content = workflow.get('content', '')
                if not content:
                    continue
                
                # 检测硬编码的秘密
                hardcoded_secrets = self._detect_hardcoded_secrets(content)
                
                # 检测敏感变量名
                sensitive_vars = self._detect_sensitive_variables(content)
                
                if hardcoded_secrets or sensitive_vars:
                    secrets_found.append({
                        'repo': repo_full_name,
                        'workflow': workflow.get('name', ''),
                        'path': workflow.get('path', ''),
                        'hardcoded_secrets': hardcoded_secrets,
                        'sensitive_variables': sensitive_vars,
                        'risk_level': 'high' if hardcoded_secrets else 'medium'
                    })
        
        # 保存结果
        save_json(
            secrets_found,
            str(self.processed_data_path / "detected_secrets.json")
        )
        
        self.logger.info(f"检测到 {len(secrets_found)} 个包含潜在秘密的 workflows")
        
        return secrets_found
    
    def analyze_vulnerability_patterns(self) -> Dict:
        """分析漏洞模式"""
        self.logger.info("分析漏洞模式...")
        
        patterns = {
            'common_vulnerability_patterns': [],
            'mitigation_recommendations': [],
            'case_studies': []
        }
        
        # 常见漏洞模式
        common_patterns = [
            {
                'pattern': 'pull_request_target with secrets',
                'description': '使用 pull_request_target 事件时暴露 secrets',
                'risk_level': 'critical',
                'detection_method': '检查 workflow 中的 on.pull_request_target 事件和 secrets 使用',
                'mitigation': '使用 pull_request_target 时避免访问 secrets，或使用更安全的替代方案'
            },
            {
                'pattern': 'unpinned external actions',
                'description': '未固定版本的外部 action 可能被攻击者篡改',
                'risk_level': 'high',
                'detection_method': '检查 uses 语句是否使用 SHA-1 哈希而非标签',
                'mitigation': '使用完整的 commit SHA 固定 action 版本'
            },
            {
                'pattern': 'excessive GITHUB_TOKEN permissions',
                'description': '授予过宽的 GITHUB_TOKEN 权限',
                'risk_level': 'medium',
                'detection_method': '检查 permissions 设置是否过于宽松',
                'mitigation': '遵循最小权限原则，只授予必要的权限'
            },
            {
                'pattern': 'long-lived cloud credentials',
                'description': '使用长期有效的云服务凭证',
                'risk_level': 'high',
                'detection_method': '检查是否使用 OIDC 而非长期凭证',
                'mitigation': '使用 GitHub OIDC 获取临时凭证'
            }
        ]
        
        patterns['common_vulnerability_patterns'] = common_patterns
        
        # 缓解建议
        mitigations = [
            {
                'area': '依赖管理',
                'recommendations': [
                    '固定所有外部 action 的版本为完整 commit SHA',
                    '定期更新依赖，使用 dependabot 或 renovate',
                    '使用官方认证的 action 而非第三方 action'
                ]
            },
            {
                'area': '权限控制',
                'recommendations': [
                    '遵循最小权限原则配置 GITHUB_TOKEN',
                    '使用环境保护规则和审批工作流',
                    '分离敏感操作的权限'
                ]
            },
            {
                'area': '秘密管理',
                'recommendations': [
                    '避免在 workflow 中硬编码秘密',
                    '使用 GitHub Secrets 存储敏感信息',
                    '定期轮换秘密和访问令牌'
                ]
            },
            {
                'area': '供应链安全',
                'recommendations': [
                    '审查所有第三方依赖的安全性',
                    '监控依赖的更新和安全公告',
                    '建立 SBOM（软件物料清单）'
                ]
            }
        ]
        
        patterns['mitigation_recommendations'] = mitigations
        
        # 案例研究（基于 tj-actions/changed-files 事件）
        case_studies = [
            {
                'case': 'tj-actions/changed-files 供应链攻击',
                'description': '攻击者通过篡改 action 标签，窃取 CI/CD 环境中的 secrets',
                'attack_vector': '供应链攻击，利用 action 依赖链',
                'impact': '数千个仓库的 secrets 泄露',
                'lessons_learned': [
                    '未固定 action 版本导致攻击者可以注入恶意代码',
                    '过宽的权限使得攻击者可以窃取敏感信息',
                    '缺乏对第三方 action 的审查机制'
                ],
                'prevention': [
                    '固定 action 版本为完整 SHA',
                    '限制 GITHUB_TOKEN 权限',
                    '监控异常 workflow 执行'
                ]
            }
        ]
        
        patterns['case_studies'] = case_studies
        
        # 保存结果
        save_json(
            patterns,
            str(self.processed_data_path / "vulnerability_patterns.json")
        )
        
        return patterns
    
    def generate_security_report(self) -> Dict:
        """生成安全报告"""
        self.logger.info("生成安全报告...")
        
        report = {
            'executive_summary': {},
            'risk_assessment': {},
            'recommendations': {},
            'detailed_findings': {},
            'appendix': {}
        }
        
        # 加载之前分析的结果
        try:
            # workflow 安全分析
            workflow_security = load_json(str(self.processed_data_path / "security_analysis.json"))
            
            # action 安全分析
            action_security = load_json(str(self.processed_data_path / "action_security_analysis.json"))
            
            # 漏洞模式
            vulnerability_patterns = load_json(str(self.processed_data_path / "vulnerability_patterns.json"))
            
            # 生成执行摘要
            report['executive_summary'] = self._generate_executive_summary(
                workflow_security, action_security
            )
            
            # 风险评估
            report['risk_assessment'] = self._generate_risk_assessment(
                workflow_security, action_security
            )
            
            # 建议
            report['recommendations'] = self._generate_recommendations(
                workflow_security, action_security, vulnerability_patterns
            )
            
            # 详细发现
            report['detailed_findings'] = {
                'workflow_security': workflow_security.get('high_risk_workflows', [])[:20],
                'action_security': action_security.get('critical_actions', [])[:20],
                'supply_chain_risks': action_security.get('supply_chain_risks', [])[:10]
            }
            
            # 附录
            report['appendix'] = {
                'analysis_methodology': self._get_analysis_methodology(),
                'risk_criteria': self._get_risk_criteria(),
                'tools_used': ['GitHub API', 'NetworkX', '自定义分析脚本']
            }
            
            # 保存报告
            save_json(
                report,
                str(self.processed_data_path / "security_report.json")
            )
            
            # 同时保存为 Markdown 格式便于阅读
            self._save_markdown_report(report)
            
            return report
            
        except Exception as e:
            self.logger.error(f"生成安全报告失败: {e}")
            return report
    
    def _analyze_single_workflow(self, repo: str, name: str, path: str, 
                                content: str, parsed_yaml: Dict) -> Dict:
        """分析单个 workflow 的安全风险"""
        findings = {
            'repo': repo,
            'workflow_name': name,
            'workflow_path': path,
            'risk_level': 'low',
            'issues': [],
            'recommendations': []
        }
        
        issues = []
        
        # 1. 检查是否使用 pull_request_target 并访问 secrets
        if self._has_pull_request_target_with_secrets(parsed_yaml, content):
            issues.append({
                'type': 'pull_request_target_secrets',
                'severity': 'critical',
                'description': 'Workflow 使用 pull_request_target 事件并可能暴露 secrets'
            })
        
        # 2. 检查未固定的 action 版本
        unpinned_actions = self._find_unpinned_actions(content)
        if unpinned_actions:
            issues.append({
                'type': 'unpinned_actions',
                'severity': 'high',
                'description': f'发现 {len(unpinned_actions)} 个未固定版本的 action',
                'details': unpinned_actions[:5]  # 只显示前5个
            })
        
        # 3. 检查过宽的权限
        excessive_permissions = self._check_excessive_permissions(parsed_yaml)
        if excessive_permissions:
            issues.append({
                'type': 'excessive_permissions',
                'severity': 'medium',
                'description': 'GITHUB_TOKEN 权限设置过宽',
                'details': excessive_permissions
            })
        
        # 4. 检查硬编码的秘密
        hardcoded_secrets = self._detect_hardcoded_secrets(content)
        if hardcoded_secrets:
            issues.append({
                'type': 'hardcoded_secrets',
                'severity': 'critical',
                'description': f'发现 {len(hardcoded_secrets)} 个硬编码的秘密'
            })
        
        # 5. 检查高风险 action
        high_risk_actions = self._find_high_risk_actions(content)
        if high_risk_actions:
            issues.append({
                'type': 'high_risk_actions',
                'severity': 'high',
                'description': f'使用 {len(high_risk_actions)} 个高风险 action',
                'details': high_risk_actions
            })
        
        # 确定风险级别
        if any(issue['severity'] == 'critical' for issue in issues):
            findings['risk_level'] = 'critical'
        elif any(issue['severity'] == 'high' for issue in issues):
            findings['risk_level'] = 'high'
        elif any(issue['severity'] == 'medium' for issue in issues):
            findings['risk_level'] = 'medium'
        
        findings['issues'] = issues
        
        # 生成建议
        findings['recommendations'] = self._generate_workflow_recommendations(issues)
        
        return findings
    
    def _has_pull_request_target_with_secrets(self, parsed_yaml: Dict, content: str) -> bool:
        """检查是否使用 pull_request_target 并访问 secrets"""
        if not parsed_yaml:
            return False
        
        # 检查是否有 pull_request_target 事件
        triggers = parsed_yaml.get('on', {})
        has_pr_target = False
        
        if isinstance(triggers, dict):
            has_pr_target = 'pull_request_target' in triggers
        elif isinstance(triggers, str):
            has_pr_target = triggers == 'pull_request_target'
        elif isinstance(triggers, list):
            has_pr_target = 'pull_request_target' in triggers
        
        if not has_pr_target:
            return False
        
        # 检查是否访问 secrets（简单检查）
        secret_patterns = [
            r'\$\{\{\s*secrets\.',
            r'secrets\.\w+',
            r'GITHUB_TOKEN',
            r'ACCESS_TOKEN',
            r'API_KEY'
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _find_unpinned_actions(self, content: str) -> List[str]:
        """查找未固定版本的 actions"""
        unpinned = []
        
        # 匹配 uses 语句
        uses_pattern = r'uses:\s*([^\s]+)'
        matches = re.findall(uses_pattern, content, re.IGNORECASE)
        
        for match in matches:
            action_ref = match.strip()
            
            # 跳过本地路径
            if action_ref.startswith(('./', '../')):
                continue
            
            # 检查是否使用完整 SHA（40个字符的十六进制）
            if '@' in action_ref:
                version = action_ref.split('@')[1]
                # 完整 SHA 应该是40个十六进制字符
                if not re.match(r'^[a-f0-9]{40}$', version, re.IGNORECASE):
                    unpinned.append(action_ref)
            else:
                # 没有版本号，视为未固定
                unpinned.append(action_ref)
        
        return unpinned
    
    def _check_excessive_permissions(self, parsed_yaml: Dict) -> Dict:
        """检查过宽的权限设置"""
        if not parsed_yaml:
            return {}
        
        permissions_issues = {}
        
        # 检查顶级 permissions
        top_permissions = parsed_yaml.get('permissions', {})
        if top_permissions:
            if top_permissions in ['write-all', 'read-all']:
                permissions_issues['top_level'] = {
                    'issue': '全局权限设置过宽',
                    'value': top_permissions
                }
        
        # 检查 jobs 中的 permissions
        jobs = parsed_yaml.get('jobs', {})
        for job_name, job_config in jobs.items():
            if isinstance(job_config, dict):
                job_permissions = job_config.get('permissions', {})
                if job_permissions in ['write-all', 'read-all']:
                    permissions_issues[job_name] = {
                        'issue': '任务权限设置过宽',
                        'value': job_permissions
                    }
        
        return permissions_issues
    
    def _detect_hardcoded_secrets(self, content: str) -> List[Dict]:
        """检测硬编码的秘密"""
        secrets = []
        
        # 常见秘密模式
        secret_patterns = {
            'aws_key': r'(?i)(aws_[a-z_]*key[^a-z0-9_=]?[=:]["\']?)([a-z0-9/+]{20,40})(["\']?)',
            'aws_secret': r'(?i)(aws_[a-z_]*secret[^a-z0-9_=]?[=:]["\']?)([a-z0-9/+]{40})(["\']?)',
            'api_key': r'(?i)(api[_-]?key[^a-z0-9_=]?[=:]["\']?)([a-z0-9_\-]{20,100})(["\']?)',
            'password': r'(?i)(password[^a-z0-9_=]?[=:]["\']?)([^\s"\']{6,50})(["\']?)',
            'token': r'(?i)(token[^a-z0-9_=]?[=:]["\']?)([a-z0-9_\-]{20,100})(["\']?)',
            'secret': r'(?i)(secret[^a-z0-9_=]?[=:]["\']?)([^\s"\']{10,100})(["\']?)',
        }
        
        for pattern_name, pattern in secret_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secret_value = match.group(2)
                # 跳过明显的占位符
                if any(placeholder in secret_value.lower() for placeholder in ['placeholder', 'example', 'your_']):
                    continue
                
                secrets.append({
                    'type': pattern_name,
                    'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                    'context': self._get_context(content, match.start(), 100)
                })
        
        return secrets
    
    def _find_high_risk_actions(self, content: str) -> List[str]:
        """查找高风险 actions"""
        high_risk = []
        
        for action in self.high_risk_actions:
            if action in content:
                high_risk.append(action)
        
        return high_risk
    
    def _detect_sensitive_variables(self, content: str) -> List[str]:
        """检测敏感变量名"""
        sensitive_vars = []
        
        # 匹配变量定义
        var_patterns = [
            r'^\s*([A-Z_][A-Z0-9_]*)\s*[=:]\s*',
            r'env:\s*\n(\s+[A-Z_][A-Z0-9_]*\s*[=:])',
            r'with:\s*\n(\s+[A-Za-z_][A-Za-z0-9_]*\s*[=:])'
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                var_line = match.group(0)
                # 提取变量名
                var_match = re.search(r'([A-Z_][A-Z0-9_]*)', var_line)
                if var_match:
                    var_name = var_match.group(1)
                    if is_sensitive_variable(var_name, self.sensitive_patterns):
                        sensitive_vars.append(var_name)
        
        return list(set(sensitive_vars))
    
    def _assess_action_risk(self, action: str, usage_count: int) -> Dict:
        """评估 action 的风险级别"""
        risk_factors = {
            'supply_chain_risk': 'medium',
            'permission_risk': 'low',
            'popularity_risk': 'low',
            'maintenance_risk': 'low'
        }
        
        # 供应链风险（第三方 action）
        if not action.startswith('actions/'):
            risk_factors['supply_chain_risk'] = 'high'
        
        # 权限风险（某些 action 需要高权限）
        high_permission_actions = ['actions/checkout', 'docker/login', 'azure/login']
        if action in high_permission_actions:
            risk_factors['permission_risk'] = 'high'
        
        # 流行度风险（使用越广泛，影响越大）
        if usage_count > 1000:
            risk_factors['popularity_risk'] = 'high'
        elif usage_count > 100:
            risk_factors['popularity_risk'] = 'medium'
        
        # 维护风险（根据 owner 判断）
        if action.count('/') == 1:
            owner = action.split('/')[0]
            # 简单的维护风险评估
            if owner in ['some-random-user', 'test-user']:  # 示例
                risk_factors['maintenance_risk'] = 'high'
        
        # 计算总体风险
        risk_levels = {'low': 0, 'medium': 1, 'high': 2}
        max_risk = max(risk_levels[risk] for risk in risk_factors.values())
        
        overall_risk = 'low'
        if max_risk == 2:
            overall_risk = 'high'
        elif max_risk == 1:
            overall_risk = 'medium'
        
        return {
            **risk_factors,
            'overall_risk': overall_risk
        }
    
    def _analyze_supply_chain_risks(self, action_dependencies: Dict) -> List[Dict]:
        """分析供应链风险"""
        supply_chain_risks = []
        
        # 加载依赖图数据
        graph_file = self.processed_data_path / "action_dependency_graph.json"
        if not graph_file.exists():
            return supply_chain_risks
        
        try:
            graph_data = load_json(str(graph_file))
            if not graph_data:
                return supply_chain_risks
            
            # 找出关键节点（高入度）
            nodes = graph_data.get('nodes', [])
            edges = graph_data.get('edges', [])
            
            # 计算每个节点的入度
            in_degree = defaultdict(int)
            for edge in edges:
                target = edge['target']
                in_degree[target] += 1
            
            # 找出高入度节点（被许多其他 action 依赖）
            high_in_degree_nodes = [
                (node['id'], in_degree[node['id']])
                for node in nodes
                if in_degree[node['id']] >= 3  # 被3个以上 action 依赖
            ]
            
            # 按入度排序
            high_in_degree_nodes.sort(key=lambda x: x[1], reverse=True)
            
            for action, degree in high_in_degree_nodes[:20]:  # 前20个
                # 评估供应链风险
                risk_assessment = self._assess_action_risk(action, degree)
                
                if risk_assessment['overall_risk'] != 'low':
                    supply_chain_risks.append({
                        'action': action,
                        'in_degree': degree,
                        'risk_assessment': risk_assessment,
                        'description': f'该 action 被 {degree} 个其他 action 依赖，存在供应链风险'
                    })
            
            return supply_chain_risks
            
        except Exception as e:
            self.logger.error(f"分析供应链风险失败: {e}")
            return supply_chain_risks
    
    def _analyze_permission_risks(self) -> List[Dict]:
        """分析权限风险"""
        permission_risks = []
        
        # 这里可以扩展分析具体的权限风险
        # 例如：检查哪些 action 通常需要高权限
        
        return permission_risks
    
    def _summarize_common_risks(self, high_risk_workflows: List[Dict]) -> Dict:
        """总结常见风险"""
        risk_counts = defaultdict(int)
        
        for workflow in high_risk_workflows:
            for issue in workflow.get('issues', []):
                risk_counts[issue['type']] += 1
        
        # 按数量排序
        sorted_risks = sorted(risk_counts.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'top_risks': sorted_risks[:10],
            'total_unique_risk_types': len(risk_counts)
        }
    
    def _generate_workflow_recommendations(self, issues: List[Dict]) -> List[str]:
        """为 workflow 生成安全建议"""
        recommendations = []
        
        # 基于问题类型生成建议
        issue_type_to_recommendation = {
            'pull_request_target_secrets': [
                '避免在 pull_request_target 工作流中访问 secrets',
                '如果必须使用 secrets，考虑使用其他安全机制'
            ],
            'unpinned_actions': [
                '使用完整 commit SHA 固定所有 action 版本',
                '例如: actions/checkout@a81bbbf8292c0d03a0b7c16fcfb38b7dfbce4bc8'
            ],
            'excessive_permissions': [
                '遵循最小权限原则配置 GITHUB_TOKEN',
                '只授予必要的权限，避免使用 write-all 或 read-all'
            ],
            'hardcoded_secrets': [
                '移除硬编码的秘密，使用 GitHub Secrets',
                '定期轮换 secrets'
            ],
            'high_risk_actions': [
                '审查高风险 action 的必要性',
                '考虑使用更安全的替代方案'
            ]
        }
        
        for issue in issues:
            issue_type = issue['type']
            if issue_type in issue_type_to_recommendation:
                recommendations.extend(issue_type_to_recommendation[issue_type])
        
        # 添加通用建议
        recommendations.extend([
            '定期审查和更新 workflow',
            '使用 dependabot 自动更新依赖',
            '实施代码审查和安全扫描'
        ])
        
        return list(set(recommendations))  # 去重
    
    def _generate_executive_summary(self, workflow_security: Dict, action_security: Dict) -> Dict:
        """生成执行摘要"""
        workflow_summary = workflow_security.get('summary', {})
        action_summary = action_security.get('summary', {})
        
        return {
            'total_workflows_analyzed': workflow_summary.get('total_workflows_analyzed', 0),
            'risky_workflows_percentage': workflow_summary.get('risk_percentage', 0),
            'critical_actions_count': action_summary.get('critical_actions_count', 0),
            'key_findings': [
                f"{workflow_summary.get('risky_workflows', 0)} 个 workflows 存在安全风险",
                f"{action_summary.get('critical_actions_count', 0)} 个 actions 被评估为高风险",
                "最常见的风险：未固定 action 版本和过宽的权限设置"
            ],
            'overall_risk_level': self._determine_overall_risk_level(
                workflow_summary.get('risk_percentage', 0)
            )
        }
    
    def _generate_risk_assessment(self, workflow_security: Dict, action_security: Dict) -> Dict:
        """生成风险评估"""
        return {
            'workflow_risks': {
                'critical': len([w for w in workflow_security.get('high_risk_workflows', []) 
                               if w.get('risk_level') == 'critical']),
                'high': len([w for w in workflow_security.get('high_risk_workflows', []) 
                            if w.get('risk_level') == 'high']),
                'medium': len([w for w in workflow_security.get('high_risk_workflows', []) 
                              if w.get('risk_level') == 'medium'])
            },
            'action_risks': {
                'supply_chain': len(action_security.get('supply_chain_risks', [])),
                'critical_actions': len(action_security.get('critical_actions', []))
            },
            'risk_matrix': self._create_risk_matrix()
        }
    
    def _generate_recommendations(self, workflow_security: Dict, 
                                 action_security: Dict, vulnerability_patterns: Dict) -> Dict:
        """生成建议"""
        return {
            'immediate_actions': [
                '审查并固定所有未固定版本的 actions',
                '限制高权限 workflow 的 GITHUB_TOKEN 权限',
                '移除所有硬编码的秘密'
            ],
            'short_term_actions': [
                '实施 action 依赖的安全审查流程',
                '建立供应链风险监控机制',
                '对高风险 actions 制定迁移计划'
            ],
            'long_term_strategy': [
                '建立完整的安全开发生命周期（SDLC）',
                '实施自动化安全扫描和合规检查',
                '定期进行供应链安全审计'
            ],
            'mitigation_measures': vulnerability_patterns.get('mitigation_recommendations', [])
        }
    
    def _get_analysis_methodology(self) -> List[str]:
        """获取分析方法"""
        return [
            '静态代码分析：解析 workflow YAML 文件',
            '依赖图分析：构建和分析 action 依赖关系',
            '模式匹配：检测已知的安全漏洞模式',
            '风险评估：基于多因素评估风险级别'
        ]
    
    def _get_risk_criteria(self) -> Dict:
        """获取风险标准"""
        return {
            'critical': [
                '硬编码的秘密',
                'pull_request_target 中的 secrets 访问',
                '直接影响生产环境的漏洞'
            ],
            'high': [
                '未固定版本的 actions',
                '过宽的 GITHUB_TOKEN 权限',
                '高风险第三方 actions'
            ],
            'medium': [
                '潜在的权限提升风险',
                '次要的配置问题',
                '需要进一步调查的问题'
            ],
            'low': [
                '最佳实践违规',
                '信息性问题',
                '不影响安全的功能问题'
            ]
        }
    
    def _determine_overall_risk_level(self, risk_percentage: float) -> str:
        """确定总体风险级别"""
        if risk_percentage > 30:
            return 'critical'
        elif risk_percentage > 15:
            return 'high'
        elif risk_percentage > 5:
            return 'medium'
        else:
            return 'low'
    
    def _create_risk_matrix(self) -> Dict:
        """创建风险矩阵"""
        return {
            'likelihood': ['rare', 'unlikely', 'possible', 'likely', 'certain'],
            'impact': ['negligible', 'minor', 'moderate', 'major', 'critical'],
            'risk_levels': {
                'low': '绿色 - 可接受风险',
                'medium': '黄色 - 需监控风险',
                'high': '橙色 - 需缓解风险',
                'critical': '红色 - 立即处理风险'
            }
        }
    
    def _get_context(self, text: str, position: int, window: int = 100) -> str:
        """获取文本上下文"""
        start = max(0, position - window)
        end = min(len(text), position + window)
        return text[start:end]
    
    def _save_security_analysis(self, findings: Dict):
        """保存安全分析结果"""
        save_json(
            findings,
            str(self.processed_data_path / "security_analysis.json")
        )
    
    def _save_action_security_analysis(self, findings: Dict):
        """保存 action 安全分析结果"""
        save_json(
            findings,
            str(self.processed_data_path / "action_security_analysis.json")
        )
    
    def _save_markdown_report(self, report: Dict):
        """保存 Markdown 格式的报告"""
        md_file = self.processed_data_path / "security_report.md"
        
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write("# GitHub Actions 安全分析报告\n\n")
            
            # 执行摘要
            f.write("## 执行摘要\n\n")
            summary = report.get('executive_summary', {})
            f.write(f"- 分析的 Workflows 总数: {summary.get('total_workflows_analyzed', 0)}\n")
            f.write(f"- 高风险 Workflows 比例: {summary.get('risky_workflows_percentage', 0):.1f}%\n")
            f.write(f"- 关键 Actions 数量: {summary.get('critical_actions_count', 0)}\n")
            f.write(f"- 总体风险级别: {summary.get('overall_risk_level', 'unknown')}\n\n")
            
            # 主要发现
            f.write("## 主要发现\n\n")
            for finding in summary.get('key_findings', []):
                f.write(f"- {finding}\n")
            
            # 建议
            f.write("\n## 建议\n\n")
            recommendations = report.get('recommendations', {})
            
            f.write("### 立即行动\n")
            for action in recommendations.get('immediate_actions', []):
                f.write(f"- {action}\n")
            
            f.write("\n### 短期行动\n")
            for action in recommendations.get('short_term_actions', []):
                f.write(f"- {action}\n")
            
            f.write("\n### 长期策略\n")
            for action in recommendations.get('long_term_strategy', []):
                f.write(f"- {action}\n")
            
            # 附录
            f.write("\n## 附录\n\n")
            f.write("### 分析方法\n")
            for method in report.get('appendix', {}).get('analysis_methodology', []):
                f.write(f"- {method}\n")
        
        self.logger.info(f"Markdown 报告已保存到: {md_file}")