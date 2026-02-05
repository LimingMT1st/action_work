 # 生成安全建议与最佳实践
# analysis/recommendations.py
import json
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import pandas as pd

from utils.file_utils import load_json, save_json, ensure_dir

class SecurityRecommendations:
    """安全建议生成器"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
        self.output_dir = Path("output/recommendations")
        ensure_dir(self.output_dir)
    
    def generate_action_specific_recommendations(self, action: str) -> Dict:
        """生成针对特定 action 的建议"""
        self.logger.info(f"为 action {action} 生成安全建议...")
        
        recommendations = {
            'action': action,
            'risk_assessment': {},
            'specific_recommendations': [],
            'dependency_recommendations': [],
            'mitigation_measures': []
        }
        
        try:
            # 加载 action 安全分析
            action_security = load_json(
                str(self.processed_data_path / "action_security_analysis.json")
            )
            
            # 查找该 action 的风险评估
            if action_security:
                for critical_action in action_security.get('critical_actions', []):
                    if critical_action['action'] == action:
                        recommendations['risk_assessment'] = critical_action.get('risk_assessment', {})
                        break
            
            # 生成具体建议
            recommendations['specific_recommendations'] = self._generate_specific_recommendations(action)
            
            # 生成依赖相关建议
            recommendations['dependency_recommendations'] = self._generate_dependency_recommendations(action)
            
            # 生成缓解措施
            recommendations['mitigation_measures'] = self._generate_mitigation_measures(action)
            
            # 保存建议
            self._save_action_recommendations(action, recommendations)
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"生成 action 建议失败: {e}")
            return recommendations
    
    def generate_workflow_recommendations(self, repo: str, workflow: str) -> Dict:
        """生成针对特定 workflow 的建议"""
        self.logger.info(f"为 {repo}/{workflow} 生成安全建议...")
        
        recommendations = {
            'repo': repo,
            'workflow': workflow,
            'risk_assessment': {},
            'immediate_actions': [],
            'long_term_improvements': [],
            'compliance_checklist': []
        }
        
        try:
            # 加载安全分析数据
            security_analysis = load_json(
                str(self.processed_data_path / "security_analysis.json")
            )
            
            if security_analysis:
                # 查找该 workflow 的风险评估
                for workflow_data in security_analysis.get('high_risk_workflows', []):
                    if (workflow_data.get('repo') == repo and 
                        workflow_data.get('workflow_name') == workflow):
                        recommendations['risk_assessment'] = {
                            'risk_level': workflow_data.get('risk_level', 'unknown'),
                            'issues': workflow_data.get('issues', []),
                            'existing_recommendations': workflow_data.get('recommendations', [])
                        }
                        break
            
            # 生成立即行动
            recommendations['immediate_actions'] = self._generate_workflow_immediate_actions(
                repo, workflow, recommendations['risk_assessment']
            )
            
            # 生成长期改进
            recommendations['long_term_improvements'] = self._generate_workflow_long_term_improvements(
                repo, workflow
            )
            
            # 生成合规检查清单
            recommendations['compliance_checklist'] = self._generate_compliance_checklist()
            
            # 保存建议
            self._save_workflow_recommendations(repo, workflow, recommendations)
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"生成 workflow 建议失败: {e}")
            return recommendations
    
    def generate_organization_recommendations(self) -> Dict:
        """生成组织级别的建议"""
        self.logger.info("生成组织级别安全建议...")
        
        recommendations = {
            'policy_recommendations': [],
            'process_improvements': [],
            'tooling_recommendations': [],
            'training_recommendations': [],
            'maturity_assessment': {}
        }
        
        # 政策建议
        recommendations['policy_recommendations'] = [
            {
                'category': '依赖管理',
                'recommendations': [
                    '建立第三方 action 使用审批流程',
                    '要求所有 action 使用完整 commit SHA 固定版本',
                    '禁止使用未经验证的第三方 actions',
                    '定期更新依赖，设置自动更新策略'
                ]
            },
            {
                'category': '权限管理',
                'recommendations': [
                    '实施最小权限原则，默认使用只读权限',
                    '对生产环境部署实施双重审批',
                    '分离敏感操作的权限',
                    '定期审计权限配置'
                ]
            },
            {
                'category': '秘密管理',
                'recommendations': [
                    '禁止在代码中硬编码 secrets',
                    '使用 GitHub Secrets 或外部秘密管理工具',
                    '实施秘密轮换策略',
                    '监控 secrets 的使用和泄露'
                ]
            },
            {
                'category': '供应链安全',
                'recommendations': [
                    '建立软件物料清单（SBOM）',
                    '实施供应链安全扫描',
                    '监控第三方依赖的安全公告',
                    '建立供应链事件响应流程'
                ]
            }
        ]
        
        # 流程改进
        recommendations['process_improvements'] = [
            {
                'process': '代码审查',
                'improvements': [
                    '将安全审查纳入代码审查流程',
                    '建立安全编码规范',
                    '实施自动化安全扫描',
                    '培训开发人员安全最佳实践'
                ]
            },
            {
                'process': 'CI/CD 管道',
                'improvements': [
                    '实施管道安全防护',
                    '建立构建环境安全标准',
                    '实施部署审批流程',
                    '监控异常构建活动'
                ]
            },
            {
                'process': '事件响应',
                'improvements': [
                    '建立供应链安全事件响应计划',
                    '定期进行安全演练',
                    '建立漏洞披露流程',
                    '实施安全监控和告警'
                ]
            }
        ]
        
        # 工具推荐
        recommendations['tooling_recommendations'] = [
            {
                'category': '安全扫描',
                'tools': [
                    {'name': 'GitHub Advanced Security', 'purpose': '代码扫描、秘密检测'},
                    {'name': 'Snyk', 'purpose': '依赖漏洞扫描'},
                    {'name': 'Checkov', 'purpose': '基础设施即代码安全'},
                    {'name': 'Trivy', 'purpose': '容器安全扫描'}
                ]
            },
            {
                'category': '合规检查',
                'tools': [
                    {'name': 'Open Policy Agent (OPA)', 'purpose': '策略即代码'},
                    {'name': 'Regula', 'purpose': '基础设施合规检查'},
                    {'name': 'Terrascan', 'purpose': '安全最佳实践检查'}
                ]
            },
            {
                'category': '监控',
                'tools': [
                    {'name': 'Falco', 'purpose': '运行时安全监控'},
                    {'name': 'Wazuh', 'purpose': '安全信息和事件管理'},
                    {'name': 'Elastic Security', 'purpose': '安全分析和监控'}
                ]
            }
        ]
        
        # 培训建议
        recommendations['training_recommendations'] = [
            {
                'audience': '开发人员',
                'topics': [
                    '安全编码实践',
                    '供应链安全基础',
                    'GitHub Actions 安全',
                    '秘密管理最佳实践'
                ]
            },
            {
                'audience': '运维人员',
                'topics': [
                    '基础设施安全',
                    'CI/CD 管道安全',
                    '监控和事件响应',
                    '合规要求'
                ]
            },
            {
                'audience': '安全团队',
                'topics': [
                    '高级威胁检测',
                    '供应链攻击分析',
                    '安全工具集成',
                    '合规框架'
                ]
            }
        ]
        
        # 成熟度评估
        recommendations['maturity_assessment'] = {
            'levels': [
                {
                    'level': '初始',
                    'characteristics': ['临时安全措施', '手动流程', '反应式响应'],
                    'recommendations': ['建立基础安全策略', '实施自动化扫描']
                },
                {
                    'level': '可重复',
                    'characteristics': ['基本安全流程', '部分自动化', '被动监控'],
                    'recommendations': ['完善安全策略', '加强监控能力']
                },
                {
                    'level': '已定义',
                    'characteristics': ['标准化流程', '全面自动化', '主动监控'],
                    'recommendations': ['优化安全流程', '实施高级防护']
                },
                {
                    'level': '已管理',
                    'characteristics': ['量化管理', '预测性分析', '持续改进'],
                    'recommendations': ['实施预测性安全', '持续优化']
                },
                {
                    'level': '优化',
                    'characteristics': ['创新安全实践', '自适应防护', '业界领先'],
                    'recommendations': ['推动安全创新', '贡献安全社区']
                }
            ]
        }
        
        # 保存建议
        self._save_organization_recommendations(recommendations)
        
        return recommendations
    
    def generate_compliance_framework(self, framework: str = 'general') -> Dict:
        """生成合规框架"""
        self.logger.info(f"生成 {framework} 合规框架...")
        
        frameworks = {
            'general': self._generate_general_compliance(),
            'soc2': self._generate_soc2_compliance(),
            'iso27001': self._generate_iso27001_compliance(),
            'hipaa': self._generate_hipaa_compliance(),
            'gdpr': self._generate_gdpr_compliance()
        }
        
        compliance_framework = frameworks.get(framework, frameworks['general'])
        
        # 保存框架
        self._save_compliance_framework(framework, compliance_framework)
        
        return compliance_framework
    
    def _generate_specific_recommendations(self, action: str) -> List[Dict]:
        """生成具体建议"""
        recommendations = []
        
        # 根据 action 类型生成建议
        if action.startswith('actions/'):
            # GitHub 官方 actions
            recommendations.extend([
                {
                    'type': 'version_pinning',
                    'description': '使用完整 commit SHA 固定版本',
                    'priority': 'high',
                    'example': f'{action}@a81bbbf8292c0d03a0b7c16fcfb38b7dfbce4bc8'
                },
                {
                    'type': 'permission_review',
                    'description': '审查所需的权限，遵循最小权限原则',
                    'priority': 'medium',
                    'check': '检查 workflow 中的 permissions 设置'
                }
            ])
        else:
            # 第三方 actions
            recommendations.extend([
                {
                    'type': 'supply_chain_risk',
                    'description': '第三方 action，需要额外审查',
                    'priority': 'high',
                    'actions': [
                        '验证 action 来源的可靠性',
                        '审查 action 的代码',
                        '监控 action 的更新'
                    ]
                },
                {
                    'type': 'version_strict_pinning',
                    'description': '必须使用完整 commit SHA 固定版本',
                    'priority': 'critical',
                    'reason': '防止供应链攻击'
                }
            ])
        
        # 通用建议
        recommendations.extend([
            {
                'type': 'security_monitoring',
                'description': '监控该 action 的安全公告和漏洞',
                'priority': 'medium',
                'tools': ['GitHub Dependabot', 'Snyk', 'Renovate']
            },
            {
                'type': 'alternative_assessment',
                'description': '评估是否有更安全的替代方案',
                'priority': 'low',
                'considerations': [
                    '官方认证的替代品',
                    '维护更活跃的项目',
                    '安全记录更好的项目'
                ]
            }
        ])
        
        return recommendations
    
    def _generate_dependency_recommendations(self, action: str) -> List[Dict]:
        """生成依赖相关建议"""
        recommendations = []
        
        try:
            # 加载依赖解析结果
            safe_action_name = action.replace('/', '_').replace('@', '_')
            dependency_file = self.processed_data_path / f"dependency_resolution_{safe_action_name}.json"
            
            if dependency_file.exists():
                dependencies = load_json(str(dependency_file))
                
                if dependencies:
                    analysis = dependencies.get('analysis', {})
                    issues = dependencies.get('issues', [])
                    
                    # 基于深度分析的建议
                    depth_analysis = analysis.get('depth_analysis', {})
                    max_depth = depth_analysis.get('max_depth', 0)
                    
                    if max_depth > 5:
                        recommendations.append({
                            'type': 'dependency_depth',
                            'description': f'依赖链深度过大 ({max_depth} 层)，增加供应链风险',
                            'priority': 'medium',
                            'action': '考虑减少间接依赖或寻找替代方案'
                        })
                    
                    # 基于复杂度分析的建议
                    complexity_metrics = analysis.get('complexity_metrics', {})
                    fan_out = complexity_metrics.get('fan_out', 0)
                    
                    if fan_out > 10:
                        recommendations.append({
                            'type': 'dependency_complexity',
                            'description': f'直接依赖过多 ({fan_out} 个)，增加维护难度',
                            'priority': 'low',
                            'action': '考虑合并或减少直接依赖'
                        })
                    
                    # 基于问题检测的建议
                    for issue in issues:
                        if issue.get('severity') in ['high', 'critical']:
                            recommendations.append({
                                'type': issue.get('type', 'unknown'),
                                'description': issue.get('description', ''),
                                'priority': issue.get('severity'),
                                'action': '立即调查和修复'
                            })
            
        except Exception:
            pass
        
        # 通用依赖建议
        recommendations.extend([
            {
                'type': 'dependency_audit',
                'description': '定期审计所有依赖的安全状况',
                'priority': 'medium',
                'frequency': '每月至少一次'
            },
            {
                'type': 'dependency_monitoring',
                'description': '监控依赖的安全公告和更新',
                'priority': 'high',
                'tools': ['自动依赖更新工具', '安全公告订阅']
            }
        ])
        
        return recommendations
    
    def _generate_mitigation_measures(self, action: str) -> List[Dict]:
        """生成缓解措施"""
        mitigation_measures = []
        
        # 根据 action 类型生成缓解措施
        if 'checkout' in action.lower():
            mitigation_measures.extend([
                {
                    'measure': '限制访问权限',
                    'description': '使用只读权限，避免不必要的写入权限',
                    'implementation': '在 workflow 中设置 permissions: read-only'
                },
                {
                    'measure': '限制代码访问范围',
                    'description': '仅 checkout 需要的代码，避免暴露敏感信息',
                    'implementation': '使用 sparse-checkout 或 path 参数'
                }
            ])
        
        elif 'docker' in action.lower():
            mitigation_measures.extend([
                {
                    'measure': '镜像验证',
                    'description': '验证 Docker 镜像的完整性和来源',
                    'implementation': '使用镜像签名和验证'
                },
                {
                    'measure': '最小化权限',
                    'description': '使用非 root 用户运行容器',
                    'implementation': '在 Dockerfile 中创建非特权用户'
                }
            ])
        
        elif 'deploy' in action.lower() or 'azure' in action.lower() or 'aws' in action.lower():
            mitigation_measures.extend([
                {
                    'measure': '使用临时凭证',
                    'description': '避免使用长期有效的云服务凭证',
                    'implementation': '使用 OIDC 或临时安全凭证'
                },
                {
                    'measure': '最小权限原则',
                    'description': '仅授予部署所需的最小权限',
                    'implementation': '创建专门的部署角色和策略'
                }
            ])
        
        # 通用缓解措施
        mitigation_measures.extend([
            {
                'measure': '沙箱执行',
                'description': '在隔离环境中执行 action',
                'implementation': '使用 GitHub-hosted runners 或自托管 runners 的安全配置'
            },
            {
                'measure': '执行前验证',
                'description': '在执行前验证 action 的完整性和来源',
                'implementation': '使用 checksum 验证和代码签名'
            },
            {
                'measure': '监控和告警',
                'description': '监控 action 的执行和异常行为',
                'implementation': '设置执行监控和异常检测'
            }
        ])
        
        return mitigation_measures
    
    def _generate_workflow_immediate_actions(self, repo: str, workflow: str, 
                                           risk_assessment: Dict) -> List[Dict]:
        """生成 workflow 立即行动"""
        immediate_actions = []
        
        # 基于风险评估生成行动
        risk_level = risk_assessment.get('risk_level', 'unknown')
        issues = risk_assessment.get('issues', [])
        
        if risk_level in ['critical', 'high']:
            immediate_actions.append({
                'action': '立即暂停使用该 workflow',
                'priority': 'critical',
                'reason': '高风险，可能已存在安全漏洞',
                'steps': ['暂停 workflow', '调查问题', '修复后重新启用']
            })
        
        # 基于具体问题生成行动
        for issue in issues:
            if issue.get('severity') in ['critical', 'high']:
                if issue.get('type') == 'unpinned_actions':
                    immediate_actions.append({
                        'action': '固定所有 action 版本',
                        'priority': 'high',
                        'reason': '防止供应链攻击',
                        'steps': ['查找所有 uses 语句', '替换为完整 commit SHA']
                    })
                
                elif issue.get('type') == 'hardcoded_secrets':
                    immediate_actions.append({
                        'action': '移除硬编码的秘密',
                        'priority': 'critical',
                        'reason': '可能导致敏感信息泄露',
                        'steps': ['查找硬编码的秘密', '替换为 GitHub Secrets', '轮换已泄露的秘密']
                    })
                
                elif issue.get('type') == 'excessive_permissions':
                    immediate_actions.append({
                        'action': '限制权限设置',
                        'priority': 'high',
                        'reason': '防止权限滥用',
                        'steps': ['审查 permissions 设置', '应用最小权限原则', '测试 workflow 功能']
                    })
        
        # 通用立即行动
        immediate_actions.extend([
            {
                'action': '审查第三方 actions',
                'priority': 'medium',
                'reason': '确保供应链安全',
                'steps': ['列出所有第三方 actions', '验证来源和可靠性', '检查安全记录']
            },
            {
                'action': '更新依赖',
                'priority': 'medium',
                'reason': '修复已知安全漏洞',
                'steps': ['运行依赖扫描', '更新到安全版本', '测试兼容性']
            }
        ])
        
        return immediate_actions
    
    def _generate_workflow_long_term_improvements(self, repo: str, workflow: str) -> List[Dict]:
        """生成长期改进建议"""
        improvements = [
            {
                'area': '安全架构',
                'improvements': [
                    '实施零信任安全模型',
                    '建立防御深度策略',
                    '实施最小权限架构'
                ],
                'benefits': ['减少攻击面', '提高安全性', '简化合规']
            },
            {
                'area': '自动化',
                'improvements': [
                    '实施自动化安全扫描',
                    '建立安全即代码流程',
                    '自动化合规检查'
                ],
                'benefits': ['提高效率', '减少人为错误', '持续安全']
            },
            {
                'area': '监控和响应',
                'improvements': [
                    '建立安全监控体系',
                    '实施异常检测',
                    '自动化事件响应'
                ],
                'benefits': ['快速发现威胁', '及时响应', '减少损失']
            },
            {
                'area': '人员和文化',
                'improvements': [
                    '建立安全培训计划',
                    '培养安全文化',
                    '实施安全奖励机制'
                ],
                'benefits': ['提高安全意识', '减少安全失误', '促进创新']
            }
        ]
        
        return improvements
    
    def _generate_compliance_checklist(self) -> List[Dict]:
        """生成合规检查清单"""
        checklist = [
            {
                'domain': '访问控制',
                'checks': [
                    '是否实施最小权限原则？',
                    '是否定期审计权限配置？',
                    '是否使用多因素认证？',
                    '是否实施会话管理？'
                ]
            },
            {
                'domain': '数据保护',
                'checks': [
                    '是否加密敏感数据？',
                    '是否实施数据分类？',
                    '是否定期备份数据？',
                    '是否实施数据保留策略？'
                ]
            },
            {
                'domain': '供应链安全',
                'checks': [
                    '是否维护软件物料清单？',
                    '是否审查第三方依赖？',
                    '是否监控安全公告？',
                    '是否实施供应链风险评估？'
                ]
            },
            {
                'domain': '事件响应',
                'checks': [
                    '是否有事件响应计划？',
                    '是否定期进行安全演练？',
                    '是否有漏洞披露流程？',
                    '是否实施安全监控？'
                ]
            },
            {
                'domain': '合规管理',
                'checks': [
                    '是否识别适用的法规？',
                    '是否实施合规控制？',
                    '是否进行合规审计？',
                    '是否维护合规文档？'
                ]
            }
        ]
        
        return checklist
    
    def _generate_general_compliance(self) -> Dict:
        """生成通用合规框架"""
        return {
            'name': '通用安全合规框架',
            'version': '1.0',
            'domains': [
                {
                    'domain': '治理和风险管理',
                    'controls': [
                        '建立安全策略和标准',
                        '实施风险评估流程',
                        '建立安全治理结构',
                        '维护安全文档'
                    ]
                },
                {
                    'domain': '访问控制',
                    'controls': [
                        '实施身份和访问管理',
                        '遵循最小权限原则',
                        '定期审计访问权限',
                        '实施特权访问管理'
                    ]
                },
                {
                    'domain': '供应链安全',
                    'controls': [
                        '维护第三方供应商清单',
                        '实施供应商风险评估',
                        '监控供应链安全',
                        '建立供应链事件响应'
                    ]
                },
                {
                    'domain': '事件响应',
                    'controls': [
                        '建立事件响应计划',
                        '实施安全监控',
                        '定期进行安全演练',
                        '建立事件报告流程'
                    ]
                },
                {
                    'domain': '业务连续性',
                    'controls': [
                        '制定业务连续性计划',
                        '实施灾难恢复策略',
                        '定期测试恢复能力',
                        '维护备份和恢复流程'
                    ]
                }
            ]
        }
    
    def _generate_soc2_compliance(self) -> Dict:
        """生成 SOC2 合规框架"""
        return {
            'name': 'SOC2 合规框架',
            'version': '1.0',
            'trust_service_criteria': [
                {
                    'criterion': '安全性',
                    'requirements': [
                        '逻辑和物理访问控制',
                        '系统操作监控',
                        '变更管理流程',
                        '风险缓解措施'
                    ]
                },
                {
                    'criterion': '可用性',
                    'requirements': [
                        '系统监控',
                        '灾难恢复',
                        '环境安全',
                        '容量规划'
                    ]
                },
                {
                    'criterion': '处理完整性',
                    'requirements': [
                        '数据处理完整性',
                        '系统处理完整性',
                        '数据验证',
                        '错误处理'
                    ]
                },
                {
                    'criterion': '机密性',
                    'requirements': [
                        '信息分类',
                        '数据加密',
                        '访问控制',
                        '数据保留'
                    ]
                },
                {
                    'criterion': '隐私',
                    'requirements': [
                        '隐私声明',
                        '数据收集限制',
                        '数据质量',
                        '数据主体权利'
                    ]
                }
            ]
        }
    
    def _generate_iso27001_compliance(self) -> Dict:
        """生成 ISO27001 合规框架"""
        return {
            'name': 'ISO27001 信息安全管理系统',
            'version': '1.0',
            'annexes': [
                {
                    'annex': 'A.5 信息安全策略',
                    'controls': [
                        '信息安全策略文档',
                        '信息安全策略评审'
                    ]
                },
                {
                    'annex': 'A.6 信息安全组织',
                    'controls': [
                        '内部组织',
                        '移动设备和远程工作',
                        '供应商关系'
                    ]
                },
                {
                    'annex': 'A.8 资产管理',
                    'controls': [
                        '资产清单',
                        '信息分类',
                        '介质处理'
                    ]
                },
                {
                    'annex': 'A.9 访问控制',
                    'controls': [
                        '访问控制策略',
                        '用户访问管理',
                        '系统和应用访问控制'
                    ]
                },
                {
                    'annex': 'A.12 操作安全',
                    'controls': [
                        '操作程序和责任',
                        '恶意软件防护',
                        '备份',
                        '日志和监控'
                    ]
                },
                {
                    'annex': 'A.14 系统获取、开发和维护',
                    'controls': [
                        '安全需求',
                        '开发和支持过程安全',
                        '测试数据'
                    ]
                },
                {
                    'annex': 'A.15 供应商关系',
                    'controls': [
                        '供应商关系信息安全',
                        '供应商服务交付管理'
                    ]
                },
                {
                    'annex': 'A.16 信息安全事件管理',
                    'controls': [
                        '信息安全事件管理',
                        '信息安全事件改进'
                    ]
                },
                {
                    'annex': 'A.17 业务连续性管理',
                    'controls': [
                        '信息安全连续性',
                        '冗余'
                    ]
                },
                {
                    'annex': 'A.18 合规',
                    'controls': [
                        '法律和合同要求合规',
                        '信息安全评审'
                    ]
                }
            ]
        }
    
    def _generate_hipaa_compliance(self) -> Dict:
        """生成 HIPAA 合规框架"""
        return {
            'name': 'HIPAA 合规框架',
            'version': '1.0',
            'rules': [
                {
                    'rule': '隐私规则',
                    'requirements': [
                        '患者权利通知',
                        '使用和披露限制',
                        '患者访问权',
                        '修正权'
                    ]
                },
                {
                    'rule': '安全规则',
                    'requirements': [
                        '管理保障措施',
                        '物理保障措施',
                        '技术保障措施'
                    ]
                },
                {
                    'rule': '违规通知规则',
                    'requirements': [
                        '违规通知',
                        '媒体通知',
                        '个人通知',
                        '监管机构通知'
                    ]
                },
                {
                    'rule': '执行规则',
                    'requirements': [
                        '民事罚款',
                        '刑事处罚',
                        '合规审计',
                        '自愿合规'
                    ]
                }
            ]
        }
    
    def _generate_gdpr_compliance(self) -> Dict:
        """生成 GDPR 合规框架"""
        return {
            'name': 'GDPR 合规框架',
            'version': '1.0',
            'principles': [
                {
                    'principle': '合法、公平和透明',
                    'requirements': [
                        '合法处理依据',
                        '透明度要求',
                        '隐私声明'
                    ]
                },
                {
                    'principle': '目的限制',
                    'requirements': [
                        '特定明确合法目的',
                        '不兼容目的限制'
                    ]
                },
                {
                    'principle': '数据最小化',
                    'requirements': [
                        '充分相关和必要',
                        '数据最小化'
                    ]
                },
                {
                    'principle': '准确性',
                    'requirements': [
                        '确保准确性',
                        '及时更新'
                    ]
                },
                {
                    'principle': '存储限制',
                    'requirements': [
                        '存储时间限制',
                        '匿名化或删除'
                    ]
                },
                {
                    'principle': '完整性和保密性',
                    'requirements': [
                        '安全处理',
                        '防止未经授权访问'
                    ]
                },
                {
                    'principle': '问责制',
                    'requirements': [
                        '责任证明',
                        '记录处理活动'
                    ]
                }
            ],
            'data_subject_rights': [
                '知情权',
                '访问权',
                '修正权',
                '删除权（被遗忘权）',
                '限制处理权',
                '数据可携权',
                '反对权',
                '自动化决策权'
            ]
        }
    
    def _save_action_recommendations(self, action: str, recommendations: Dict):
        """保存 action 建议"""
        safe_action_name = action.replace('/', '_').replace('@', '_')
        output_file = self.output_dir / f"action_recommendations_{safe_action_name}.json"
        save_json(recommendations, str(output_file))
        
        # 同时保存为 Markdown 格式
        md_file = self.output_dir / f"action_recommendations_{safe_action_name}.md"
        self._save_action_recommendations_md(action, recommendations, md_file)
    
    def _save_workflow_recommendations(self, repo: str, workflow: str, recommendations: Dict):
        """保存 workflow 建议"""
        safe_repo_name = repo.replace('/', '_')
        safe_workflow_name = workflow.replace('/', '_')
        output_file = self.output_dir / f"workflow_recommendations_{safe_repo_name}_{safe_workflow_name}.json"
        save_json(recommendations, str(output_file))
    
    def _save_organization_recommendations(self, recommendations: Dict):
        """保存组织建议"""
        output_file = self.output_dir / "organization_recommendations.json"
        save_json(recommendations, str(output_file))
        
        # 同时保存为 Markdown 格式
        md_file = self.output_dir / "organization_recommendations.md"
        self._save_organization_recommendations_md(recommendations, md_file)
    
    def _save_compliance_framework(self, framework: str, compliance: Dict):
        """保存合规框架"""
        output_file = self.output_dir / f"compliance_framework_{framework}.json"
        save_json(compliance, str(output_file))
    
    def _save_action_recommendations_md(self, action: str, recommendations: Dict, filepath: Path):
        """保存 action 建议为 Markdown 格式"""
        md_content = f"""# Action 安全建议: {action}

## 风险评估
- **总体风险**: {recommendations['risk_assessment'].get('overall_risk', '未知')}
- **供应链风险**: {recommendations['risk_assessment'].get('supply_chain_risk', '未知')}
- **权限风险**: {recommendations['risk_assessment'].get('permission_risk', '未知')}

## 具体建议

### 1. 版本管理
"""
        
        for rec in recommendations['specific_recommendations']:
            if rec['type'] in ['version_pinning', 'version_strict_pinning']:
                md_content += f"- **{rec['description']}** (优先级: {rec['priority']})\n"
                if 'example' in rec:
                    md_content += f"  示例: `{rec['example']}`\n"
        
        md_content += "\n### 2. 依赖管理\n"
        
        for rec in recommendations['dependency_recommendations']:
            md_content += f"- **{rec['description']}** (优先级: {rec['priority']})\n"
            if 'action' in rec:
                md_content += f"  建议行动: {rec['action']}\n"
        
        md_content += "\n### 3. 缓解措施\n"
        
        for measure in recommendations['mitigation_measures']:
            md_content += f"- **{measure['measure']}**: {measure['description']}\n"
            md_content += f"  实施方法: {measure['implementation']}\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
    
    def _save_organization_recommendations_md(self, recommendations: Dict, filepath: Path):
        """保存组织建议为 Markdown 格式"""
        md_content = """# 组织级别安全建议

## 政策建议

### 依赖管理
"""
        
        for policy in recommendations['policy_recommendations']:
            if policy['category'] == '依赖管理':
                for rec in policy['recommendations']:
                    md_content += f"- {rec}\n"
        
        md_content += "\n### 权限管理\n"
        
        for policy in recommendations['policy_recommendations']:
            if policy['category'] == '权限管理':
                for rec in policy['recommendations']:
                    md_content += f"- {rec}\n"
        
        md_content += "\n## 工具推荐\n"
        
        for tool_category in recommendations['tooling_recommendations']:
            md_content += f"\n### {tool_category['category']}\n"
            for tool in tool_category['tools']:
                md_content += f"- **{tool['name']}**: {tool['purpose']}\n"
        
        md_content += "\n## 成熟度评估\n"
        
        for level in recommendations['maturity_assessment']['levels']:
            md_content += f"\n### {level['level']} 级\n"
            md_content += "特点:\n"
            for char in level['characteristics']:
                md_content += f"- {char}\n"
            md_content += "建议:\n"
            for rec in level['recommendations']:
                md_content += f"- {rec}\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)