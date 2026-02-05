# 从 workflow YAML 中提取 action 依赖关系
# crawler/dependency_extractor.py
import re
import logging
import yaml
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict
from pathlib import Path
from utils.action_parser import ActionParser
from utils.file_utils import save_json, load_json

class DependencyExtractor:
    """依赖提取器 - 从 workflows 中提取 action 依赖关系"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.action_parser = ActionParser()
        
        # 路径
        self.raw_data_path = Path(config['paths']['raw_data'])
        self.processed_data_path = Path(config['paths']['processed_data'])
        self.processed_data_path.mkdir(parents=True, exist_ok=True)
    
    def extract_from_workflows(self, workflows_data: Dict) -> Dict:
        """
        从 workflows 数据中提取依赖关系
        
        Args:
            workflows_data: 包含仓库 workflows 的字典
            
        Returns:
            包含依赖关系的字典
        """
        self.logger.info("开始提取 action 依赖关系...")
        
        # 存储各种依赖关系
        dependencies = {
            'repo_actions': defaultdict(list),  # 仓库 -> 使用的 actions
            'action_repos': defaultdict(list),  # action -> 使用它的仓库
            'action_usage_count': defaultdict(int),  # action 使用次数
            'action_details': {},  # action 详细信息
            'repo_stats': defaultdict(dict)  # 仓库统计信息
        }
        
        total_workflows = 0
        total_actions = 0
        
        # 处理每个仓库的 workflows
        for repo_full_name, workflows in workflows_data.items():
            self.logger.debug(f"处理仓库: {repo_full_name}")
            
            repo_actions = set()
            workflow_count = 0
            
            for workflow in workflows:
                if not isinstance(workflow, dict):
                    continue
                
                workflow_count += 1
                total_workflows += 1
                
                # 从 workflow 内容中提取 actions
                content = workflow.get('content', '')
                parsed_yaml = workflow.get('parsed_yaml', {})
                
                # 两种方式提取 actions
                actions_from_content = self._extract_actions_from_content(content)
                actions_from_yaml = self._extract_actions_from_yaml(parsed_yaml)
                
                # 合并结果
                all_actions = set(actions_from_content + actions_from_yaml)
                
                for action_ref in all_actions:
                    # 解析 action 引用
                    parsed = self.action_parser._parse_action_ref(action_ref)
                    if not parsed:
                        continue
                    
                    owner, repo, version = parsed
                    action_key = f"{owner}/{repo}"
                    
                    # 添加到仓库的 actions 列表
                    repo_actions.add(action_key)
                    
                    # 添加到反向索引
                    dependencies['action_repos'][action_key].append({
                        'repo': repo_full_name,
                        'workflow': workflow.get('name', ''),
                        'version': version,
                        'ref': action_ref
                    })
                    
                    # 更新使用计数
                    dependencies['action_usage_count'][action_key] += 1
                    
                    # 保存 action 详情
                    if action_key not in dependencies['action_details']:
                        dependencies['action_details'][action_key] = {
                            'owner': owner,
                            'repo': repo,
                            'versions_used': set(),
                            'total_usage': 0
                        }
                    
                    dependencies['action_details'][action_key]['versions_used'].add(version)
                    total_actions += 1
            
            # 保存仓库的 actions
            if repo_actions:
                dependencies['repo_actions'][repo_full_name] = list(repo_actions)
            
            # 保存仓库统计
            dependencies['repo_stats'][repo_full_name] = {
                'workflow_count': workflow_count,
                'action_count': len(repo_actions),
                'unique_actions': list(repo_actions)
            }
        
        # 转换 set 为 list 以便 JSON 序列化
        for action_key, details in dependencies['action_details'].items():
            details['versions_used'] = list(details['versions_used'])
            details['total_usage'] = dependencies['action_usage_count'][action_key]
        
        # 保存结果
        self._save_dependencies(dependencies, total_workflows, total_actions)
        
        return dependencies
    
    def _extract_actions_from_content(self, content: str) -> List[str]:
        """从 workflow 文本内容中提取 actions"""
        actions = []
        
        # 使用正则表达式查找 uses: 语句
        uses_pattern = r'^\s*-\s*uses:\s*(.+)$'
        matches = re.findall(uses_pattern, content, re.MULTILINE | re.IGNORECASE)
        
        for match in matches:
            action_ref = match.strip()
            # 移除可能的引号
            if action_ref.startswith(('"', "'")):
                action_ref = action_ref[1:-1]
            
            # 跳过本地路径
            if not action_ref.startswith(('./', '../')):
                actions.append(action_ref)
        
        return actions
    
    def _extract_actions_from_yaml(self, workflow_yaml: Dict) -> List[str]:
        """从解析的 YAML 中提取 actions"""
        actions = []
        
        if not isinstance(workflow_yaml, dict):
            return actions
        
        # 遍历 jobs
        jobs = workflow_yaml.get('jobs', {})
        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue
            
            # 处理 steps
            steps = job_config.get('steps', [])
            for step in steps:
                if isinstance(step, dict) and 'uses' in step:
                    action_ref = step['uses']
                    if not action_ref.startswith(('./', '../')):
                        actions.append(action_ref)
            
            # 处理 uses 在 job 级别的情况
            if 'uses' in job_config:
                action_ref = job_config['uses']
                if not action_ref.startswith(('./', '../')):
                    actions.append(action_ref)
        
        return actions
    
    def build_dependency_graphs(self, dependencies: Dict) -> Dict:
        """构建依赖关系图"""
        self.logger.info("构建依赖关系图...")
        
        graphs = {
            'repo_action_edges': [],
            'action_repo_edges': [],
            'action_popularity': [],
            'top_actions': []
        }
        
        # 构建仓库-action 边
        for repo, actions in dependencies['repo_actions'].items():
            for action in actions:
                usage_count = dependencies['action_usage_count'].get(action, 0)
                graphs['repo_action_edges'].append({
                    'source': repo,
                    'target': action,
                    'type': 'uses',
                    'weight': 1
                })
        
        # 构建 action 流行度列表
        for action, count in dependencies['action_usage_count'].items():
            graphs['action_popularity'].append({
                'action': action,
                'usage_count': count,
                'repo_count': len(set([r['repo'] for r in dependencies['action_repos'].get(action, [])]))
            })
        
        # 排序并获取 top actions
        graphs['action_popularity'].sort(key=lambda x: x['usage_count'], reverse=True)
        graphs['top_actions'] = graphs['action_popularity'][:100]
        
        # 保存图数据
        self._save_graph_data(graphs)
        
        return graphs
    
    def _save_dependencies(self, dependencies: Dict, total_workflows: int, total_actions: int):
        """保存依赖关系数据"""
        # 保存完整依赖数据
        deps_file = self.raw_data_path / "dependencies.json"
        save_json(dependencies, str(deps_file))
        
        # 保存为 CSV 格式便于分析
        self._save_to_csv(dependencies)
        
        # 保存统计信息
        stats = {
            'total_repos': len(dependencies['repo_actions']),
            'total_workflows': total_workflows,
            'total_unique_actions': len(dependencies['action_usage_count']),
            'total_action_uses': total_actions,
            'top_10_actions': sorted(
                dependencies['action_usage_count'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
        
        stats_file = self.raw_data_path / "dependencies_stats.json"
        save_json(stats, str(stats_file))
        
        self.logger.info(f"依赖关系提取完成:")
        self.logger.info(f"  涉及仓库: {stats['total_repos']}")
        self.logger.info(f"  Workflows: {stats['total_workflows']}")
        self.logger.info(f"  唯一 Actions: {stats['total_unique_actions']}")
        self.logger.info(f"  Action 使用次数: {stats['total_action_uses']}")
    
    def _save_to_csv(self, dependencies: Dict):
        """保存为 CSV 文件"""
        import csv
        
        # 仓库-action 关系
        repo_action_file = self.processed_data_path / "repo_actions_edges.csv"
        with open(repo_action_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['source', 'target', 'type'])
            for repo, actions in dependencies['repo_actions'].items():
                for action in actions:
                    writer.writerow([repo, action, 'uses'])
        
        # action 使用统计
        usage_file = self.processed_data_path / "action_usage_stats.csv"
        with open(usage_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['action', 'usage_count', 'repo_count'])
            for action, count in dependencies['action_usage_count'].items():
                repo_count = len(set([r['repo'] for r in dependencies['action_repos'].get(action, [])]))
                writer.writerow([action, count, repo_count])
    
    def _save_graph_data(self, graphs: Dict):
        """保存图数据"""
        graphs_file = self.processed_data_path / "dependency_graphs.json"
        save_json(graphs, str(graphs_file))
        
        self.logger.info(f"图数据已保存到 {graphs_file}")