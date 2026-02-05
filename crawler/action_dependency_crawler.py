# 【新增】专门爬取 Action 之间的嵌套依赖
# crawler/action_dependency_crawler.py
import time
import logging
from typing import Dict, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from pathlib import Path
import json

from utils.action_parser import ActionParser
from utils.file_utils import save_json, load_json, ensure_dir
from .github_api_client import GitHubAPIClient

class ActionDependencyCrawler:
    """Action 依赖爬取器 - 深入爬取 Action 之间的嵌套依赖"""
    
    def __init__(self, api_client: GitHubAPIClient, config: Dict):
        self.api = api_client
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.action_parser = ActionParser()
        
        # 配置
        crawl_config = config['crawler']['action_dependency']
        self.max_depth = crawl_config['max_depth']
        self.top_k_actions = crawl_config['top_k_actions']
        self.include_composite = crawl_config['include_composite_actions']
        self.include_docker = crawl_config['include_docker_actions']
        self.skip_verified = crawl_config['skip_verified_actions']
        
        # 路径
        self.raw_data_path = Path(config['paths']['raw_data'])
        self.action_repos_dir = self.raw_data_path / "action_repos"
        ensure_dir(self.action_repos_dir)
        
        # 缓存和状态
        self.crawled_actions: Set[str] = set()
        self.action_dependencies: Dict[str, List[str]] = {}
        self.action_metadata: Dict[str, Dict] = {}
        
    def crawl_action_dependencies(self, top_actions: List[Dict]) -> Dict:
        """
        爬取 Action 的嵌套依赖
        
        Args:
            top_actions: 高频 action 列表
            
        Returns:
            包含 Action 依赖关系的字典
        """
        self.logger.info(f"开始爬取 Action 嵌套依赖，最大深度: {self.max_depth}")
        
        # 获取要爬取的 actions
        actions_to_crawl = self._select_actions_to_crawl(top_actions)
        self.logger.info(f"选择了 {len(actions_to_crawl)} 个 actions 进行爬取")
        
        # 递归爬取依赖
        all_dependencies = {}
        for action in tqdm(actions_to_crawl, desc="爬取 Action 依赖"):
            dependencies = self._crawl_action_recursive(action, depth=0)
            if dependencies:
                all_dependencies[action] = dependencies
        
        # 构建完整的依赖图
        dependency_graph = self._build_dependency_graph(all_dependencies)
        
        # 分析依赖关系
        analysis = self._analyze_dependencies(dependency_graph)
        
        # 保存结果
        self._save_results(all_dependencies, dependency_graph, analysis)
        
        return {
            'dependencies': all_dependencies,
            'graph': dependency_graph,
            'analysis': analysis
        }
    
    def _select_actions_to_crawl(self, top_actions: List[Dict]) -> List[str]:
        """选择要爬取的 actions"""
        selected = []
        
        # 按使用频率排序
        sorted_actions = sorted(top_actions, key=lambda x: x.get('usage_count', 0), reverse=True)
        
        for action_info in sorted_actions[:self.top_k_actions]:
            action = action_info.get('action', '')
            if not action:
                continue
            
            # 跳过官方认证的 actions（可选）
            if self.skip_verified and self._is_verified_action(action):
                self.logger.debug(f"跳过官方认证 action: {action}")
                continue
            
            selected.append(action)
        
        return selected
    
    def _crawl_action_recursive(self, action: str, depth: int, visited: Set = None) -> Optional[Dict]:
        """
        递归爬取 Action 依赖
        
        Args:
            action: Action 名称 (owner/repo)
            depth: 当前深度
            visited: 已访问的 actions 集合（防止循环）
            
        Returns:
            Action 依赖信息字典
        """
        if visited is None:
            visited = set()
        
        # 检查深度限制
        if depth >= self.max_depth:
            self.logger.debug(f"达到最大深度 {self.max_depth}: {action}")
            return None
        
        # 检查是否已访问（防止循环）
        if action in visited:
            self.logger.debug(f"检测到循环依赖: {action}")
            return {'action': action, 'circular': True}
        
        visited.add(action)
        
        # 检查是否已爬取
        if action in self.crawled_actions:
            dependencies = self.action_dependencies.get(action, [])
            return {
                'action': action,
                'dependencies': dependencies,
                'cached': True
            }
        
        try:
            self.logger.debug(f"爬取 Action: {action} (深度: {depth})")
            
            # 解析 owner 和 repo
            owner, repo_name = self._parse_action_name(action)
            if not owner or not repo_name:
                return None
            
            # 获取 Action 文件
            action_files = self.api.get_action_files(owner, repo_name)
            if not action_files:
                self.logger.debug(f"未找到 Action 文件: {action}")
                return None
            
            # 解析依赖
            dependencies = []
            metadata = {
                'action': action,
                'owner': owner,
                'repo': repo_name,
                'files_found': list(action_files.keys()),
                'depth': depth
            }
            
            # 解析每个文件
            for filename, content in action_files.items():
                if filename in ['action.yml', 'action.yaml']:
                    # 解析 action.yml
                    parsed = self.action_parser.parse_action_yml(content)
                    if parsed and 'dependencies' in parsed:
                        for dep in parsed['dependencies']:
                            dep_action = dep.get('action', '')
                            if dep_action and dep.get('type') == 'composite_dependency':
                                # 解析依赖的 action
                                parsed_dep = self.action_parser._parse_action_ref(dep_action)
                                if parsed_dep:
                                    dep_owner, dep_repo, dep_version = parsed_dep
                                    dep_key = f"{dep_owner}/{dep_repo}"
                                    dependencies.append(dep_key)
                    
                    metadata['action_yml'] = {
                        'name': parsed.get('name', ''),
                        'description': parsed.get('description', ''),
                        'using': parsed.get('runs', {}).get('using', '')
                    }
                
                elif filename == 'Dockerfile' and self.include_docker:
                    # 解析 Dockerfile
                    docker_images = self.action_parser.parse_dockerfile(content)
                    metadata['docker_images'] = docker_images
            
            # 递归爬取依赖
            recursive_deps = []
            for dep_action in dependencies:
                dep_info = self._crawl_action_recursive(dep_action, depth + 1, visited.copy())
                if dep_info:
                    recursive_deps.append(dep_info)
            
            # 保存到缓存
            self.crawled_actions.add(action)
            self.action_dependencies[action] = dependencies
            self.action_metadata[action] = metadata
            
            # 构建结果
            result = {
                'action': action,
                'dependencies': dependencies,
                'recursive_dependencies': recursive_deps,
                'metadata': metadata,
                'depth': depth
            }
            
            # 避免速率限制
            time.sleep(0.3)
            
            return result
            
        except Exception as e:
            self.logger.error(f"爬取 Action {action} 失败: {e}")
            return None
    
    def _build_dependency_graph(self, all_dependencies: Dict) -> Dict:
        """构建完整的依赖关系图"""
        self.logger.info("构建 Action 依赖图...")
        
        graph = {
            'nodes': [],
            'edges': [],
            'node_categories': {},
            'adjacency_list': {}
        }
        
        # 收集所有节点
        node_set = set()
        for action, deps_info in all_dependencies.items():
            node_set.add(action)
            if isinstance(deps_info, dict) and 'dependencies' in deps_info:
                for dep in deps_info['dependencies']:
                    node_set.add(dep)
        
        # 创建节点
        for node in node_set:
            node_info = {
                'id': node,
                'label': node,
                'is_top_action': node in all_dependencies,
                'in_degree': 0,
                'out_degree': 0
            }
            
            # 尝试从 metadata 获取更多信息
            metadata = self.action_metadata.get(node, {})
            if metadata:
                node_info.update({
                    'owner': metadata.get('owner'),
                    'repo': metadata.get('repo'),
                    'depth': metadata.get('depth', 0),
                    'has_action_yml': 'action_yml' in metadata,
                    'has_dockerfile': 'docker_images' in metadata
                })
            
            graph['nodes'].append(node_info)
        
        # 创建边
        for action, deps_info in all_dependencies.items():
            if not isinstance(deps_info, dict):
                continue
            
            dependencies = deps_info.get('dependencies', [])
            for dep in dependencies:
                edge = {
                    'source': action,
                    'target': dep,
                    'type': 'depends_on',
                    'depth': deps_info.get('depth', 0)
                }
                graph['edges'].append(edge)
                
                # 更新邻接表
                if action not in graph['adjacency_list']:
                    graph['adjacency_list'][action] = []
                graph['adjacency_list'][action].append(dep)
        
        # 计算节点的入度和出度
        for edge in graph['edges']:
            source = edge['source']
            target = edge['target']
            
            # 找到对应的节点更新度数
            for node in graph['nodes']:
                if node['id'] == source:
                    node['out_degree'] += 1
                if node['id'] == target:
                    node['in_degree'] += 1
        
        return graph
    
    def _analyze_dependencies(self, graph: Dict) -> Dict:
        """分析依赖关系"""
        analysis = {
            'statistics': {},
            'critical_actions': [],
            'dependency_chains': [],
            'circular_dependencies': []
        }
        
        # 基础统计
        nodes = graph['nodes']
        edges = graph['edges']
        
        analysis['statistics'] = {
            'total_actions': len(nodes),
            'total_dependencies': len(edges),
            'avg_dependencies_per_action': len(edges) / len(nodes) if nodes else 0,
            'max_in_degree': max((n['in_degree'] for n in nodes), default=0),
            'max_out_degree': max((n['out_degree'] for n in nodes), default=0)
        }
        
        # 找出关键 actions（高入度或高出度）
        high_in_degree = sorted(nodes, key=lambda x: x['in_degree'], reverse=True)[:10]
        high_out_degree = sorted(nodes, key=lambda x: x['out_degree'], reverse=True)[:10]
        
        analysis['critical_actions'] = {
            'most_depended_on': [{'action': n['id'], 'in_degree': n['in_degree']} for n in high_in_degree],
            'most_dependencies': [{'action': n['id'], 'out_degree': n['out_degree']} for n in high_out_degree]
        }
        
        # 检测循环依赖
        analysis['circular_dependencies'] = self._detect_circular_dependencies(graph)
        
        # 找出最长依赖链
        analysis['dependency_chains'] = self._find_longest_chains(graph)
        
        return analysis
    
    def _detect_circular_dependencies(self, graph: Dict) -> List[List[str]]:
        """检测循环依赖"""
        circular = []
        visited = set()
        
        def dfs(node, path):
            if node in visited:
                return
            
            visited.add(node)
            path.append(node)
            
            neighbors = graph['adjacency_list'].get(node, [])
            for neighbor in neighbors:
                if neighbor in path:
                    # 找到循环
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    if cycle not in circular:
                        circular.append(cycle.copy())
                else:
                    dfs(neighbor, path.copy())
        
        for node in graph['adjacency_list']:
            dfs(node, [])
        
        return circular
    
    def _find_longest_chains(self, graph: Dict, max_chains: int = 10) -> List[List[str]]:
        """找出最长依赖链"""
        chains = []
        
        def find_chains(node, current_chain, all_chains):
            current_chain.append(node)
            
            neighbors = graph['adjacency_list'].get(node, [])
            if not neighbors:
                # 到达链的末端
                all_chains.append(current_chain.copy())
            else:
                for neighbor in neighbors:
                    find_chains(neighbor, current_chain.copy(), all_chains)
        
        # 从入度为0的节点开始（这些是顶级依赖）
        start_nodes = [n['id'] for n in graph['nodes'] if n['in_degree'] == 0]
        
        for start_node in start_nodes:
            all_chains = []
            find_chains(start_node, [], all_chains)
            
            # 取最长的几条链
            all_chains.sort(key=len, reverse=True)
            chains.extend(all_chains[:2])  # 每个起始节点取2条最长链
        
        # 返回最长的几条链
        chains.sort(key=len, reverse=True)
        return chains[:max_chains]
    
    def _parse_action_name(self, action: str) -> Tuple[Optional[str], Optional[str]]:
        """解析 action 名称"""
        parts = action.split('/')
        if len(parts) >= 2:
            return parts[0], parts[1]
        return None, None
    
    def _is_verified_action(self, action: str) -> bool:
        """检查是否为官方认证的 action"""
        verified_prefixes = [
            'actions/',  # GitHub 官方 actions
            'github/',   # GitHub 官方
            'docker/',   # Docker 官方
            'azure/',    # Azure 官方
        ]
        
        return any(action.startswith(prefix) for prefix in verified_prefixes)
    
    def _save_results(self, dependencies: Dict, graph: Dict, analysis: Dict):
        """保存爬取结果"""
        # 保存原始依赖数据
        deps_file = self.raw_data_path / "action_dependencies.json"
        save_json(dependencies, str(deps_file))
        
        # 保存依赖图
        graph_file = self.processed_data_path / "action_dependency_graph.json"
        save_json(graph, str(graph_file))
        
        # 保存分析结果
        analysis_file = self.processed_data_path / "action_dependency_analysis.json"
        save_json(analysis, str(analysis_file))
        
        # 保存为 CSV 格式
        self._save_as_csv(graph)
        
        # 保存 metadata
        metadata_file = self.action_repos_dir / "action_metadata.json"
        save_json(self.action_metadata, str(metadata_file))
        
        self.logger.info(f"Action 依赖数据已保存:")
        self.logger.info(f"  涉及 Actions: {len(dependencies)}")
        self.logger.info(f"  依赖关系总数: {len(graph['edges'])}")
        self.logger.info(f"  最长依赖链: {len(analysis.get('dependency_chains', [[]])[0]) if analysis.get('dependency_chains') else 0}")
    
    def _save_as_csv(self, graph: Dict):
        """保存为 CSV 文件"""
        import csv
        
        # Action 之间的依赖关系
        edges_file = self.processed_data_path / "action_action_edges.csv"
        with open(edges_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['source', 'target', 'type'])
            for edge in graph['edges']:
                writer.writerow([edge['source'], edge['target'], 'depends_on'])
        
        # Action 节点信息
        nodes_file = self.processed_data_path / "action_nodes.csv"
        with open(nodes_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['action', 'owner', 'repo', 'in_degree', 'out_degree', 'is_top_action'])
            for node in graph['nodes']:
                writer.writerow([
                    node['id'],
                    node.get('owner', ''),
                    node.get('repo', ''),
                    node.get('in_degree', 0),
                    node.get('out_degree', 0),
                    node.get('is_top_action', False)
                ])