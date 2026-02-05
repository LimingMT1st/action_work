# 解析 Action 嵌套依赖，构建完整依赖链
# processors/action_dependency_resolver.py
import networkx as nx
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from pathlib import Path

from utils.file_utils import load_json, save_json
from .graph_builder import GraphBuilder

class ActionDependencyResolver:
    """Action 依赖解析器 - 解析和解决依赖关系"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
        self.graphs_path = Path(config['paths']['graphs'])
        
    def resolve_dependencies(self, action: str) -> Dict:
        """解析特定 action 的所有依赖"""
        self.logger.info(f"解析 action 依赖: {action}")
        
        # 加载依赖图
        graph_file = self.graphs_path / "action_dependency_graph.gml"
        if not graph_file.exists():
            self.logger.error(f"依赖图文件不存在: {graph_file}")
            return {}
        
        try:
            G = nx.read_gml(str(graph_file))
            
            # 检查 action 是否在图中
            if action not in G:
                self.logger.warning(f"Action {action} 不在依赖图中")
                return {}
            
            # 解析依赖
            dependencies = self._resolve_all_dependencies(G, action)
            
            # 分析依赖关系
            analysis = self._analyze_dependency_structure(dependencies)
            
            # 检测问题
            issues = self._detect_dependency_issues(G, action, dependencies)
            
            result = {
                'action': action,
                'dependencies': dependencies,
                'analysis': analysis,
                'issues': issues,
                'visualization_data': self._prepare_visualization_data(G, action)
            }
            
            # 保存结果
            save_json(
                result,
                str(self.processed_data_path / f"dependency_resolution_{action.replace('/', '_')}.json")
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"解析依赖失败: {e}")
            return {}
    
    def find_transitive_dependencies(self, action: str) -> Dict:
        """查找传递依赖"""
        self.logger.info(f"查找传递依赖: {action}")
        
        # 加载依赖图
        graph_file = self.graphs_path / "action_dependency_graph.gml"
        if not graph_file.exists():
            return {}
        
        try:
            G = nx.read_gml(str(graph_file))
            
            if action not in G:
                return {}
            
            # 查找所有传递依赖
            transitive_deps = set()
            visited = set()
            
            def dfs(node, depth=0):
                if node in visited:
                    return
                
                visited.add(node)
                
                # 遍历所有依赖
                for successor in G.successors(node):
                    transitive_deps.add((node, successor, depth))
                    dfs(successor, depth + 1)
            
            dfs(action)
            
            # 组织结果
            result = {
                'action': action,
                'transitive_dependencies': list(transitive_deps),
                'total_dependencies': len(transitive_deps),
                'dependency_depth': self._calculate_max_depth(transitive_deps),
                'unique_dependencies': len(set(dep[1] for dep in transitive_deps))
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"查找传递依赖失败: {e}")
            return {}
    
    def detect_circular_dependencies(self) -> List[List[str]]:
        """检测循环依赖"""
        self.logger.info("检测循环依赖...")
        
        # 加载依赖图
        graph_file = self.graphs_path / "action_dependency_graph.gml"
        if not graph_file.exists():
            return []
        
        try:
            G = nx.read_gml(str(graph_file))
            
            # 检测所有简单循环
            cycles = list(nx.simple_cycles(G))
            
            # 分析和分类循环
            analyzed_cycles = []
            for cycle in cycles:
                if len(cycle) <= 10:  # 忽略太长的循环（可能是误报）
                    analysis = self._analyze_cycle(G, cycle)
                    analyzed_cycles.append({
                        'cycle': cycle,
                        'length': len(cycle),
                        'analysis': analysis
                    })
            
            # 按长度排序
            analyzed_cycles.sort(key=lambda x: x['length'])
            
            # 保存结果
            save_json(
                analyzed_cycles,
                str(self.processed_data_path / "circular_dependencies.json")
            )
            
            self.logger.info(f"检测到 {len(analyzed_cycles)} 个循环依赖")
            
            return analyzed_cycles
            
        except Exception as e:
            self.logger.error(f"检测循环依赖失败: {e}")
            return []
    
    def calculate_dependency_metrics(self) -> Dict:
        """计算依赖指标"""
        self.logger.info("计算依赖指标...")
        
        # 加载依赖图
        graph_file = self.graphs_path / "action_dependency_graph.gml"
        if not graph_file.exists():
            return {}
        
        try:
            G = nx.read_gml(str(graph_file))
            
            metrics = {
                'basic_metrics': self._calculate_basic_metrics(G),
                'dependency_depth_metrics': self._calculate_depth_metrics(G),
                'complexity_metrics': self._calculate_complexity_metrics(G),
                'critical_path_analysis': self._analyze_critical_paths(G),
                'vulnerability_metrics': self._calculate_vulnerability_metrics(G)
            }
            
            # 保存结果
            save_json(
                metrics,
                str(self.processed_data_path / "dependency_metrics.json")
            )
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"计算依赖指标失败: {e}")
            return {}
    
    def find_common_dependency_patterns(self) -> Dict:
        """查找常见依赖模式"""
        self.logger.info("查找常见依赖模式...")
        
        patterns = {
            'star_patterns': [],
            'chain_patterns': [],
            'tree_patterns': [],
            'complex_patterns': [],
            'summary': {}
        }
        
        # 加载依赖图
        graph_file = self.graphs_path / "action_dependency_graph.gml"
        if not graph_file.exists():
            return patterns
        
        try:
            G = nx.read_gml(str(graph_file))
            
            # 查找星型模式（一个中心节点，多个依赖）
            star_patterns = self._find_star_patterns(G)
            patterns['star_patterns'] = star_patterns[:10]  # 前10个
            
            # 查找链式模式
            chain_patterns = self._find_chain_patterns(G)
            patterns['chain_patterns'] = chain_patterns[:10]
            
            # 查找树型模式
            tree_patterns = self._find_tree_patterns(G)
            patterns['tree_patterns'] = tree_patterns[:10]
            
            # 查找复杂模式
            complex_patterns = self._find_complex_patterns(G)
            patterns['complex_patterns'] = complex_patterns[:10]
            
            # 生成摘要
            patterns['summary'] = {
                'total_patterns_found': len(star_patterns) + len(chain_patterns) + 
                                      len(tree_patterns) + len(complex_patterns),
                'most_common_pattern': self._identify_most_common_pattern(patterns),
                'pattern_distribution': {
                    'star': len(star_patterns),
                    'chain': len(chain_patterns),
                    'tree': len(tree_patterns),
                    'complex': len(complex_patterns)
                }
            }
            
            # 保存结果
            save_json(
                patterns,
                str(self.processed_data_path / "dependency_patterns.json")
            )
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"查找依赖模式失败: {e}")
            return patterns
    
    def _resolve_all_dependencies(self, G: nx.DiGraph, start_node: str) -> Dict:
        """解析所有依赖关系"""
        dependencies = {
            'direct_dependencies': [],
            'transitive_dependencies': [],
            'dependency_tree': {},
            'dependency_levels': defaultdict(list)
        }
        
        # BFS 遍历依赖
        queue = deque([(start_node, 0)])
        visited = set()
        
        while queue:
            node, level = queue.popleft()
            
            if node in visited:
                continue
            
            visited.add(node)
            
            # 记录层级
            dependencies['dependency_levels'][level].append(node)
            
            # 获取直接依赖
            successors = list(G.successors(node))
            
            if level == 0:
                dependencies['direct_dependencies'] = successors
            else:
                dependencies['transitive_dependencies'].append({
                    'node': node,
                    'level': level,
                    'dependencies': successors
                })
            
            # 添加到队列继续遍历
            for successor in successors:
                if successor not in visited:
                    queue.append((successor, level + 1))
        
        # 构建依赖树
        dependencies['dependency_tree'] = self._build_dependency_tree(G, start_node)
        
        return dependencies
    
    def _build_dependency_tree(self, G: nx.DiGraph, root: str) -> Dict:
        """构建依赖树"""
        tree = {
            'node': root,
            'type': G.nodes[root].get('type', 'unknown'),
            'children': []
        }
        
        def build_subtree(node, depth=0, max_depth=5):
            if depth >= max_depth:
                return {'node': node, 'type': 'leaf', 'depth_limit_reached': True}
            
            children = []
            for child in G.successors(node):
                child_tree = build_subtree(child, depth + 1, max_depth)
                children.append(child_tree)
            
            return {
                'node': node,
                'type': G.nodes[node].get('type', 'unknown'),
                'children': children
            }
        
        tree['children'] = [
            build_subtree(child, depth=1, max_depth=5)
            for child in G.successors(root)
        ]
        
        return tree
    
    def _analyze_dependency_structure(self, dependencies: Dict) -> Dict:
        """分析依赖结构"""
        analysis = {
            'depth_analysis': {},
            'breadth_analysis': {},
            'complexity_metrics': {},
            'critical_nodes': []
        }
        
        # 深度分析
        levels = dependencies.get('dependency_levels', {})
        if levels:
            analysis['depth_analysis'] = {
                'max_depth': max(levels.keys()) if levels else 0,
                'nodes_by_depth': {level: len(nodes) for level, nodes in levels.items()},
                'avg_depth': self._calculate_average_depth(levels)
            }
        
        # 广度分析
        direct_deps = dependencies.get('direct_dependencies', [])
        transitive_deps = dependencies.get('transitive_dependencies', [])
        
        analysis['breadth_analysis'] = {
            'direct_dependencies_count': len(direct_deps),
            'transitive_dependencies_count': sum(len(dep['dependencies']) for dep in transitive_deps),
            'unique_dependencies_count': len(set(direct_deps + 
                [dep['node'] for dep in transitive_deps] + 
                [d for dep in transitive_deps for d in dep['dependencies']]))
        }
        
        # 复杂度指标
        analysis['complexity_metrics'] = {
            'fan_in': len(direct_deps),
            'fan_out': self._calculate_fan_out(dependencies),
            'cyclomatic_complexity': self._calculate_cyclomatic_complexity(dependencies)
        }
        
        return analysis
    
    def _detect_dependency_issues(self, G: nx.DiGraph, start_node: str, 
                                 dependencies: Dict) -> List[Dict]:
        """检测依赖问题"""
        issues = []
        
        # 1. 检查循环依赖
        try:
            cycles = nx.simple_cycles(G)
            for cycle in cycles:
                if start_node in cycle:
                    issues.append({
                        'type': 'circular_dependency',
                        'severity': 'high',
                        'description': f'检测到循环依赖: {" -> ".join(cycle)}',
                        'cycle': cycle
                    })
                    break
        except Exception:
            pass
        
        # 2. 检查深度过大
        max_depth = max(dependencies.get('dependency_levels', {}).keys(), default=0)
        if max_depth > 10:
            issues.append({
                'type': 'deep_dependency_chain',
                'severity': 'medium',
                'description': f'依赖链深度过大: {max_depth} 层',
                'max_depth': max_depth
            })
        
        # 3. 检查重复依赖
        all_deps = []
        for deps in dependencies.get('dependency_levels', {}).values():
            all_deps.extend(deps)
        
        from collections import Counter
        dep_counts = Counter(all_deps)
        duplicates = [dep for dep, count in dep_counts.items() if count > 1]
        
        if duplicates:
            issues.append({
                'type': 'duplicate_dependencies',
                'severity': 'low',
                'description': f'发现 {len(duplicates)} 个重复依赖',
                'duplicates': duplicates[:5]  # 只显示前5个
            })
        
        # 4. 检查高风险依赖
        high_risk_actions = ['unknown-action', 'unmaintained/repo']  # 示例
        for dep in all_deps:
            if any(risk_action in dep for risk_action in high_risk_actions):
                issues.append({
                    'type': 'high_risk_dependency',
                    'severity': 'high',
                    'description': f'依赖高风险 action: {dep}',
                    'dependency': dep
                })
        
        return issues
    
    def _prepare_visualization_data(self, G: nx.DiGraph, start_node: str) -> Dict:
        """准备可视化数据"""
        visualization_data = {
            'nodes': [],
            'edges': [],
            'hierarchical_data': {}
        }
        
        # 收集相关节点和边
        relevant_nodes = set()
        relevant_edges = []
        
        # BFS 收集相关子图
        queue = deque([start_node])
        visited = set()
        
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            
            visited.add(node)
            relevant_nodes.add(node)
            
            # 收集出边
            for successor in G.successors(node):
                relevant_edges.append({
                    'source': node,
                    'target': successor,
                    'type': 'depends_on'
                })
                queue.append(successor)
            
            # 收集入边（限于相关节点之间）
            for predecessor in G.predecessors(node):
                if predecessor in visited or predecessor in queue:
                    relevant_edges.append({
                        'source': predecessor,
                        'target': node,
                        'type': 'depends_on'
                    })
        
        # 构建节点数据
        for node in relevant_nodes:
            node_data = {
                'id': node,
                'label': node,
                'type': G.nodes[node].get('type', 'unknown'),
                'is_root': node == start_node
            }
            
            # 添加额外属性
            for attr in ['pagerank', 'degree_centrality', 'in_degree', 'out_degree']:
                if attr in G.nodes[node]:
                    node_data[attr] = G.nodes[node][attr]
            
            visualization_data['nodes'].append(node_data)
        
        visualization_data['edges'] = relevant_edges
        
        return visualization_data
    
    def _calculate_max_depth(self, dependencies: Set[Tuple]) -> int:
        """计算最大深度"""
        if not dependencies:
            return 0
        
        max_depth = 0
        for _, _, depth in dependencies:
            max_depth = max(max_depth, depth)
        
        return max_depth
    
    def _analyze_cycle(self, G: nx.DiGraph, cycle: List[str]) -> Dict:
        """分析循环"""
        analysis = {
            'nodes_in_cycle': len(cycle),
            'cycle_types': set(),
            'potential_issues': []
        }
        
        # 分析节点类型
        node_types = set()
        for node in cycle:
            node_type = G.nodes[node].get('type', 'unknown')
            node_types.add(node_type)
        
        analysis['cycle_types'] = node_types
        
        # 检查潜在问题
        if len(cycle) == 2:
            analysis['potential_issues'].append('双向依赖，可能导致构建顺序问题')
        elif len(cycle) > 5:
            analysis['potential_issues'].append('复杂循环，可能难以理解和维护')
        
        # 检查是否涉及高风险节点
        high_risk_keywords = ['login', 'secret', 'token', 'auth']
        for node in cycle:
            if any(keyword in node.lower() for keyword in high_risk_keywords):
                analysis['potential_issues'].append('循环涉及高风险认证相关节点')
                break
        
        return analysis
    
    def _calculate_basic_metrics(self, G: nx.DiGraph) -> Dict:
        """计算基础指标"""
        return {
            'total_actions': G.number_of_nodes(),
            'total_dependencies': G.number_of_edges(),
            'density': nx.density(G),
            'average_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0
        }
    
    def _calculate_depth_metrics(self, G: nx.DiGraph) -> Dict:
        """计算深度指标"""
        depth_metrics = {
            'max_depth': 0,
            'average_depth': 0,
            'depth_distribution': defaultdict(int)
        }
        
        # 找到所有根节点（入度为0）
        root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        all_depths = []
        
        for root in root_nodes:
            # BFS 计算深度
            depths = {root: 0}
            queue = deque([root])
            
            while queue:
                node = queue.popleft()
                current_depth = depths[node]
                
                for successor in G.successors(node):
                    if successor not in depths:
                        depths[successor] = current_depth + 1
                        queue.append(successor)
            
            # 更新统计
            for depth in depths.values():
                depth_metrics['depth_distribution'][depth] += 1
                all_depths.append(depth)
        
        if all_depths:
            depth_metrics['max_depth'] = max(all_depths)
            depth_metrics['average_depth'] = sum(all_depths) / len(all_depths)
        
        return depth_metrics
    
    def _calculate_complexity_metrics(self, G: nx.DiGraph) -> Dict:
        """计算复杂度指标"""
        # 计算每个节点的依赖复杂度
        complexity_scores = {}
        
        for node in G.nodes():
            # 依赖数量
            out_degree = G.out_degree(node)
            in_degree = G.in_degree(node)
            
            # 计算复杂度分数
            complexity = out_degree * 2 + in_degree  # 出边权重更高
            
            complexity_scores[node] = {
                'out_degree': out_degree,
                'in_degree': in_degree,
                'complexity_score': complexity,
                'is_critical': in_degree >= 3 or out_degree >= 5
            }
        
        # 总体复杂度
        total_complexity = sum(score['complexity_score'] for score in complexity_scores.values())
        avg_complexity = total_complexity / len(complexity_scores) if complexity_scores else 0
        
        return {
            'complexity_scores': dict(list(complexity_scores.items())[:20]),  # 只显示前20个
            'total_complexity': total_complexity,
            'average_complexity': avg_complexity,
            'most_complex_nodes': sorted(
                complexity_scores.items(),
                key=lambda x: x[1]['complexity_score'],
                reverse=True
            )[:10]
        }
    
    def _analyze_critical_paths(self, G: nx.DiGraph) -> Dict:
        """分析关键路径"""
        critical_paths = []
        
        # 找到所有根节点
        root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        for root in root_nodes:
            # 找到从根节点出发的最长路径
            try:
                longest_path = nx.dag_longest_path(G.subgraph(
                    nx.descendants(G, root).union({root})
                ))
                
                if len(longest_path) >= 3:  # 只考虑长度>=3的路径
                    critical_paths.append({
                        'root': root,
                        'path': longest_path,
                        'length': len(longest_path),
                        'nodes': longest_path
                    })
            except Exception:
                continue
        
        # 按长度排序
        critical_paths.sort(key=lambda x: x['length'], reverse=True)
        
        return {
            'critical_paths': critical_paths[:10],  # 前10个关键路径
            'longest_path_length': critical_paths[0]['length'] if critical_paths else 0,
            'total_critical_paths': len(critical_paths)
        }
    
    def _calculate_vulnerability_metrics(self, G: nx.DiGraph) -> Dict:
        """计算漏洞指标"""
        vulnerability_scores = {}
        
        for node in G.nodes():
            score = 0
            
            # 基于度中心性
            out_degree = G.out_degree(node)
            in_degree = G.in_degree(node)
            
            # 高入度节点更关键（被更多依赖）
            if in_degree >= 5:
                score += 3
            elif in_degree >= 3:
                score += 2
            elif in_degree >= 1:
                score += 1
            
            # 高出度节点更复杂（依赖更多）
            if out_degree >= 5:
                score += 2
            elif out_degree >= 3:
                score += 1
            
            # 基于节点类型
            node_type = G.nodes[node].get('type', 'unknown')
            if node_type == 'action':
                score += 1
            
            # 基于名称（简单启发式）
            node_lower = node.lower()
            if any(keyword in node_lower for keyword in ['auth', 'login', 'secret', 'token']):
                score += 2
            
            vulnerability_scores[node] = score
        
        # 找出高漏洞分数节点
        high_vulnerability = sorted(
            vulnerability_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:20]
        
        return {
            'vulnerability_scores': dict(high_vulnerability),
            'average_vulnerability': sum(vulnerability_scores.values()) / len(vulnerability_scores) if vulnerability_scores else 0,
            'high_vulnerability_nodes': high_vulnerability
        }
    
    def _find_star_patterns(self, G: nx.DiGraph) -> List[Dict]:
        """查找星型模式"""
        star_patterns = []
        
        for node in G.nodes():
            out_degree = G.out_degree(node)
            in_degree = G.in_degree(node)
            
            # 星型模式：一个中心节点，多个依赖
            if out_degree >= 3 and in_degree <= 1:
                star_patterns.append({
                    'center': node,
                    'dependencies': list(G.successors(node)),
                    'dependency_count': out_degree,
                    'pattern_type': 'star'
                })
        
        # 按依赖数量排序
        star_patterns.sort(key=lambda x: x['dependency_count'], reverse=True)
        return star_patterns
    
    def _find_chain_patterns(self, G: nx.DiGraph) -> List[Dict]:
        """查找链式模式"""
        chain_patterns = []
        
        # 找到所有线性链
        visited = set()
        
        for node in G.nodes():
            if node in visited or G.out_degree(node) != 1 or G.in_degree(node) > 1:
                continue
            
            # 跟随链
            chain = [node]
            current = node
            visited.add(node)
            
            while True:
                successors = list(G.successors(current))
                if len(successors) != 1:
                    break
                
                next_node = successors[0]
                if next_node in visited or G.in_degree(next_node) > 1:
                    break
                
                chain.append(next_node)
                visited.add(next_node)
                current = next_node
            
            if len(chain) >= 3:  # 至少3个节点的链
                chain_patterns.append({
                    'chain': chain,
                    'length': len(chain),
                    'pattern_type': 'chain'
                })
        
        # 按长度排序
        chain_patterns.sort(key=lambda x: x['length'], reverse=True)
        return chain_patterns
    
    def _find_tree_patterns(self, G: nx.DiGraph) -> List[Dict]:
        """查找树型模式"""
        tree_patterns = []
        
        # 找到所有根节点
        root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        for root in root_nodes:
            # BFS 检查树结构
            is_tree = True
            visited = set()
            queue = deque([root])
            
            while queue and is_tree:
                node = queue.popleft()
                if node in visited:
                    is_tree = False
                    break
                
                visited.add(node)
                successors = list(G.successors(node))
                queue.extend(successors)
            
            if is_tree and len(visited) >= 3:
                tree_patterns.append({
                    'root': root,
                    'nodes': list(visited),
                    'size': len(visited),
                    'pattern_type': 'tree'
                })
        
        # 按大小排序
        tree_patterns.sort(key=lambda x: x['size'], reverse=True)
        return tree_patterns
    
    def _find_complex_patterns(self, G: nx.DiGraph) -> List[Dict]:
        """查找复杂模式"""
        complex_patterns = []
        
        # 检测强连通分量（复杂相互依赖）
        sccs = list(nx.strongly_connected_components(G))
        
        for scc in sccs:
            if len(scc) >= 3:  # 至少3个节点的强连通分量
                subgraph = G.subgraph(scc)
                
                # 分析复杂度
                edge_count = subgraph.number_of_edges()
                density = nx.density(subgraph)
                
                complex_patterns.append({
                    'nodes': list(scc),
                    'size': len(scc),
                    'edge_count': edge_count,
                    'density': density,
                    'pattern_type': 'complex'
                })
        
        # 按复杂度排序
        complex_patterns.sort(key=lambda x: x['density'], reverse=True)
        return complex_patterns
    
    def _identify_most_common_pattern(self, patterns: Dict) -> str:
        """识别最常见的模式"""
        distribution = patterns.get('summary', {}).get('pattern_distribution', {})
        
        if not distribution:
            return 'unknown'
        
        max_count = 0
        most_common = 'unknown'
        
        for pattern_type, count in distribution.items():
            if count > max_count:
                max_count = count
                most_common = pattern_type
        
        return most_common
    
    def _calculate_average_depth(self, levels: Dict) -> float:
        """计算平均深度"""
        total_nodes = 0
        weighted_sum = 0
        
        for depth, nodes in levels.items():
            node_count = len(nodes)
            total_nodes += node_count
            weighted_sum += depth * node_count
        
        return weighted_sum / total_nodes if total_nodes > 0 else 0
    
    def _calculate_fan_out(self, dependencies: Dict) -> int:
        """计算扇出"""
        direct_deps = dependencies.get('direct_dependencies', [])
        return len(direct_deps)
    
    def _calculate_cyclomatic_complexity(self, dependencies: Dict) -> int:
        """计算圈复杂度（简化版）"""
        # 简化的圈复杂度计算：边数 - 节点数 + 2*连通分量数
        # 这里使用依赖数量作为近似
        
        all_nodes = set()
        all_edges = 0
        
        # 收集所有节点和边
        levels = dependencies.get('dependency_levels', {})
        for level_nodes in levels.values():
            all_nodes.update(level_nodes)
        
        direct_deps = dependencies.get('direct_dependencies', [])
        transitive_deps = dependencies.get('transitive_dependencies', [])
        
        # 估计边数
        all_edges = len(direct_deps)
        for dep in transitive_deps:
            all_edges += len(dep.get('dependencies', []))
        
        # 圈复杂度公式
        if all_nodes:
            # 简化计算
            complexity = all_edges - len(all_nodes) + 2
            return max(1, complexity)  # 确保至少为1
        
        return 1