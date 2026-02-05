# processors/graph_builder.py
import networkx as nx
import pandas as pd
import json
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from pathlib import Path
import igraph as ig
import community as community_louvain  # python-louvain

from utils.file_utils import load_json, save_json, save_pickle

class GraphBuilder:
    """图构建器 - 构建和分析依赖关系图"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
        self.graphs_path = Path(config['paths']['graphs'])
        self.graphs_path.mkdir(parents=True, exist_ok=True)
        
    def build_repo_action_graph(self) -> Optional[nx.Graph]:
        """构建仓库-action 依赖图"""
        self.logger.info("构建仓库-action 依赖图...")
        
        # 加载数据
        edges_file = self.processed_data_path / "repo_actions_edges.csv"
        if not edges_file.exists():
            self.logger.error(f"找不到边文件: {edges_file}")
            return None
        
        try:
            # 读取 CSV 文件
            df = pd.read_csv(edges_file)
            
            # 创建有向图
            G = nx.DiGraph()
            
            # 添加边
            for _, row in df.iterrows():
                source = row['source']
                target = row['target']
                
                # 添加节点
                G.add_node(source, type='repo')
                G.add_node(target, type='action')
                
                # 添加边
                if G.has_edge(source, target):
                    # 如果边已存在，增加权重
                    G[source][target]['weight'] += 1
                else:
                    G.add_edge(source, target, weight=1, type='uses')
            
            # 计算节点属性
            self._calculate_node_attributes(G)
            
            # 保存图
            self._save_graph(G, 'repo_action_graph')
            
            # 生成统计信息
            stats = self._generate_graph_stats(G, '仓库-action')
            self._save_graph_stats(stats, 'repo_action_stats')
            
            self.logger.info(f"仓库-action 图构建完成:")
            self.logger.info(f"  节点数: {G.number_of_nodes()}")
            self.logger.info(f"  边数: {G.number_of_edges()}")
            
            return G
            
        except Exception as e:
            self.logger.error(f"构建仓库-action 图失败: {e}")
            return None
    
    def build_action_dependency_graph(self) -> Optional[nx.Graph]:
        """构建 action-action 依赖图"""
        self.logger.info("构建 action-action 依赖图...")
        
        # 加载数据
        edges_file = self.processed_data_path / "action_action_edges.csv"
        if not edges_file.exists():
            self.logger.error(f"找不到边文件: {edges_file}")
            return None
        
        try:
            # 读取 CSV 文件
            df = pd.read_csv(edges_file)
            
            # 创建有向图
            G = nx.DiGraph()
            
            # 添加边
            for _, row in df.iterrows():
                source = row['source']
                target = row['target']
                
                # 添加节点
                G.add_node(source, type='action')
                G.add_node(target, type='action')
                
                # 添加边
                if G.has_edge(source, target):
                    G[source][target]['weight'] += 1
                else:
                    G.add_edge(source, target, weight=1, type='depends_on')
            
            # 计算节点属性
            self._calculate_node_attributes(G)
            
            # 检测并标记循环依赖
            self._mark_circular_dependencies(G)
            
            # 计算依赖深度
            self._calculate_dependency_depth(G)
            
            # 保存图
            self._save_graph(G, 'action_dependency_graph')
            
            # 生成统计信息
            stats = self._generate_graph_stats(G, 'action-action')
            self._save_graph_stats(stats, 'action_dependency_stats')
            
            self.logger.info(f"Action-action 依赖图构建完成:")
            self.logger.info(f"  节点数: {G.number_of_nodes()}")
            self.logger.info(f"  边数: {G.number_of_edges()}")
            
            return G
            
        except Exception as e:
            self.logger.error(f"构建 action-action 图失败: {e}")
            return None
    
    def build_combined_graph(self) -> Optional[nx.Graph]:
        """构建组合图（仓库 + action）"""
        self.logger.info("构建组合依赖图...")
        
        # 加载两个图
        repo_action_graph = self.build_repo_action_graph()
        action_dep_graph = self.build_action_dependency_graph()
        
        if not repo_action_graph or not action_dep_graph:
            self.logger.error("无法构建组合图：缺少基础图数据")
            return None
        
        try:
            # 合并两个图
            combined = nx.compose(repo_action_graph, action_dep_graph)
            
            # 重新计算中心性指标
            self._calculate_node_attributes(combined)
            
            # 保存图
            self._save_graph(combined, 'combined_dependency_graph')
            
            # 生成统计信息
            stats = self._generate_graph_stats(combined, '组合图')
            self._save_graph_stats(stats, 'combined_stats')
            
            self.logger.info(f"组合图构建完成:")
            self.logger.info(f"  总节点数: {combined.number_of_nodes()}")
            self.logger.info(f"  总边数: {combined.number_of_edges()}")
            
            return combined
            
        except Exception as e:
            self.logger.error(f"构建组合图失败: {e}")
            return None
    
    def analyze_graph_metrics(self, G: nx.Graph) -> Dict:
        """分析图指标"""
        self.logger.info("计算图指标...")
        
        metrics = {}
        
        try:
            # 基础指标
            metrics['basic'] = {
                'nodes': G.number_of_nodes(),
                'edges': G.number_of_edges(),
                'density': nx.density(G),
                'is_directed': nx.is_directed(G),
                'is_connected': nx.is_weakly_connected(G) if nx.is_directed(G) else nx.is_connected(G)
            }
            
            # 节点度分布
            degrees = dict(G.degree())
            metrics['degree_distribution'] = {
                'max_degree': max(degrees.values(), default=0),
                'min_degree': min(degrees.values(), default=0),
                'avg_degree': sum(degrees.values()) / len(degrees) if degrees else 0,
                'degree_histogram': self._create_degree_histogram(degrees)
            }
            
            # 中心性指标（仅对较大图采样计算）
            if G.number_of_nodes() <= 1000:
                metrics['centrality'] = self._calculate_centrality(G)
            else:
                metrics['centrality'] = {'note': '图太大，跳过详细中心性计算'}
            
            # 连通分量
            if nx.is_directed(G):
                components = list(nx.weakly_connected_components(G))
            else:
                components = list(nx.connected_components(G))
            
            metrics['connectivity'] = {
                'num_components': len(components),
                'largest_component_size': max(len(c) for c in components) if components else 0,
                'component_sizes': sorted([len(c) for c in components], reverse=True)
            }
            
            # 路径长度（仅对连通图）
            if metrics['basic']['is_connected'] and G.number_of_nodes() <= 500:
                try:
                    avg_path_length = nx.average_shortest_path_length(G)
                    metrics['path_length'] = {
                        'average_shortest_path': avg_path_length
                    }
                except Exception as e:
                    metrics['path_length'] = {'error': str(e)}
            
            # 聚类系数（仅对无向图）
            if not nx.is_directed(G):
                try:
                    avg_clustering = nx.average_clustering(G)
                    metrics['clustering'] = {
                        'average_clustering_coefficient': avg_clustering
                    }
                except Exception as e:
                    metrics['clustering'] = {'error': str(e)}
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"计算图指标失败: {e}")
            return {}
    
    def detect_communities(self, G: nx.Graph) -> Dict:
        """检测社区结构"""
        self.logger.info("检测社区结构...")
        
        # 转换为无向图用于社区检测
        if nx.is_directed(G):
            G_undirected = G.to_undirected()
        else:
            G_undirected = G.copy()
        
        try:
            # 使用 Louvain 算法检测社区
            partition = community_louvain.best_partition(G_undirected)
            
            # 统计社区信息
            communities = defaultdict(list)
            for node, comm_id in partition.items():
                communities[comm_id].append(node)
            
            # 计算社区指标
            community_stats = []
            for comm_id, nodes in communities.items():
                # 计算社区内连接密度
                subgraph = G_undirected.subgraph(nodes)
                intra_edges = subgraph.number_of_edges()
                possible_intra_edges = len(nodes) * (len(nodes) - 1) / 2
                
                community_stats.append({
                    'community_id': comm_id,
                    'size': len(nodes),
                    'intra_edges': intra_edges,
                    'density': intra_edges / possible_intra_edges if possible_intra_edges > 0 else 0,
                    'nodes': nodes[:10],  # 只显示前10个节点
                    'node_count': len(nodes)
                })
            
            # 按大小排序
            community_stats.sort(key=lambda x: x['size'], reverse=True)
            
            result = {
                'num_communities': len(communities),
                'modularity': community_louvain.modularity(partition, G_undirected),
                'communities': community_stats[:20],  # 只显示前20个社区
                'partition': dict(list(partition.items())[:100])  # 只保存部分分区信息
            }
            
            # 保存结果
            save_json(result, str(self.processed_data_path / "community_detection.json"))
            
            return result
            
        except Exception as e:
            self.logger.error(f"社区检测失败: {e}")
            return {}
    
    def find_critical_nodes(self, G: nx.Graph, top_n: int = 20) -> List[Dict]:
        """找出关键节点"""
        self.logger.info(f"查找前 {top_n} 个关键节点...")
        
        critical_nodes = []
        
        try:
            # 计算多种中心性指标
            if G.number_of_nodes() <= 500:
                # 度中心性
                degree_centrality = nx.degree_centrality(G)
                
                # 中介中心性（仅对较小图）
                betweenness_centrality = nx.betweenness_centrality(G, k=min(100, G.number_of_nodes()))
                
                # 接近中心性
                closeness_centrality = nx.closeness_centrality(G)
                
                # PageRank
                pagerank = nx.pagerank(G)
                
                # 收集所有节点的指标
                nodes_data = []
                for node in G.nodes():
                    node_type = G.nodes[node].get('type', 'unknown')
                    
                    nodes_data.append({
                        'node': node,
                        'type': node_type,
                        'degree': G.degree(node),
                        'in_degree': G.in_degree(node) if nx.is_directed(G) else 0,
                        'out_degree': G.out_degree(node) if nx.is_directed(G) else 0,
                        'degree_centrality': degree_centrality.get(node, 0),
                        'betweenness_centrality': betweenness_centrality.get(node, 0),
                        'closeness_centrality': closeness_centrality.get(node, 0),
                        'pagerank': pagerank.get(node, 0)
                    })
                
                # 按多种指标排序
                for metric in ['betweenness_centrality', 'degree_centrality', 'pagerank']:
                    sorted_nodes = sorted(nodes_data, key=lambda x: x[metric], reverse=True)[:top_n]
                    critical_nodes.append({
                        'metric': metric,
                        'nodes': sorted_nodes
                    })
            
            else:
                # 对大型图，只计算度中心性
                degrees = dict(G.degree())
                sorted_degrees = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:top_n]
                
                critical_nodes.append({
                    'metric': 'degree',
                    'nodes': [{'node': n, 'degree': d} for n, d in sorted_degrees]
                })
            
            # 保存结果
            save_json(critical_nodes, str(self.processed_data_path / "critical_nodes.json"))
            
            return critical_nodes
            
        except Exception as e:
            self.logger.error(f"查找关键节点失败: {e}")
            return []
    
    def _calculate_node_attributes(self, G: nx.Graph):
        """计算节点属性"""
        # 度中心性
        if G.number_of_nodes() <= 1000:
            try:
                degree_centrality = nx.degree_centrality(G)
                for node, centrality in degree_centrality.items():
                    G.nodes[node]['degree_centrality'] = centrality
            except Exception:
                pass
        
        # PageRank
        if G.number_of_nodes() <= 2000:
            try:
                pagerank = nx.pagerank(G)
                for node, score in pagerank.items():
                    G.nodes[node]['pagerank'] = score
            except Exception:
                pass
        
        # 节点类型统计
        node_types = {}
        for node in G.nodes():
            node_type = G.nodes[node].get('type', 'unknown')
            node_types[node_type] = node_types.get(node_type, 0) + 1
        
        G.graph['node_type_stats'] = node_types
    
    def _mark_circular_dependencies(self, G: nx.Graph):
        """标记循环依赖"""
        try:
            cycles = list(nx.simple_cycles(G))
            G.graph['circular_dependencies'] = cycles
            
            # 标记涉及循环的节点
            for cycle in cycles:
                for node in cycle:
                    if 'in_cycles' not in G.nodes[node]:
                        G.nodes[node]['in_cycles'] = []
                    G.nodes[node]['in_cycles'].append(cycle)
        except Exception as e:
            self.logger.warning(f"检测循环依赖失败: {e}")
    
    def _calculate_dependency_depth(self, G: nx.Graph):
        """计算依赖深度"""
        try:
            # 找到所有入度为0的节点（顶级依赖）
            root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
            
            # 为每个节点计算深度
            for node in G.nodes():
                if node in root_nodes:
                    G.nodes[node]['depth'] = 0
                else:
                    # 计算从所有前驱节点到该节点的最长路径
                    depths = []
                    for pred in G.predecessors(node):
                        pred_depth = G.nodes[pred].get('depth', -1)
                        if pred_depth >= 0:
                            depths.append(pred_depth + 1)
                    
                    if depths:
                        G.nodes[node]['depth'] = max(depths)
                    else:
                        G.nodes[node]['depth'] = -1  # 无法确定
        except Exception as e:
            self.logger.warning(f"计算依赖深度失败: {e}")
    
    def _calculate_centrality(self, G: nx.Graph) -> Dict:
        """计算中心性指标"""
        centrality = {}
        
        try:
            # 度中心性
            centrality['degree'] = dict(nx.degree_centrality(G))
            
            # 接近中心性
            if nx.is_weakly_connected(G) if nx.is_directed(G) else nx.is_connected(G):
                centrality['closeness'] = dict(nx.closeness_centrality(G))
            
            # 中介中心性（抽样计算）
            sample_size = min(100, G.number_of_nodes())
            centrality['betweenness'] = dict(nx.betweenness_centrality(G, k=sample_size))
            
            # PageRank
            centrality['pagerank'] = dict(nx.pagerank(G))
            
        except Exception as e:
            self.logger.warning(f"中心性计算部分失败: {e}")
        
        return centrality
    
    def _create_degree_histogram(self, degrees: Dict) -> List[Dict]:
        """创建度分布直方图"""
        from collections import Counter
        degree_counts = Counter(degrees.values())
        
        histogram = []
        for degree, count in sorted(degree_counts.items()):
            histogram.append({
                'degree': degree,
                'count': count,
                'percentage': count / len(degrees) * 100
            })
        
        return histogram
    
    def _generate_graph_stats(self, G: nx.Graph, graph_name: str) -> Dict:
        """生成图统计信息"""
        stats = {
            'graph_name': graph_name,
            'timestamp': pd.Timestamp.now().isoformat(),
            'basic_stats': {
                'nodes': G.number_of_nodes(),
                'edges': G.number_of_edges(),
                'directed': nx.is_directed(G),
                'density': nx.density(G)
            },
            'node_types': G.graph.get('node_type_stats', {}),
            'degree_stats': self._calculate_degree_stats(G),
            'connectivity': self._calculate_connectivity_stats(G)
        }
        
        return stats
    
    def _calculate_degree_stats(self, G: nx.Graph) -> Dict:
        """计算度统计"""
        degrees = [d for _, d in G.degree()]
        
        if not degrees:
            return {}
        
        import numpy as np
        return {
            'max': max(degrees),
            'min': min(degrees),
            'mean': np.mean(degrees),
            'median': np.median(degrees),
            'std': np.std(degrees)
        }
    
    def _calculate_connectivity_stats(self, G: nx.Graph) -> Dict:
        """计算连通性统计"""
        if nx.is_directed(G):
            components = list(nx.weakly_connected_components(G))
        else:
            components = list(nx.connected_components(G))
        
        component_sizes = [len(c) for c in components]
        
        return {
            'num_components': len(components),
            'largest_component': max(component_sizes) if component_sizes else 0,
            'component_size_distribution': component_sizes
        }
    
    def _save_graph(self, G: nx.Graph, name: str):
        """保存图到文件"""
        # 保存为 NetworkX pickle 格式
        nx_file = self.graphs_path / f"{name}.gpickle"
        nx.write_gpickle(G, str(nx_file))
        
        # 保存为 GML 格式（兼容其他工具）
        gml_file = self.graphs_path / f"{name}.gml"
        nx.write_gml(G, str(gml_file))
        
        # 保存为 JSON 格式（便于查看）
        json_file = self.graphs_path / f"{name}.json"
        
        # 转换图数据为 JSON 可序列化的格式
        graph_data = {
            'nodes': [],
            'edges': []
        }
        
        # 节点数据
        for node, data in G.nodes(data=True):
            node_info = {'id': node, **data}
            # 确保数据可序列化
            for key, value in list(node_info.items()):
                if not isinstance(value, (str, int, float, bool, type(None))):
                    node_info[key] = str(value)
            graph_data['nodes'].append(node_info)
        
        # 边数据
        for source, target, data in G.edges(data=True):
            edge_info = {
                'source': source,
                'target': target,
                **data
            }
            # 确保数据可序列化
            for key, value in list(edge_info.items()):
                if not isinstance(value, (str, int, float, bool, type(None))):
                    edge_info[key] = str(value)
            graph_data['edges'].append(edge_info)
        
        save_json(graph_data, str(json_file))
        
        self.logger.debug(f"图已保存到: {nx_file}, {gml_file}, {json_file}")
    
    def _save_graph_stats(self, stats: Dict, name: str):
        """保存图统计信息"""
        stats_file = self.processed_data_path / f"{name}.json"
        save_json(stats, str(stats_file))