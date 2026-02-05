# analysis/action_dependency_analysis.py
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Set
import logging
from pathlib import Path
from collections import defaultdict, deque
import json

from utils.file_utils import load_json, save_json
from processors.graph_builder import GraphBuilder
from processors.action_dependency_resolver import ActionDependencyResolver

class ActionDependencyAnalysis:
    """Action 依赖分析器 - 深度分析依赖关系"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
        self.graphs_path = Path(config['paths']['graphs'])
        
        # 工具
        self.graph_builder = GraphBuilder(config)
        self.dependency_resolver = ActionDependencyResolver(config)
    
    def analyze_supply_chain_vulnerabilities(self) -> Dict:
        """分析供应链漏洞"""
        self.logger.info("分析供应链漏洞...")
        
        vulnerabilities = {
            'single_points_of_failure': [],
            'critical_dependency_chains': [],
            'vulnerability_clusters': [],
            'attack_surface_analysis': {},
            'summary': {}
        }
        
        try:
            # 加载依赖图
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if not graph_file.exists():
                return vulnerabilities
            
            G = nx.read_gml(str(graph_file))
            
            # 1. 单点故障分析
            vulnerabilities['single_points_of_failure'] = self._find_single_points_of_failure(G)
            
            # 2. 关键依赖链分析
            vulnerabilities['critical_dependency_chains'] = self._find_critical_dependency_chains(G)
            
            # 3. 漏洞集群分析
            vulnerabilities['vulnerability_clusters'] = self._find_vulnerability_clusters(G)
            
            # 4. 攻击面分析
            vulnerabilities['attack_surface_analysis'] = self._analyze_attack_surface(G)
            
            # 5. 生成摘要
            vulnerabilities['summary'] = self._generate_vulnerability_summary(vulnerabilities)
            
            # 保存分析结果
            self._save_vulnerability_analysis(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"分析供应链漏洞失败: {e}")
            return vulnerabilities
    
    def analyze_dependency_complexity(self) -> Dict:
        """分析依赖复杂度"""
        self.logger.info("分析依赖复杂度...")
        
        complexity_analysis = {
            'cyclomatic_complexity': {},
            'cognitive_complexity': {},
            'maintenance_complexity': {},
            'coupling_analysis': {},
            'cohesion_analysis': {}
        }
        
        try:
            # 加载依赖图
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if not graph_file.exists():
                return complexity_analysis
            
            G = nx.read_gml(str(graph_file))
            
            # 1. 圈复杂度分析
            complexity_analysis['cyclomatic_complexity'] = self._calculate_cyclomatic_complexity(G)
            
            # 2. 认知复杂度分析
            complexity_analysis['cognitive_complexity'] = self._calculate_cognitive_complexity(G)
            
            # 3. 维护复杂度分析
            complexity_analysis['maintenance_complexity'] = self._calculate_maintenance_complexity(G)
            
            # 4. 耦合度分析
            complexity_analysis['coupling_analysis'] = self._analyze_coupling(G)
            
            # 5. 内聚度分析
            complexity_analysis['cohesion_analysis'] = self._analyze_cohesion(G)
            
            # 保存分析结果
            self._save_complexity_analysis(complexity_analysis)
            
            return complexity_analysis
            
        except Exception as e:
            self.logger.error(f"分析依赖复杂度失败: {e}")
            return complexity_analysis
    
    def analyze_dependency_evolution(self) -> Dict:
        """分析依赖演化"""
        self.logger.info("分析依赖演化...")
        
        evolution_analysis = {
            'dependency_growth': {},
            'stability_analysis': {},
            'technical_debt': {},
            'refactoring_opportunities': [],
            'evolution_trends': {}
        }
        
        try:
            # 这里需要历史数据，使用模拟数据
            # 实际项目中应该从版本历史中提取
            
            # 1. 依赖增长分析
            evolution_analysis['dependency_growth'] = self._analyze_dependency_growth()
            
            # 2. 稳定性分析
            evolution_analysis['stability_analysis'] = self._analyze_stability()
            
            # 3. 技术债务分析
            evolution_analysis['technical_debt'] = self._analyze_technical_debt()
            
            # 4. 重构机会
            evolution_analysis['refactoring_opportunities'] = self._identify_refactoring_opportunities()
            
            # 5. 演化趋势
            evolution_analysis['evolution_trends'] = self._analyze_evolution_trends()
            
            # 保存分析结果
            self._save_evolution_analysis(evolution_analysis)
            
            return evolution_analysis
            
        except Exception as e:
            self.logger.error(f"分析依赖演化失败: {e}")
            return evolution_analysis
    
    def perform_impact_analysis(self, target_action: str) -> Dict:
        """执行影响分析"""
        self.logger.info(f"执行影响分析: {target_action}")
        
        impact_analysis = {
            'target': target_action,
            'direct_impact': {},
            'indirect_impact': {},
            'risk_propagation': {},
            'mitigation_strategies': []
        }
        
        try:
            # 加载依赖图
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if not graph_file.exists():
                return impact_analysis
            
            G = nx.read_gml(str(graph_file))
            
            # 检查目标是否存在
            if target_action not in G:
                impact_analysis['error'] = f"Action {target_action} 不在依赖图中"
                return impact_analysis
            
            # 1. 直接影响分析
            impact_analysis['direct_impact'] = self._analyze_direct_impact(G, target_action)
            
            # 2. 间接影响分析
            impact_analysis['indirect_impact'] = self._analyze_indirect_impact(G, target_action)
            
            # 3. 风险传播分析
            impact_analysis['risk_propagation'] = self._analyze_risk_propagation(G, target_action)
            
            # 4. 缓解策略
            impact_analysis['mitigation_strategies'] = self._generate_mitigation_strategies(
                G, target_action, impact_analysis
            )
            
            # 保存分析结果
            self._save_impact_analysis(target_action, impact_analysis)
            
            return impact_analysis
            
        except Exception as e:
            self.logger.error(f"执行影响分析失败: {e}")
            return impact_analysis
    
    def generate_dependency_health_score(self) -> Dict:
        """生成依赖健康评分"""
        self.logger.info("生成依赖健康评分...")
        
        health_scores = {
            'overall_score': 0,
            'component_scores': {},
            'risk_factors': [],
            'improvement_areas': [],
            'health_trend': {}
        }
        
        try:
            # 加载各种分析数据
            vulnerability_analysis = load_json(
                str(self.processed_data_path / "vulnerability_analysis.json")
            )
            
            complexity_analysis = load_json(
                str(self.processed_data_path / "complexity_analysis.json")
            )
            
            # 计算总体评分
            overall_score = self._calculate_overall_health_score(
                vulnerability_analysis, complexity_analysis
            )
            
            health_scores['overall_score'] = overall_score
            
            # 计算组件评分
            health_scores['component_scores'] = self._calculate_component_scores(
                vulnerability_analysis, complexity_analysis
            )
            
            # 识别风险因素
            health_scores['risk_factors'] = self._identify_risk_factors(
                vulnerability_analysis, complexity_analysis
            )
            
            # 识别改进领域
            health_scores['improvement_areas'] = self._identify_improvement_areas(
                vulnerability_analysis, complexity_analysis
            )
            
            # 健康趋势
            health_scores['health_trend'] = self._analyze_health_trend()
            
            # 保存健康评分
            self._save_health_scores(health_scores)
            
            return health_scores
            
        except Exception as e:
            self.logger.error(f"生成健康评分失败: {e}")
            return health_scores
    
    def _find_single_points_of_failure(self, G: nx.DiGraph) -> List[Dict]:
        """查找单点故障"""
        single_points = []
        
        # 计算节点的中介中心性
        try:
            betweenness = nx.betweenness_centrality(G, k=min(100, G.number_of_nodes()))
        except:
            betweenness = {}
        
        # 计算节点的 PageRank
        try:
            pagerank = nx.pagerank(G)
        except:
            pagerank = {}
        
        # 找出关键节点
        for node in G.nodes():
            # 计算重要性分数
            importance_score = 0
            
            # 1. 高入度节点（被很多节点依赖）
            in_degree = G.in_degree(node)
            if in_degree >= 5:
                importance_score += in_degree * 2
            
            # 2. 高中介中心性节点
            if betweenness:
                importance_score += betweenness.get(node, 0) * 100
            
            # 3. 高 PageRank 节点
            if pagerank:
                importance_score += pagerank.get(node, 0) * 1000
            
            # 4. 检查是否在关键路径上
            is_critical = self._is_node_on_critical_path(G, node)
            if is_critical:
                importance_score += 50
            
            # 如果重要性分数足够高，标记为潜在单点故障
            if importance_score >= 10:
                single_points.append({
                    'node': node,
                    'importance_score': importance_score,
                    'in_degree': in_degree,
                    'betweenness_centrality': betweenness.get(node, 0) if betweenness else 0,
                    'pagerank': pagerank.get(node, 0) if pagerank else 0,
                    'is_critical_path': is_critical,
                    'risk_level': 'high' if importance_score >= 30 else 'medium'
                })
        
        # 按重要性分数排序
        single_points.sort(key=lambda x: x['importance_score'], reverse=True)
        
        return single_points[:20]  # 返回前20个
    
    def _find_critical_dependency_chains(self, G: nx.DiGraph) -> List[Dict]:
        """查找关键依赖链"""
        critical_chains = []
        
        # 找到所有根节点（入度为0）
        root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        for root in root_nodes:
            # 找到从根节点出发的最长路径
            try:
                # 获取从根节点可达的所有节点
                reachable_nodes = nx.descendants(G, root).union({root})
                subgraph = G.subgraph(reachable_nodes)
                
                # 找到最长路径
                longest_path = nx.dag_longest_path(subgraph)
                
                if len(longest_path) >= 3:  # 只考虑长度>=3的链
                    # 分析链的脆弱性
                    vulnerability_score = self._calculate_chain_vulnerability(G, longest_path)
                    
                    critical_chains.append({
                        'root': root,
                        'chain': longest_path,
                        'length': len(longest_path),
                        'vulnerability_score': vulnerability_score,
                        'risk_level': 'high' if vulnerability_score >= 0.7 else 'medium'
                    })
            except Exception:
                continue
        
        # 按长度和脆弱性排序
        critical_chains.sort(key=lambda x: (x['length'], x['vulnerability_score']), reverse=True)
        
        return critical_chains[:10]  # 返回前10个
    
    def _find_vulnerability_clusters(self, G: nx.DiGraph) -> List[Dict]:
        """查找漏洞集群"""
        clusters = []
        
        # 检测强连通分量（复杂的相互依赖）
        try:
            sccs = list(nx.strongly_connected_components(G))
            
            for scc in sccs:
                if len(scc) >= 3:  # 只考虑大小>=3的集群
                    subgraph = G.subgraph(scc)
                    
                    # 分析集群的脆弱性
                    vulnerability_metrics = self._analyze_cluster_vulnerability(subgraph)
                    
                    clusters.append({
                        'nodes': list(scc),
                        'size': len(scc),
                        'density': nx.density(subgraph),
                        'vulnerability_metrics': vulnerability_metrics,
                        'risk_level': 'high' if vulnerability_metrics.get('overall_risk', 0) >= 0.7 else 'medium'
                    })
        except Exception:
            pass
        
        # 按大小和风险排序
        clusters.sort(key=lambda x: (x['size'], x['vulnerability_metrics'].get('overall_risk', 0)), reverse=True)
        
        return clusters[:10]  # 返回前10个
    
    def _analyze_attack_surface(self, G: nx.DiGraph) -> Dict:
        """分析攻击面"""
        attack_surface = {
            'entry_points': [],
            'propagation_paths': [],
            'critical_assets': [],
            'attack_complexity': {}
        }
        
        # 1. 入口点分析（根节点）
        root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        for root in root_nodes[:10]:  # 只分析前10个根节点
            # 计算从该入口点可达的攻击面
            reachable = nx.descendants(G, root)
            
            attack_surface['entry_points'].append({
                'node': root,
                'reachable_nodes': len(reachable),
                'attack_surface_size': len(reachable) + 1  # 包括自身
            })
        
        # 2. 传播路径分析
        # 找到最长的传播路径
        try:
            longest_path = nx.dag_longest_path(G)
            if longest_path:
                attack_surface['propagation_paths'].append({
                    'path': longest_path,
                    'length': len(longest_path),
                    'propagation_risk': 'high' if len(longest_path) >= 5 else 'medium'
                })
        except Exception:
            pass
        
        # 3. 关键资产识别
        # 找出高入度节点（被很多节点依赖的关键资产）
        high_in_degree = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)[:10]
        
        for node, degree in high_in_degree:
            attack_surface['critical_assets'].append({
                'node': node,
                'in_degree': degree,
                'importance': 'critical' if degree >= 10 else 'high'
            })
        
        # 4. 攻击复杂度分析
        attack_surface['attack_complexity'] = {
            'graph_complexity': nx.density(G),
            'average_path_length': self._calculate_average_path_length(G),
            'defense_depth': self._calculate_defense_depth(G)
        }
        
        return attack_surface
    
    def _calculate_cyclomatic_complexity(self, G: nx.DiGraph) -> Dict:
        """计算圈复杂度"""
        complexity = {
            'graph_cyclomatic_complexity': 0,
            'node_complexities': {},
            'complexity_distribution': {}
        }
        
        try:
            # 图的圈复杂度: E - N + 2P
            # 其中 E=边数, N=节点数, P=连通分量数
            E = G.number_of_edges()
            N = G.number_of_nodes()
            
            # 计算弱连通分量数
            if nx.is_directed(G):
                components = list(nx.weakly_connected_components(G))
            else:
                components = list(nx.connected_components(G))
            
            P = len(components)
            
            graph_complexity = E - N + 2 * P
            complexity['graph_cyclomatic_complexity'] = graph_complexity
            
            # 节点复杂度（基于出度）
            node_complexities = {}
            for node in G.nodes():
                out_degree = G.out_degree(node)
                in_degree = G.in_degree(node)
                
                # 简单复杂度计算
                node_complexity = out_degree * 2 + in_degree
                node_complexities[node] = node_complexity
            
            complexity['node_complexities'] = dict(
                sorted(node_complexities.items(), key=lambda x: x[1], reverse=True)[:20]
            )
            
            # 复杂度分布
            complexity_values = list(node_complexities.values())
            if complexity_values:
                complexity['complexity_distribution'] = {
                    'max': max(complexity_values),
                    'min': min(complexity_values),
                    'mean': np.mean(complexity_values),
                    'median': np.median(complexity_values),
                    'std': np.std(complexity_values)
                }
            
            return complexity
            
        except Exception:
            return complexity
    
    def _calculate_cognitive_complexity(self, G: nx.DiGraph) -> Dict:
        """计算认知复杂度"""
        cognitive_complexity = {
            'overall_score': 0,
            'complexity_factors': [],
            'hotspots': []
        }
        
        # 认知复杂度因素
        factors = []
        
        # 1. 嵌套深度
        max_depth = self._calculate_max_nesting_depth(G)
        factors.append({
            'factor': '嵌套深度',
            'value': max_depth,
            'weight': 0.3,
            'impact': 'high' if max_depth > 5 else 'medium'
        })
        
        # 2. 分支数量（出度分布）
        out_degrees = [G.out_degree(n) for n in G.nodes()]
        avg_branches = np.mean(out_degrees) if out_degrees else 0
        
        factors.append({
            'factor': '平均分支数',
            'value': avg_branches,
            'weight': 0.2,
            'impact': 'high' if avg_branches > 3 else 'medium'
        })
        
        # 3. 循环依赖
        try:
            cycles = list(nx.simple_cycles(G))
            cycle_count = len(cycles)
            factors.append({
                'factor': '循环依赖',
                'value': cycle_count,
                'weight': 0.25,
                'impact': 'high' if cycle_count > 0 else 'low'
            })
        except:
            factors.append({
                'factor': '循环依赖',
                'value': 0,
                'weight': 0.25,
                'impact': 'low'
            })
        
        # 4. 模块间耦合
        coupling_score = self._calculate_coupling_score(G)
        factors.append({
            'factor': '耦合度',
            'value': coupling_score,
            'weight': 0.15,
            'impact': 'high' if coupling_score > 0.7 else 'medium'
        })
        
        # 5. 命名复杂性（简单启发式）
        naming_complexity = self._calculate_naming_complexity(G)
        factors.append({
            'factor': '命名复杂性',
            'value': naming_complexity,
            'weight': 0.1,
            'impact': 'medium'
        })
        
        # 计算总体认知复杂度分数
        overall_score = sum(factor['value'] * factor['weight'] for factor in factors)
        cognitive_complexity['overall_score'] = overall_score
        cognitive_complexity['complexity_factors'] = factors
        
        # 识别热点（高认知复杂度的节点）
        hotspots = []
        for node in G.nodes():
            # 简单热点识别
            node_score = G.out_degree(node) * 0.4 + G.in_degree(node) * 0.3
            
            # 如果节点在循环中，增加分数
            try:
                if any(node in cycle for cycle in nx.simple_cycles(G)):
                    node_score += 0.3
            except:
                pass
            
            if node_score >= 0.5:
                hotspots.append({
                    'node': node,
                    'score': node_score,
                    'out_degree': G.out_degree(node),
                    'in_degree': G.in_degree(node)
                })
        
        # 按分数排序
        hotspots.sort(key=lambda x: x['score'], reverse=True)
        cognitive_complexity['hotspots'] = hotspots[:10]
        
        return cognitive_complexity
    
    def _calculate_maintenance_complexity(self, G: nx.DiGraph) -> Dict:
        """计算维护复杂度"""
        maintenance_complexity = {
            'maintenance_score': 0,
            'risk_factors': [],
            'effort_estimation': {}
        }
        
        risk_factors = []
        
        # 1. 依赖数量
        total_dependencies = G.number_of_edges()
        risk_factors.append({
            'factor': '总依赖数',
            'value': total_dependencies,
            'risk': 'high' if total_dependencies > 1000 else 'medium' if total_dependencies > 500 else 'low'
        })
        
        # 2. 第三方依赖比例
        third_party_count = sum(1 for n in G.nodes() if not n.startswith('actions/'))
        third_party_ratio = third_party_count / G.number_of_nodes() if G.number_of_nodes() > 0 else 0
        
        risk_factors.append({
            'factor': '第三方依赖比例',
            'value': third_party_ratio,
            'risk': 'high' if third_party_ratio > 0.5 else 'medium' if third_party_ratio > 0.2 else 'low'
        })
        
        # 3. 深度复杂度
        max_depth = self._calculate_max_nesting_depth(G)
        risk_factors.append({
            'factor': '最大嵌套深度',
            'value': max_depth,
            'risk': 'high' if max_depth > 7 else 'medium' if max_depth > 3 else 'low'
        })
        
        # 4. 变更影响范围
        avg_impact = self._calculate_average_change_impact(G)
        risk_factors.append({
            'factor': '平均变更影响范围',
            'value': avg_impact,
            'risk': 'high' if avg_impact > 10 else 'medium' if avg_impact > 5 else 'low'
        })
        
        # 5. 文档完整性（模拟）
        documentation_score = 0.6  # 假设60%的文档完整性
        risk_factors.append({
            'factor': '文档完整性',
            'value': documentation_score,
            'risk': 'low' if documentation_score > 0.8 else 'medium' if documentation_score > 0.5 else 'high'
        })
        
        # 计算维护分数
        risk_weights = {'high': 3, 'medium': 2, 'low': 1}
        total_risk = sum(risk_weights[factor['risk']] for factor in risk_factors)
        max_possible_risk = len(risk_factors) * 3
        
        maintenance_score = 100 * (1 - total_risk / max_possible_risk)
        maintenance_complexity['maintenance_score'] = maintenance_score
        maintenance_complexity['risk_factors'] = risk_factors
        
        # 工作量估算
        maintenance_complexity['effort_estimation'] = {
            'routine_maintenance': f"{int(total_dependencies * 0.1)} 小时/月",
            'security_updates': f"{int(third_party_count * 2)} 小时/季度",
            'major_refactoring': f"{int(max_depth * 20)} 小时",
            'documentation': f"{int((1 - documentation_score) * 100)} 小时"
        }
        
        return maintenance_complexity
    
    def _analyze_coupling(self, G: nx.DiGraph) -> Dict:
        """分析耦合度"""
        coupling_analysis = {
            'afferent_coupling': {},  # 传入耦合
            'efferent_coupling': {},  # 传出耦合
            'instability_index': {},
            'abstractness_index': {}
        }
        
        # 传入耦合（有多少节点依赖此节点）
        afferent_coupling = {}
        for node in G.nodes():
            afferent_coupling[node] = G.in_degree(node)
        
        coupling_analysis['afferent_coupling'] = dict(
            sorted(afferent_coupling.items(), key=lambda x: x[1], reverse=True)[:20]
        )
        
        # 传出耦合（此节点依赖多少其他节点）
        efferent_coupling = {}
        for node in G.nodes():
            efferent_coupling[node] = G.out_degree(node)
        
        coupling_analysis['efferent_coupling'] = dict(
            sorted(efferent_coupling.items(), key=lambda x: x[1], reverse=True)[:20]
        )
        
        # 不稳定性指数: Ce / (Ce + Ca)
        instability_index = {}
        for node in G.nodes():
            Ce = efferent_coupling.get(node, 0)
            Ca = afferent_coupling.get(node, 0)
            if Ce + Ca > 0:
                instability = Ce / (Ce + Ca)
            else:
                instability = 0
            instability_index[node] = instability
        
        coupling_analysis['instability_index'] = dict(
            sorted(instability_index.items(), key=lambda x: x[1], reverse=True)[:20]
        )
        
        # 抽象性指数（模拟）
        abstractness_index = {}
        for node in G.nodes():
            # 简单启发式：名称中包含"abstract"、"base"、"interface"等
            abstract_keywords = ['abstract', 'base', 'interface', 'common', 'util']
            is_abstract = any(keyword in node.lower() for keyword in abstract_keywords)
            abstractness_index[node] = 0.8 if is_abstract else 0.2
        
        coupling_analysis['abstractness_index'] = abstractness_index
        
        return coupling_analysis
    
    def _analyze_cohesion(self, G: nx.DiGraph) -> Dict:
        """分析内聚度"""
        cohesion_analysis = {
            'modularity_score': 0,
            'community_structure': {},
            'cohesion_metrics': {}
        }
        
        try:
            # 转换为无向图用于社区检测
            G_undirected = G.to_undirected()
            
            # 使用 Louvain 算法计算模块度
            import community as community_louvain
            partition = community_louvain.best_partition(G_undirected)
            modularity = community_louvain.modularity(partition, G_undirected)
            
            cohesion_analysis['modularity_score'] = modularity
            
            # 分析社区结构
            communities = defaultdict(list)
            for node, comm_id in partition.items():
                communities[comm_id].append(node)
            
            community_stats = []
            for comm_id, nodes in communities.items():
                # 计算社区内连接密度
                subgraph = G_undirected.subgraph(nodes)
                intra_edges = subgraph.number_of_edges()
                possible_intra_edges = len(nodes) * (len(nodes) - 1) / 2
                
                community_stats.append({
                    'community_id': comm_id,
                    'size': len(nodes),
                    'density': intra_edges / possible_intra_edges if possible_intra_edges > 0 else 0,
                    'cohesion_score': intra_edges / len(nodes) if len(nodes) > 0 else 0
                })
            
            cohesion_analysis['community_structure'] = {
                'num_communities': len(communities),
                'communities': community_stats[:10]  # 只显示前10个社区
            }
            
            # 内聚度指标
            cohesion_metrics = {
                'average_clustering': nx.average_clustering(G_undirected),
                'global_efficiency': nx.global_efficiency(G_undirected),
                'local_efficiency': nx.local_efficiency(G_undirected)
            }
            
            cohesion_analysis['cohesion_metrics'] = cohesion_metrics
            
        except Exception as e:
            self.logger.warning(f"内聚度分析失败: {e}")
        
        return cohesion_analysis
    
    def _is_node_on_critical_path(self, G: nx.DiGraph, node: str) -> bool:
        """检查节点是否在关键路径上"""
        try:
            # 找到所有最长路径
            longest_paths = []
            max_length = 0
            
            # 找到所有根节点
            root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
            
            for root in root_nodes:
                # 获取从根节点可达的所有节点
                reachable = nx.descendants(G, root).union({root})
                subgraph = G.subgraph(reachable)
                
                try:
                    path = nx.dag_longest_path(subgraph)
                    if len(path) > max_length:
                        max_length = len(path)
                        longest_paths = [path]
                    elif len(path) == max_length:
                        longest_paths.append(path)
                except:
                    continue
            
            # 检查节点是否在任何最长路径上
            for path in longest_paths:
                if node in path:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _calculate_chain_vulnerability(self, G: nx.DiGraph, chain: List[str]) -> float:
        """计算链的脆弱性分数"""
        if len(chain) < 2:
            return 0.0
        
        vulnerability_factors = []
        
        # 1. 链长度因子
        length_factor = min(1.0, len(chain) / 10.0)
        vulnerability_factors.append(length_factor * 0.3)
        
        # 2. 第三方依赖比例
        third_party_count = sum(1 for node in chain if not node.startswith('actions/'))
        third_party_factor = third_party_count / len(chain)
        vulnerability_factors.append(third_party_factor * 0.4)
        
        # 3. 节点重要性因子（基于入度）
        importance_sum = sum(G.in_degree(node) for node in chain)
        max_possible_importance = len(chain) * 10  # 假设最大入度为10
        importance_factor = min(1.0, importance_sum / max_possible_importance)
        vulnerability_factors.append(importance_factor * 0.3)
        
        return sum(vulnerability_factors)
    
    def _analyze_cluster_vulnerability(self, subgraph: nx.DiGraph) -> Dict:
        """分析集群脆弱性"""
        vulnerability_metrics = {
            'size_risk': 0,
            'density_risk': 0,
            'coupling_risk': 0,
            'overall_risk': 0
        }
        
        try:
            # 1. 大小风险
            size = subgraph.number_of_nodes()
            vulnerability_metrics['size_risk'] = min(1.0, size / 20.0)
            
            # 2. 密度风险
            density = nx.density(subgraph)
            vulnerability_metrics['density_risk'] = density
            
            # 3. 耦合风险（基于外部依赖）
            # 计算集群节点与外部节点的连接
            # 这里简化处理
            vulnerability_metrics['coupling_risk'] = density * 0.5
            
            # 4. 总体风险
            vulnerability_metrics['overall_risk'] = (
                vulnerability_metrics['size_risk'] * 0.3 +
                vulnerability_metrics['density_risk'] * 0.4 +
                vulnerability_metrics['coupling_risk'] * 0.3
            )
            
        except Exception:
            pass
        
        return vulnerability_metrics
    
    def _calculate_max_nesting_depth(self, G: nx.DiGraph) -> int:
        """计算最大嵌套深度"""
        max_depth = 0
        
        # 找到所有根节点
        root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
        
        for root in root_nodes:
            # BFS 计算深度
            depths = {root: 0}
            queue = deque([root])
            
            while queue:
                node = queue.popleft()
                current_depth = depths[node]
                max_depth = max(max_depth, current_depth)
                
                for successor in G.successors(node):
                    if successor not in depths:
                        depths[successor] = current_depth + 1
                        queue.append(successor)
        
        return max_depth
    
    def _calculate_coupling_score(self, G: nx.DiGraph) -> float:
        """计算耦合度分数"""
        try:
            # 平均度作为耦合度的简单指标
            degrees = [d for _, d in G.degree()]
            if degrees:
                avg_degree = np.mean(degrees)
                # 归一化到0-1范围
                return min(1.0, avg_degree / 10.0)
        except:
            pass
        
        return 0.0
    
    def _calculate_naming_complexity(self, G: nx.DiGraph) -> float:
        """计算命名复杂性"""
        # 简单启发式：名称长度和特殊字符
        complexity_scores = []
        
        for node in G.nodes():
            name = str(node)
            score = 0
            
            # 长度因子
            if len(name) > 30:
                score += 0.3
            elif len(name) > 20:
                score += 0.2
            elif len(name) > 10:
                score += 0.1
            
            # 特殊字符因子
            special_chars = sum(1 for c in name if not c.isalnum() and c not in ['/', '-', '_'])
            if special_chars > 2:
                score += 0.3
            elif special_chars > 0:
                score += 0.1
            
            complexity_scores.append(min(1.0, score))
        
        return np.mean(complexity_scores) if complexity_scores else 0.0
    
    def _calculate_average_change_impact(self, G: nx.DiGraph) -> float:
        """计算平均变更影响范围"""
        impact_sizes = []
        
        for node in G.nodes()[:20]:  # 采样计算
            # 计算变更此节点会影响多少下游节点
            reachable = nx.descendants(G, node)
            impact_sizes.append(len(reachable))
        
        return np.mean(impact_sizes) if impact_sizes else 0.0
    
    def _calculate_average_path_length(self, G: nx.DiGraph) -> float:
        """计算平均路径长度"""
        try:
            if nx.is_weakly_connected(G):
                return nx.average_shortest_path_length(G)
        except:
            pass
        
        return 0.0
    
    def _calculate_defense_depth(self, G: nx.DiGraph) -> int:
        """计算防御深度"""
        return self._calculate_max_nesting_depth(G)
    
    def _generate_vulnerability_summary(self, vulnerabilities: Dict) -> Dict:
        """生成漏洞摘要"""
        summary = {
            'total_single_points': len(vulnerabilities.get('single_points_of_failure', [])),
            'total_critical_chains': len(vulnerabilities.get('critical_dependency_chains', [])),
            'total_vulnerability_clusters': len(vulnerabilities.get('vulnerability_clusters', [])),
            'overall_risk_level': 'medium',
            'recommended_actions': []
        }
        
        # 确定总体风险级别
        high_risk_count = 0
        for point in vulnerabilities.get('single_points_of_failure', []):
            if point.get('risk_level') == 'high':
                high_risk_count += 1
        
        for chain in vulnerabilities.get('critical_dependency_chains', []):
            if chain.get('risk_level') == 'high':
                high_risk_count += 1
        
        for cluster in vulnerabilities.get('vulnerability_clusters', []):
            if cluster.get('risk_level') == 'high':
                high_risk_count += 1
        
        if high_risk_count >= 5:
            summary['overall_risk_level'] = 'critical'
        elif high_risk_count >= 2:
            summary['overall_risk_level'] = 'high'
        elif high_risk_count >= 1:
            summary['overall_risk_level'] = 'medium'
        else:
            summary['overall_risk_level'] = 'low'
        
        # 生成建议行动
        if summary['overall_risk_level'] in ['critical', 'high']:
            summary['recommended_actions'] = [
                '立即审查高风险单点故障',
                '优化关键依赖链',
                '考虑分解复杂的依赖集群',
                '实施额外的监控和告警'
            ]
        else:
            summary['recommended_actions'] = [
                '定期审查依赖关系',
                '监控依赖变化',
                '建立依赖健康检查流程'
            ]
        
        return summary
    
    def _analyze_dependency_growth(self) -> Dict:
        """分析依赖增长"""
        # 模拟数据
        return {
            'growth_rate': 0.15,  # 每月15%增长
            'new_dependencies_per_month': 45,
            'deprecated_dependencies_per_month': 12,
            'trend': 'increasing',
            'forecast': {
                'next_3_months': '持续增长，预计新增150个依赖',
                'next_6_months': '增长可能放缓，预计新增250个依赖',
                'next_12_months': '趋于稳定，预计新增400个依赖'
            }
        }
    
    def _analyze_stability(self) -> Dict:
        """分析稳定性"""
        return {
            'change_frequency': {
                'high_churn': ['actions/checkout', 'docker/login-action'],  # 高频变更
                'stable': ['actions/setup-node', 'actions/setup-python'],  # 稳定
                'deprecated': []  # 已废弃
            },
            'breaking_changes': {
                'count_last_year': 8,
                'most_affected': ['azure/login', 'aws-actions/configure-aws-credentials'],
                'mitigation': '使用语义化版本和定期测试'
            },
            'version_pinning_status': {
                'pinned': 65,  # 65%已固定
                'unpinned': 35,  # 35%未固定
                'improvement_target': '达到90%固定率'
            }
        }
    
    def _analyze_technical_debt(self) -> Dict:
        """分析技术债务"""
        return {
            'debt_categories': [
                {
                    'category': '安全债务',
                    'debt_amount': '高',
                    'issues': ['未固定版本', '过宽权限', '硬编码秘密'],
                    'remediation_cost': '中',
                    'business_risk': '高'
                },
                {
                    'category': '维护债务',
                    'debt_amount': '中',
                    'issues': ['复杂依赖链', '循环依赖', '文档缺失'],
                    'remediation_cost': '高',
                    'business_risk': '中'
                },
                {
                    'category': '架构债务',
                    'debt_amount': '低',
                    'issues': ['模块化不足', '耦合度高'],
                    'remediation_cost': '高',
                    'business_risk': '低'
                }
            ],
            'total_debt_score': 7.2,  # 10分制
            'repayment_priority': ['安全债务', '维护债务', '架构债务'],
            'repayment_plan': {
                'short_term': '修复高危安全债务（3个月）',
                'medium_term': '优化维护债务（6个月）',
                'long_term': '重构架构债务（12个月）'
            }
        }
    
    def _identify_refactoring_opportunities(self) -> List[Dict]:
        """识别重构机会"""
        return [
            {
                'opportunity': '提取公共依赖为共享 action',
                'benefit': '减少重复，提高一致性',
                'effort': '中',
                'impact': '高',
                'examples': ['多个 workflow 使用相同的配置步骤']
            },
            {
                'opportunity': '分解复杂 action 为小型可组合 action',
                'benefit': '提高可维护性和复用性',
                'effort': '高',
                'impact': '中',
                'examples': ['单个 action 包含多个不相关的功能']
            },
            {
                'opportunity': '替换废弃或维护不良的依赖',
                'benefit': '减少安全风险和技术债务',
                'effort': '低到中',
                'impact': '高',
                'examples': ['使用官方替代品替换第三方 action']
            },
            {
                'opportunity': '实施依赖注入模式',
                'benefit': '提高可测试性和灵活性',
                'effort': '高',
                'impact': '中',
                'examples': ['硬编码配置和参数']
            }
        ]
    
    def _analyze_evolution_trends(self) -> Dict:
        """分析演化趋势"""
        return {
            'emerging_trends': [
                'OIDC 认证替代长期凭证',
                '可重用 workflow 的普及',
                '安全扫描的集成',
                '策略即代码的实施'
            ],
            'declining_trends': [
                '硬编码 secrets',
                '未固定版本',
                '过宽权限配置',
                '手动部署流程'
            ],
            'predicted_changes': [
                '更多的安全自动化',
                '增强的供应链安全',
                'AI 辅助的安全分析',
                '实时威胁检测'
            ],
            'recommended_adaptations': [
                '投资自动化安全工具',
                '培训团队安全最佳实践',
                '建立安全文化',
                '持续监控和优化'
            ]
        }
    
    def _analyze_direct_impact(self, G: nx.DiGraph, target: str) -> Dict:
        """分析直接影响"""
        direct_impact = {
            'immediate_dependents': [],
            'immediate_dependencies': [],
            'impact_score': 0
        }
        
        # 直接影响的下游节点
        successors = list(G.successors(target))
        direct_impact['immediate_dependents'] = [
            {
                'node': node,
                'relationship': 'depends_on',
                'risk': 'direct'
            }
            for node in successors
        ]
        
        # 直接影响的依赖节点
        predecessors = list(G.predecessors(target))
        direct_impact['immediate_dependencies'] = [
            {
                'node': node,
                'relationship': 'required_by',
                'risk': 'indirect'
            }
            for node in predecessors
        ]
        
        # 计算影响分数
        impact_score = len(successors) * 0.6 + len(predecessors) * 0.4
        direct_impact['impact_score'] = impact_score
        
        return direct_impact
    
    def _analyze_indirect_impact(self, G: nx.DiGraph, target: str) -> Dict:
        """分析间接影响"""
        indirect_impact = {
            'transitive_dependents': [],
            'transitive_dependencies': [],
            'impact_radius': 0,
            'impact_score': 0
        }
        
        try:
            # 传递影响的下游节点
            transitive_successors = nx.descendants(G, target)
            indirect_impact['transitive_dependents'] = list(transitive_successors)[:50]  # 限制数量
            
            # 传递影响的依赖节点
            transitive_predecessors = nx.ancestors(G, target)
            indirect_impact['transitive_dependencies'] = list(transitive_predecessors)[:50]
            
            # 计算影响半径
            impact_radius = len(transitive_successors) + len(transitive_predecessors)
            indirect_impact['impact_radius'] = impact_radius
            
            # 计算影响分数
            impact_score = min(100, impact_radius * 0.1)
            indirect_impact['impact_score'] = impact_score
            
        except Exception:
            pass
        
        return indirect_impact
    
    def _analyze_risk_propagation(self, G: nx.DiGraph, target: str) -> Dict:
        """分析风险传播"""
        risk_propagation = {
            'propagation_paths': [],
            'critical_assets_at_risk': [],
            'propagation_speed': 0,
            'containment_strategies': []
        }
        
        try:
            # 找到从目标出发的传播路径
            successors = list(G.successors(target))
            
            for successor in successors[:10]:  # 只分析前10个
                # 找到从后继节点出发的路径
                try:
                    path = nx.shortest_path(G, target, successor)
                    risk_propagation['propagation_paths'].append({
                        'path': path,
                        'length': len(path),
                        'risk': 'high' if len(path) <= 3 else 'medium'
                    })
                except:
                    pass
            
            # 识别处于风险的关键资产
            transitive_successors = nx.descendants(G, target)
            
            for node in transitive_successors:
                in_degree = G.in_degree(node)
                if in_degree >= 5:  # 高入度节点是关键资产
                    risk_propagation['critical_assets_at_risk'].append({
                        'node': node,
                        'in_degree': in_degree,
                        'distance': nx.shortest_path_length(G, target, node)
                    })
            
            # 计算传播速度（基于平均路径长度）
            if transitive_successors:
                avg_distance = np.mean([
                    nx.shortest_path_length(G, target, node)
                    for node in list(transitive_successors)[:20]  # 采样
                    if nx.has_path(G, target, node)
                ])
                risk_propagation['propagation_speed'] = 1.0 / avg_distance if avg_distance > 0 else 0
            
            # 生成遏制策略
            risk_propagation['containment_strategies'] = [
                '在关键路径上设置监控点',
                '实施依赖隔离',
                '建立快速响应机制',
                '准备回滚计划'
            ]
            
        except Exception:
            pass
        
        return risk_propagation
    
    def _generate_mitigation_strategies(self, G: nx.DiGraph, target: str, 
                                       impact_analysis: Dict) -> List[Dict]:
        """生成缓解策略"""
        strategies = []
        
        direct_impact = impact_analysis.get('direct_impact', {})
        indirect_impact = impact_analysis.get('indirect_impact', {})
        
        # 1. 隔离策略
        strategies.append({
            'strategy': '依赖隔离',
            'description': '将目标 action 隔离到独立的环境中执行',
            'implementation': '使用专门的 runner 或容器',
            'effectiveness': '高',
            'cost': '中'
        })
        
        # 2. 监控策略
        strategies.append({
            'strategy': '增强监控',
            'description': '加强对目标 action 及其依赖的监控',
            'implementation': '设置执行监控、异常检测和告警',
            'effectiveness': '中',
            'cost': '低'
        })
        
        # 3. 替代策略
        strategies.append({
            'strategy': '寻找替代方案',
            'description': '评估并迁移到更安全的替代 action',
            'implementation': '进行替代方案评估和迁移计划',
            'effectiveness': '高',
            'cost': '高'
        })
        
        # 4. 加固策略
        strategies.append({
            'strategy': '安全加固',
            'description': '对目标 action 进行安全加固',
            'implementation': '实施沙箱执行、权限限制、输入验证',
            'effectiveness': '中',
            'cost': '中'
        })
        
        # 基于影响分析添加特定策略
        if direct_impact.get('impact_score', 0) > 5:
            strategies.append({
                'strategy': '依赖重构',
                'description': '重构直接依赖关系，减少耦合',
                'implementation': '分析并优化直接依赖结构',
                'effectiveness': '中',
                'cost': '高'
            })
        
        if indirect_impact.get('impact_radius', 0) > 20:
            strategies.append({
                'strategy': '影响限制',
                'description': '限制间接影响的传播范围',
                'implementation': '设置依赖边界和隔离层',
                'effectiveness': '高',
                'cost': '高'
            })
        
        return strategies
    
    def _calculate_overall_health_score(self, vulnerability_analysis: Dict, 
                                       complexity_analysis: Dict) -> float:
        """计算总体健康评分"""
        # 简单加权计算
        scores = []
        weights = []
        
        # 从漏洞分析中提取分数
        if vulnerability_analysis:
            summary = vulnerability_analysis.get('summary', {})
            risk_level = summary.get('overall_risk_level', 'medium')
            
            risk_scores = {'critical': 20, 'high': 40, 'medium': 60, 'low': 80}
            scores.append(risk_scores.get(risk_level, 60))
            weights.append(0.4)
        
        # 从复杂度分析中提取分数
        if complexity_analysis:
            # 维护复杂度分数
            maintenance = complexity_analysis.get('maintenance_complexity', {})
            maintenance_score = maintenance.get('maintenance_score', 50)
            scores.append(maintenance_score)
            weights.append(0.3)
            
            # 认知复杂度分数
            cognitive = complexity_analysis.get('cognitive_complexity', {})
            cognitive_score = 100 - cognitive.get('overall_score', 0) * 20  # 转换为百分制
            scores.append(cognitive_score)
            weights.append(0.3)
        
        # 计算加权平均
        if scores and weights:
            total_weight = sum(weights)
            weighted_sum = sum(s * w for s, w in zip(scores, weights))
            return weighted_sum / total_weight
        
        return 50.0  # 默认分数
    
    def _calculate_component_scores(self, vulnerability_analysis: Dict, 
                                   complexity_analysis: Dict) -> Dict:
        """计算组件评分"""
        component_scores = {
            'security_score': 70,
            'maintainability_score': 65,
            'reliability_score': 75,
            'performance_score': 80
        }
        
        # 基于分析数据调整分数
        if vulnerability_analysis:
            summary = vulnerability_analysis.get('summary', {})
            risk_level = summary.get('overall_risk_level', 'medium')
            
            risk_adjustments = {'critical': -30, 'high': -20, 'medium': -10, 'low': 0}
            adjustment = risk_adjustments.get(risk_level, 0)
            component_scores['security_score'] = max(0, component_scores['security_score'] + adjustment)
        
        if complexity_analysis:
            maintenance = complexity_analysis.get('maintenance_complexity', {})
            maintenance_score = maintenance.get('maintenance_score', 50)
            component_scores['maintainability_score'] = maintenance_score
            
            cognitive = complexity_analysis.get('cognitive_complexity', {})
            cognitive_score = 100 - cognitive.get('overall_score', 0) * 20
            component_scores['reliability_score'] = cognitive_score
        
        return component_scores
    
    def _identify_risk_factors(self, vulnerability_analysis: Dict, 
                              complexity_analysis: Dict) -> List[Dict]:
        """识别风险因素"""
        risk_factors = []
        
        # 从漏洞分析中提取风险因素
        if vulnerability_analysis:
            single_points = vulnerability_analysis.get('single_points_of_failure', [])
            for point in single_points[:5]:  # 前5个单点故障
                if point.get('risk_level') in ['high', 'critical']:
                    risk_factors.append({
                        'factor': f"单点故障: {point['node']}",
                        'risk': point['risk_level'],
                        'impact': '高',
                        'mitigation': '实施冗余或寻找替代方案'
                    })
            
            critical_chains = vulnerability_analysis.get('critical_dependency_chains', [])
            for chain in critical_chains[:3]:  # 前3个关键链
                if chain.get('risk_level') in ['high', 'critical']:
                    risk_factors.append({
                        'factor': f"关键依赖链 (长度: {chain['length']})",
                        'risk': chain['risk_level'],
                        'impact': '中到高',
                        'mitigation': '优化依赖结构，减少链长度'
                    })
        
        # 从复杂度分析中提取风险因素
        if complexity_analysis:
            cognitive = complexity_analysis.get('cognitive_complexity', {})
            hotspots = cognitive.get('hotspots', [])
            for hotspot in hotspots[:3]:  # 前3个热点
                risk_factors.append({
                    'factor': f"认知复杂度热点: {hotspot['node']}",
                    'risk': 'medium',
                    'impact': '中',
                    'mitigation': '重构简化，提高可理解性'
                })
        
        return risk_factors
    
    def _identify_improvement_areas(self, vulnerability_analysis: Dict, 
                                   complexity_analysis: Dict) -> List[Dict]:
        """识别改进领域"""
        improvement_areas = []
        
        # 安全改进
        improvement_areas.append({
            'area': '供应链安全',
            'current_state': '中等',
            'target_state': '良好',
            'actions': [
                '增加依赖审查频率',
                '实施自动安全扫描',
                '建立安全更新流程'
            ],
            'priority': '高'
        })
        
        # 维护性改进
        improvement_areas.append({
            'area': '依赖可维护性',
            'current_state': '需要改进',
            'target_state': '良好',
            'actions': [
                '减少复杂依赖链',
                '优化模块结构',
                '完善文档'
            ],
            'priority': '中'
        })
        
        # 监控改进
        improvement_areas.append({
            'area': '安全监控',
            'current_state': '基础',
            'target_state': '高级',
            'actions': [
                '实施实时异常检测',
                '建立安全仪表板',
                '自动化告警和响应'
            ],
            'priority': '中'
        })
        
        return improvement_areas
    
    def _analyze_health_trend(self) -> Dict:
        """分析健康趋势"""
        return {
            'trend': 'improving',
            'velocity': 0.1,  # 每月改善10%
            'confidence': 0.8,
            'forecast': {
                'next_month': '继续改善，预计分数提高5%',
                'next_quarter': '稳定改善，预计分数提高15%',
                'next_year': '达到良好状态，预计分数达到80+'
            },
            'risks': [
                '新的依赖引入可能降低分数',
                '安全事件可能突然降低分数',
                '团队变动可能影响维护质量'
            ]
        }
    
    def _save_vulnerability_analysis(self, vulnerabilities: Dict):
        """保存漏洞分析"""
        output_file = self.processed_data_path / "vulnerability_analysis.json"
        save_json(vulnerabilities, str(output_file))
    
    def _save_complexity_analysis(self, complexity: Dict):
        """保存复杂度分析"""
        output_file = self.processed_data_path / "complexity_analysis.json"
        save_json(complexity, str(output_file))
    
    def _save_evolution_analysis(self, evolution: Dict):
        """保存演化分析"""
        output_file = self.processed_data_path / "evolution_analysis.json"
        save_json(evolution, str(output_file))
    
    def _save_impact_analysis(self, target: str, impact: Dict):
        """保存影响分析"""
        safe_target = target.replace('/', '_').replace('@', '_')
        output_file = self.processed_data_path / f"impact_analysis_{safe_target}.json"
        save_json(impact, str(output_file))
    
    def _save_health_scores(self, health_scores: Dict):
        """保存健康评分"""
        output_file = self.processed_data_path / "dependency_health_scores.json"
        save_json(health_scores, str(output_file))