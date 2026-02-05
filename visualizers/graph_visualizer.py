 # 依赖图可视化（matplotlib, plotly, Gephi 导出等）
# visualizers/graph_visualizer.py
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from utils.file_utils import load_json, ensure_dir

class GraphVisualizer:
    """图可视化器 - 可视化依赖关系图"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 可视化配置
        self.max_nodes_display = config['analysis']['visualization']['max_nodes_display']
        self.color_scheme = config['analysis']['visualization']['color_scheme']
        
        # 路径
        self.graphs_path = Path(config['paths']['graphs'])
        self.processed_data_path = Path(config['paths']['processed_data'])
        
        # 创建输出目录
        self.output_dir = Path("output/visualizations")
        ensure_dir(self.output_dir)
        
    def visualize_repo_action_graph(self, interactive: bool = True) -> Optional[str]:
        """可视化仓库-action 依赖图"""
        self.logger.info("可视化仓库-action 依赖图...")
        
        try:
            # 加载图数据
            graph_file = self.graphs_path / "repo_action_graph.gml"
            if not graph_file.exists():
                self.logger.error(f"图文件不存在: {graph_file}")
                return None
            
            G = nx.read_gml(str(graph_file))
            
            # 如果图太大，进行采样
            if G.number_of_nodes() > self.max_nodes_display:
                G = self._sample_large_graph(G)
            
            if interactive:
                # 创建交互式可视化
                fig = self._create_interactive_graph(G, "仓库-Action 依赖图")
                
                # 保存为 HTML
                output_file = self.output_dir / "repo_action_graph.html"
                fig.write_html(str(output_file))
                
                self.logger.info(f"交互式图已保存到: {output_file}")
                return str(output_file)
            else:
                # 创建静态可视化
                fig = self._create_static_graph(G, "仓库-Action 依赖图")
                
                # 保存为图片
                output_file = self.output_dir / "repo_action_graph.png"
                fig.savefig(str(output_file), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
                self.logger.info(f"静态图已保存到: {output_file}")
                return str(output_file)
                
        except Exception as e:
            self.logger.error(f"可视化仓库-action 图失败: {e}")
            return None
    
    def visualize_action_dependency_graph(self, interactive: bool = True) -> Optional[str]:
        """可视化 action-action 依赖图"""
        self.logger.info("可视化 action-action 依赖图...")
        
        try:
            # 加载图数据
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if not graph_file.exists():
                self.logger.error(f"图文件不存在: {graph_file}")
                return None
            
            G = nx.read_gml(str(graph_file))
            
            # 如果图太大，进行采样
            if G.number_of_nodes() > self.max_nodes_display:
                G = self._sample_large_graph(G, sample_type='important')
            
            if interactive:
                # 创建交互式可视化
                fig = self._create_interactive_graph(G, "Action 依赖图", 
                                                     node_size_attr='pagerank',
                                                     node_color_attr='type')
                
                # 保存为 HTML
                output_file = self.output_dir / "action_dependency_graph.html"
                fig.write_html(str(output_file))
                
                self.logger.info(f"交互式图已保存到: {output_file}")
                return str(output_file)
            else:
                # 创建静态可视化
                fig = self._create_static_graph(G, "Action 依赖图", 
                                                node_size='pagerank',
                                                node_color='type')
                
                # 保存为图片
                output_file = self.output_dir / "action_dependency_graph.png"
                fig.savefig(str(output_file), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
                self.logger.info(f"静态图已保存到: {output_file}")
                return str(output_file)
                
        except Exception as e:
            self.logger.error(f"可视化 action-action 图失败: {e}")
            return None
    
    def visualize_combined_graph(self, interactive: bool = True) -> Optional[str]:
        """可视化组合依赖图"""
        self.logger.info("可视化组合依赖图...")
        
        try:
            # 加载图数据
            graph_file = self.graphs_path / "combined_dependency_graph.gml"
            if not graph_file.exists():
                self.logger.error(f"图文件不存在: {graph_file}")
                return None
            
            G = nx.read_gml(str(graph_file))
            
            # 采样大型图
            if G.number_of_nodes() > self.max_nodes_display:
                G = self._sample_large_graph(G, sample_type='mixed')
            
            if interactive:
                # 创建交互式可视化
                fig = self._create_interactive_graph(G, "组合依赖图", 
                                                     node_size_attr='degree',
                                                     node_color_attr='type')
                
                # 保存为 HTML
                output_file = self.output_dir / "combined_dependency_graph.html"
                fig.write_html(str(output_file))
                
                self.logger.info(f"交互式图已保存到: {output_file}")
                return str(output_file)
            else:
                # 创建静态可视化
                fig = self._create_static_graph(G, "组合依赖图", 
                                                node_size='degree',
                                                node_color='type')
                
                # 保存为图片
                output_file = self.output_dir / "combined_dependency_graph.png"
                fig.savefig(str(output_file), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
                self.logger.info(f"静态图已保存到: {output_file}")
                return str(output_file)
                
        except Exception as e:
            self.logger.error(f"可视化组合图失败: {e}")
            return None
    
    def visualize_degree_distribution(self) -> List[str]:
        """可视化度分布"""
        self.logger.info("可视化度分布...")
        
        output_files = []
        
        try:
            # 加载图数据
            graph_files = {
                'repo_action': self.graphs_path / "repo_action_graph.gml",
                'action_dependency': self.graphs_path / "action_dependency_graph.gml",
                'combined': self.graphs_path / "combined_dependency_graph.gml"
            }
            
            for graph_name, graph_file in graph_files.items():
                if not graph_file.exists():
                    continue
                
                G = nx.read_gml(str(graph_file))
                
                # 计算度分布
                degrees = [d for _, d in G.degree()]
                
                if not degrees:
                    continue
                
                # 创建直方图
                fig, axes = plt.subplots(1, 2, figsize=(14, 6))
                
                # 度直方图
                axes[0].hist(degrees, bins=30, edgecolor='black', alpha=0.7)
                axes[0].set_xlabel('度')
                axes[0].set_ylabel('频率')
                axes[0].set_title(f'{graph_name} - 度分布直方图')
                axes[0].grid(True, alpha=0.3)
                
                # 度对数分布
                axes[1].hist(np.log10(np.array(degrees) + 1), bins=30, 
                            edgecolor='black', alpha=0.7)
                axes[1].set_xlabel('log10(度+1)')
                axes[1].set_ylabel('频率')
                axes[1].set_title(f'{graph_name} - 对数度分布')
                axes[1].grid(True, alpha=0.3)
                
                plt.tight_layout()
                
                # 保存图片
                output_file = self.output_dir / f"{graph_name}_degree_distribution.png"
                fig.savefig(str(output_file), dpi=300, bbox_inches='tight')
                plt.close(fig)
                
                output_files.append(str(output_file))
                self.logger.debug(f"度分布图已保存: {output_file}")
            
            return output_files
            
        except Exception as e:
            self.logger.error(f"可视化度分布失败: {e}")
            return output_files
    
    def visualize_centrality_metrics(self) -> List[str]:
        """可视化中心性指标"""
        self.logger.info("可视化中心性指标...")
        
        output_files = []
        
        try:
            # 加载图数据
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if not graph_file.exists():
                return output_files
            
            G = nx.read_gml(str(graph_file))
            
            # 计算各种中心性指标
            centrality_measures = {
                '度中心性': nx.degree_centrality(G),
                '接近中心性': nx.closeness_centrality(G) if nx.is_weakly_connected(G) else {},
                '中介中心性': nx.betweenness_centrality(G, k=min(100, G.number_of_nodes())),
                'PageRank': nx.pagerank(G)
            }
            
            # 创建子图
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=list(centrality_measures.keys()),
                vertical_spacing=0.15,
                horizontal_spacing=0.1
            )
            
            for idx, (measure_name, centrality) in enumerate(centrality_measures.items()):
                if not centrality:
                    continue
                
                row = idx // 2 + 1
                col = idx % 2 + 1
                
                # 获取前20个节点
                top_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:20]
                nodes = [node for node, _ in top_nodes]
                values = [value for _, value in top_nodes]
                
                # 创建条形图
                trace = go.Bar(
                    x=nodes,
                    y=values,
                    name=measure_name,
                    marker_color=px.colors.qualitative.Set2[idx]
                )
                
                fig.add_trace(trace, row=row, col=col)
                
                # 更新坐标轴
                fig.update_xaxes(tickangle=45, row=row, col=col)
                fig.update_yaxes(title_text='中心性值', row=row, col=col)
            
            fig.update_layout(
                title_text='Action 依赖图中心性指标',
                height=800,
                showlegend=False
            )
            
            # 保存为 HTML
            output_file = self.output_dir / "centrality_metrics.html"
            fig.write_html(str(output_file))
            output_files.append(str(output_file))
            
            # 同时保存为图片
            img_file = self.output_dir / "centrality_metrics.png"
            fig.write_image(str(img_file))
            output_files.append(str(img_file))
            
            self.logger.info(f"中心性指标可视化已保存")
            
            return output_files
            
        except Exception as e:
            self.logger.error(f"可视化中心性指标失败: {e}")
            return output_files
    
    def visualize_community_structure(self) -> Optional[str]:
        """可视化社区结构"""
        self.logger.info("可视化社区结构...")
        
        try:
            # 加载社区检测结果
            community_file = self.processed_data_path / "community_detection.json"
            if not community_file.exists():
                self.logger.error(f"社区检测文件不存在: {community_file}")
                return None
            
            community_data = load_json(str(community_file))
            if not community_data:
                return None
            
            # 加载图数据
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if not graph_file.exists():
                return None
            
            G = nx.read_gml(str(graph_file))
            
            # 获取分区信息
            partition = community_data.get('partition', {})
            if not partition:
                return None
            
            # 为每个节点分配社区颜色
            community_colors = {}
            unique_communities = set(partition.values())
            colors = px.colors.qualitative.Plotly
            
            for i, comm in enumerate(unique_communities):
                community_colors[comm] = colors[i % len(colors)]
            
            node_colors = [community_colors.get(partition.get(node, 0), 'gray') 
                          for node in G.nodes()]
            
            # 创建交互式图
            fig = self._create_interactive_graph(
                G, 
                "社区结构检测",
                node_color=node_colors,
                show_labels=True
            )
            
            # 添加图例
            legend_traces = []
            for comm, color in list(community_colors.items())[:10]:  # 只显示前10个社区
                legend_traces.append(go.Scatter(
                    x=[None], y=[None],
                    mode='markers',
                    marker=dict(size=10, color=color),
                    name=f'社区 {comm}'
                ))
            
            # 更新布局
            fig.update_layout(
                title=f'社区结构检测 (模块度: {community_data.get("modularity", 0):.3f})',
                showlegend=True
            )
            
            # 保存为 HTML
            output_file = self.output_dir / "community_structure.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"社区结构可视化已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"可视化社区结构失败: {e}")
            return None
    
    def create_dashboard(self) -> Optional[str]:
        """创建综合仪表板"""
        self.logger.info("创建综合仪表板...")
        
        try:
            # 创建仪表板
            fig = make_subplots(
                rows=3, cols=3,
                specs=[
                    [{"type": "scatter", "colspan": 2}, None, {"type": "bar"}],
                    [{"type": "heatmap"}, {"type": "scatter"}, {"type": "pie"}],
                    [{"type": "scatter3d", "colspan": 3}, None, None]
                ],
                subplot_titles=[
                    "Action 使用频率分布", "关键节点", "度分布",
                    "依赖矩阵", "增长趋势", "社区分布",
                    "3D 依赖视图"
                ],
                vertical_spacing=0.1,
                horizontal_spacing=0.1
            )
            
            # 1. Action 使用频率分布
            usage_file = self.processed_data_path / "action_usage_stats.csv"
            if usage_file.exists():
                df = pd.read_csv(usage_file)
                top_actions = df.nlargest(20, 'usage_count')
                
                fig.add_trace(
                    go.Scatter(
                        x=top_actions['action'],
                        y=top_actions['usage_count'],
                        mode='lines+markers',
                        name='使用频率'
                    ),
                    row=1, col=1
                )
            
            # 2. 关键节点
            critical_file = self.processed_data_path / "critical_nodes.json"
            if critical_file.exists():
                critical_data = load_json(str(critical_file))
                if critical_data:
                    nodes_data = critical_data[0].get('nodes', [])[:10]
                    nodes = [node['node'] for node in nodes_data]
                    values = [node['betweenness_centrality'] for node in nodes_data]
                    
                    fig.add_trace(
                        go.Bar(
                            x=nodes,
                            y=values,
                            name='中介中心性'
                        ),
                        row=1, col=3
                    )
            
            # 3. 度分布
            graph_file = self.graphs_path / "action_dependency_graph.gml"
            if graph_file.exists():
                G = nx.read_gml(str(graph_file))
                degrees = [d for _, d in G.degree()]
                
                fig.add_trace(
                    go.Histogram(
                        x=degrees,
                        name='度分布',
                        nbinsx=30
                    ),
                    row=1, col=3
                )
            
            # 4. 依赖矩阵
            edges_file = self.processed_data_path / "action_action_edges.csv"
            if edges_file.exists():
                df = pd.read_csv(edges_file)
                # 创建邻接矩阵...
                # 简化为显示边数量分布
                edge_counts = df['source'].value_counts().head(20)
                
                fig.add_trace(
                    go.Bar(
                        x=edge_counts.index,
                        y=edge_counts.values,
                        name='依赖数量'
                    ),
                    row=2, col=1
                )
            
            # 更新布局
            fig.update_layout(
                title_text='GitHub Actions 依赖分析仪表板',
                height=1200,
                showlegend=True
            )
            
            # 保存仪表板
            output_file = self.output_dir / "analysis_dashboard.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"综合仪表板已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"创建仪表板失败: {e}")
            return None
    
    def _sample_large_graph(self, G: nx.Graph, sample_type: str = 'random', 
                           sample_size: int = None) -> nx.Graph:
        """采样大型图"""
        if sample_size is None:
            sample_size = self.max_nodes_display
        
        if G.number_of_nodes() <= sample_size:
            return G
        
        if sample_type == 'random':
            # 随机采样
            nodes_to_keep = list(G.nodes())[:sample_size]
            return G.subgraph(nodes_to_keep)
        
        elif sample_type == 'important':
            # 基于 PageRank 重要性采样
            if 'pagerank' in G.nodes[list(G.nodes())[0]]:
                pagerank_scores = {node: G.nodes[node].get('pagerank', 0) 
                                  for node in G.nodes()}
                top_nodes = sorted(pagerank_scores.items(), 
                                 key=lambda x: x[1], reverse=True)[:sample_size]
                nodes_to_keep = [node for node, _ in top_nodes]
            else:
                # 使用度中心性
                degrees = dict(G.degree())
                top_nodes = sorted(degrees.items(), 
                                 key=lambda x: x[1], reverse=True)[:sample_size]
                nodes_to_keep = [node for node, _ in top_nodes]
            
            return G.subgraph(nodes_to_keep)
        
        elif sample_type == 'mixed':
            # 混合采样：保持连通性
            # 先选取重要节点，然后添加它们的邻居
            important_nodes = []
            
            # 获取高 PageRank 节点
            if 'pagerank' in G.nodes[list(G.nodes())[0]]:
                pagerank_scores = {node: G.nodes[node].get('pagerank', 0) 
                                  for node in G.nodes()}
                top_pagerank = sorted(pagerank_scores.items(), 
                                    key=lambda x: x[1], reverse=True)[:sample_size//2]
                important_nodes.extend([node for node, _ in top_pagerank])
            
            # 添加高入度节点
            in_degrees = dict(G.in_degree())
            top_in_degree = sorted(in_degrees.items(), 
                                 key=lambda x: x[1], reverse=True)[:sample_size//4]
            important_nodes.extend([node for node, _ in top_in_degree])
            
            # 添加高出度节点
            out_degrees = dict(G.out_degree())
            top_out_degree = sorted(out_degrees.items(), 
                                  key=lambda x: x[1], reverse=True)[:sample_size//4]
            important_nodes.extend([node for node, _ in top_out_degree])
            
            nodes_to_keep = list(set(important_nodes))[:sample_size]
            return G.subgraph(nodes_to_keep)
        
        else:
            return G.subgraph(list(G.nodes())[:sample_size])
    
    def _create_interactive_graph(self, G: nx.Graph, title: str, 
                                 node_size_attr: str = None,
                                 node_color_attr: str = None,
                                 node_color: List = None,
                                 show_labels: bool = True) -> go.Figure:
        """创建交互式图"""
        # 获取位置布局
        if G.number_of_nodes() < 100:
            pos = nx.spring_layout(G, k=2, iterations=50)
        else:
            pos = nx.kamada_kawai_layout(G)
        
        # 创建边轨迹
        edge_x = []
        edge_y = []
        edge_text = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_text.append(f"{edge[0]} → {edge[1]}")
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines',
            showlegend=False
        )
        
        # 创建节点轨迹
        node_x = []
        node_y = []
        node_text = []
        node_sizes = []
        node_colors = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            # 节点文本
            node_info = f"节点: {node}<br>"
            node_info += f"类型: {G.nodes[node].get('type', 'unknown')}<br>"
            
            if 'pagerank' in G.nodes[node]:
                node_info += f"PageRank: {G.nodes[node]['pagerank']:.4f}<br>"
            if 'degree' in G.nodes[node]:
                node_info += f"度: {G.nodes[node]['degree']}<br>"
            
            node_text.append(node_info)
            
            # 节点大小
            if node_size_attr and node_size_attr in G.nodes[node]:
                size_val = G.nodes[node][node_size_attr]
                node_sizes.append(max(5, size_val * 100))
            else:
                node_sizes.append(10)
            
            # 节点颜色
            if node_color is not None and len(node_color) == G.number_of_nodes():
                node_colors.append(node_color[list(G.nodes()).index(node)])
            elif node_color_attr and node_color_attr in G.nodes[node]:
                color_val = G.nodes[node][node_color_attr]
                # 简单颜色映射
                if isinstance(color_val, (int, float)):
                    # 数值映射到颜色
                    node_colors.append(color_val)
                else:
                    # 分类颜色
                    categories = list(set(G.nodes[n].get(node_color_attr) 
                                        for n in G.nodes()))
                    if color_val in categories:
                        idx = categories.index(color_val)
                        colors = px.colors.qualitative.Set3
                        node_colors.append(colors[idx % len(colors)])
                    else:
                        node_colors.append('lightblue')
            else:
                node_colors.append('lightblue')
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers' + ('+text' if show_labels else ''),
            text=[node if show_labels else '' for node in G.nodes()],
            textposition="bottom center",
            hovertext=node_text,
            hoverinfo='text',
            marker=dict(
                showscale=True,
                colorscale=self.color_scheme,
                color=node_colors if isinstance(node_colors[0], (int, float)) else None,
                size=node_sizes,
                line_width=2
            ),
            showlegend=False
        )
        
        # 创建图形
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title=title,
                           titlefont_size=16,
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                       ))
        
        return fig
    
    def _create_static_graph(self, G: nx.Graph, title: str,
                            node_size: str = 'degree',
                            node_color: str = 'type') -> plt.Figure:
        """创建静态图"""
        plt.style.use('seaborn-v0_8-darkgrid')
        
        fig, ax = plt.subplots(figsize=(14, 10))
        
        # 获取位置布局
        if G.number_of_nodes() < 100:
            pos = nx.spring_layout(G, k=2, iterations=50)
        else:
            pos = nx.kamada_kawai_layout(G)
        
        # 准备节点属性
        node_sizes = []
        node_colors = []
        color_map = {}
        
        # 确定颜色映射
        if node_color == 'type':
            types = list(set(G.nodes[n].get('type', 'unknown') for n in G.nodes()))
            cmap = plt.cm.get_cmap('tab20', len(types))
            color_map = {t: cmap(i) for i, t in enumerate(types)}
        
        for node in G.nodes():
            # 节点大小
            if node_size == 'degree':
                size = G.degree(node) * 50 + 50
            elif node_size == 'pagerank' and 'pagerank' in G.nodes[node]:
                size = G.nodes[node]['pagerank'] * 1000 + 50
            else:
                size = 100
            
            node_sizes.append(size)
            
            # 节点颜色
            if node_color == 'type':
                node_type = G.nodes[node].get('type', 'unknown')
                node_colors.append(color_map.get(node_type, 'gray'))
            else:
                node_colors.append('lightblue')
        
        # 绘制边
        nx.draw_networkx_edges(G, pos, alpha=0.2, ax=ax)
        
        # 绘制节点
        nodes = nx.draw_networkx_nodes(
            G, pos,
            node_size=node_sizes,
            node_color=node_colors,
            alpha=0.8,
            ax=ax
        )
        
        # 绘制标签（只显示重要的节点）
        if G.number_of_nodes() <= 50:
            labels = {node: node for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels, font_size=8, ax=ax)
        
        # 添加图例（对于类型）
        if node_color == 'type' and len(color_map) <= 10:
            from matplotlib.patches import Patch
            legend_elements = [Patch(facecolor=color, label=type_name) 
                             for type_name, color in color_map.items()]
            ax.legend(handles=legend_elements, loc='upper left', fontsize=8)
        
        ax.set_title(title, fontsize=16, fontweight='bold')
        ax.axis('off')
        
        return fig