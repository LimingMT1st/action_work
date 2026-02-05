# 【新增】专门展示 Action 依赖关系的交互视图
# visualizers/action_dependency_viewer.py
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path
import json

from utils.file_utils import load_json, ensure_dir
from processors.action_dependency_resolver import ActionDependencyResolver

class ActionDependencyViewer:
    """Action 依赖查看器 - 专门展示 Action 依赖关系的交互视图"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 输出目录
        self.output_dir = Path("output/visualizations/action_dependencies")
        ensure_dir(self.output_dir)
        
        # 依赖解析器
        self.dependency_resolver = ActionDependencyResolver(config)
    
    def visualize_specific_action_dependencies(self, action: str) -> Optional[str]:
        """可视化特定 action 的依赖关系"""
        self.logger.info(f"可视化 action 依赖关系: {action}")
        
        try:
            # 解析依赖
            dependencies = self.dependency_resolver.resolve_dependencies(action)
            if not dependencies:
                return None
            
            # 创建可视化
            fig = self._create_action_dependency_visualization(dependencies)
            
            if not fig:
                return None
            
            # 保存可视化
            safe_action_name = action.replace('/', '_').replace('@', '_')
            output_file = self.output_dir / f"{safe_action_name}_dependencies.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"依赖可视化已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"可视化 action 依赖失败: {e}")
            return None
    
    def create_dependency_explorer(self) -> Optional[str]:
        """创建依赖关系探索器"""
        self.logger.info("创建依赖关系探索器...")
        
        try:
            # 加载图数据
            graph_file = Path(self.config['paths']['graphs']) / "action_dependency_graph.gml"
            if not graph_file.exists():
                self.logger.error(f"图文件不存在: {graph_file}")
                return None
            
            G = nx.read_gml(str(graph_file))
            
            # 创建交互式探索器
            fig = self._create_interactive_explorer(G)
            
            # 保存探索器
            output_file = self.output_dir / "dependency_explorer.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"依赖探索器已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"创建依赖探索器失败: {e}")
            return None
    
    def visualize_dependency_metrics(self) -> List[str]:
        """可视化依赖指标"""
        self.logger.info("可视化依赖指标...")
        
        output_files = []
        
        try:
            # 加载依赖指标
            metrics_file = Path(self.config['paths']['processed_data']) / "dependency_metrics.json"
            if not metrics_file.exists():
                return output_files
            
            metrics = load_json(str(metrics_file))
            if not metrics:
                return output_files
            
            # 1. 深度指标可视化
            depth_fig = self._visualize_depth_metrics(metrics.get('dependency_depth_metrics', {}))
            if depth_fig:
                output_file1 = self.output_dir / "depth_metrics.html"
                depth_fig.write_html(str(output_file1))
                output_files.append(str(output_file1))
            
            # 2. 复杂度指标可视化
            complexity_fig = self._visualize_complexity_metrics(metrics.get('complexity_metrics', {}))
            if complexity_fig:
                output_file2 = self.output_dir / "complexity_metrics.html"
                complexity_fig.write_html(str(output_file2))
                output_files.append(str(output_file2))
            
            # 3. 关键路径可视化
            critical_path_fig = self._visualize_critical_paths(metrics.get('critical_path_analysis', {}))
            if critical_path_fig:
                output_file3 = self.output_dir / "critical_paths.html"
                critical_path_fig.write_html(str(output_file3))
                output_files.append(str(output_file3))
            
            return output_files
            
        except Exception as e:
            self.logger.error(f"可视化依赖指标失败: {e}")
            return output_files
    
    def visualize_dependency_patterns(self) -> Optional[str]:
        """可视化依赖模式"""
        self.logger.info("可视化依赖模式...")
        
        try:
            # 加载依赖模式数据
            patterns_file = Path(self.config['paths']['processed_data']) / "dependency_patterns.json"
            if not patterns_file.exists():
                return None
            
            patterns = load_json(str(patterns_file))
            if not patterns:
                return None
            
            # 创建模式可视化
            fig = self._create_pattern_visualization(patterns)
            
            # 保存可视化
            output_file = self.output_dir / "dependency_patterns.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"依赖模式可视化已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"可视化依赖模式失败: {e}")
            return None
    
    def create_sunburst_dependency_view(self) -> Optional[str]:
        """创建旭日图依赖视图"""
        self.logger.info("创建旭日图依赖视图...")
        
        try:
            # 加载图数据
            graph_file = Path(self.config['paths']['graphs']) / "action_dependency_graph.gml"
            if not graph_file.exists():
                return None
            
            G = nx.read_gml(str(graph_file))
            
            # 找到根节点（入度为0）
            root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]
            
            if not root_nodes:
                return None
            
            # 选择一个根节点创建旭日图
            root = root_nodes[0]
            
            # 构建层次数据
            hierarchical_data = self._build_hierarchical_data(G, root, max_depth=4)
            
            # 创建旭日图
            fig = px.sunburst(
                hierarchical_data,
                path=['root', 'level1', 'level2', 'level3'],
                values='count',
                title=f'依赖层次结构 - 根节点: {root}',
                color='depth',
                color_continuous_scale='viridis'
            )
            
            # 保存可视化
            safe_root_name = root.replace('/', '_').replace('@', '_')
            output_file = self.output_dir / f"sunburst_{safe_root_name}.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"旭日图已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"创建旭日图失败: {e}")
            return None
    
    def _create_action_dependency_visualization(self, dependencies: Dict) -> Optional[go.Figure]:
        """创建 action 依赖可视化"""
        try:
            # 从依赖数据中提取可视化所需信息
            dependency_tree = dependencies.get('dependency_tree', {})
            analysis = dependencies.get('analysis', {})
            issues = dependencies.get('issues', [])
            
            # 创建子图
            fig = make_subplots(
                rows=2, cols=3,
                specs=[
                    [{"type": "treemap", "colspan": 2}, None, {"type": "indicator"}],
                    [{"type": "bar"}, {"type": "scatter"}, {"type": "table"}]
                ],
                subplot_titles=[
                    "依赖树结构", "", "依赖深度",
                    "依赖指标", "节点分布", "检测到的问题"
                ],
                vertical_spacing=0.15
            )
            
            # 1. 依赖树结构（树状图）
            treemap_data = self._prepare_treemap_data(dependency_tree)
            
            fig.add_trace(
                go.Treemap(
                    labels=treemap_data['labels'],
                    parents=treemap_data['parents'],
                    values=treemap_data['values'],
                    textinfo="label+value",
                    marker=dict(
                        colors=treemap_data['colors'],
                        colorscale='Blues'
                    )
                ),
                row=1, col=1
            )
            
            # 2. 依赖深度指标
            depth_analysis = analysis.get('depth_analysis', {})
            max_depth = depth_analysis.get('max_depth', 0)
            
            fig.add_trace(
                go.Indicator(
                    mode="number+gauge",
                    value=max_depth,
                    title={'text': "最大深度"},
                    gauge={
                        'axis': {'range': [0, 10]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 3], 'color': "green"},
                            {'range': [3, 7], 'color': "yellow"},
                            {'range': [7, 10], 'color': "red"}
                        ]
                    }
                ),
                row=1, col=3
            )
            
            # 3. 依赖指标条形图
            breadth_analysis = analysis.get('breadth_analysis', {})
            
            metrics_data = {
                '指标': ['直接依赖', '传递依赖', '唯一依赖'],
                '数量': [
                    breadth_analysis.get('direct_dependencies_count', 0),
                    breadth_analysis.get('transitive_dependencies_count', 0),
                    breadth_analysis.get('unique_dependencies_count', 0)
                ]
            }
            
            fig.add_trace(
                go.Bar(
                    x=metrics_data['指标'],
                    y=metrics_data['数量'],
                    marker_color='lightblue'
                ),
                row=2, col=1
            )
            
            # 4. 节点分布散点图
            depth_levels = analysis.get('depth_analysis', {}).get('nodes_by_depth', {})
            
            fig.add_trace(
                go.Scatter(
                    x=list(depth_levels.keys()),
                    y=list(depth_levels.values()),
                    mode='lines+markers',
                    line=dict(color='orange', width=3),
                    marker=dict(size=10)
                ),
                row=2, col=2
            )
            
            # 5. 检测到的问题表格
            if issues:
                table_data = [
                    [issue['type'] for issue in issues],
                    [issue['severity'] for issue in issues],
                    [issue['description'][:50] + '...' for issue in issues]
                ]
                
                fig.add_trace(
                    go.Table(
                        header=dict(
                            values=['问题类型', '严重程度', '描述'],
                            font=dict(size=10, color='white'),
                            fill_color='navy'
                        ),
                        cells=dict(
                            values=table_data,
                            font=dict(size=9),
                            height=30
                        )
                    ),
                    row=2, col=3
                )
            
            # 更新布局
            fig.update_layout(
                title_text=f"Action 依赖分析: {dependencies.get('action', 'unknown')}",
                height=800,
                showlegend=False
            )
            
            return fig
            
        except Exception as e:
            self.logger.error(f"创建依赖可视化失败: {e}")
            return None
    
    def _create_interactive_explorer(self, G: nx.DiGraph) -> go.Figure:
        """创建交互式探索器"""
        # 获取布局
        if G.number_of_nodes() < 100:
            pos = nx.spring_layout(G, k=1.5, iterations=50)
        else:
            # 对大型图使用力导向布局
            pos = nx.spring_layout(G, k=0.5, iterations=30)
        
        # 创建节点轨迹
        node_x = []
        node_y = []
        node_text = []
        node_sizes = []
        node_colors = []
        node_ids = []
        
        # 计算节点属性用于可视化
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_ids.append(node)
            
            # 节点信息
            info = f"<b>{node}</b><br>"
            info += f"类型: {G.nodes[node].get('type', 'unknown')}<br>"
            
            # 添加度信息
            in_degree = G.in_degree(node)
            out_degree = G.out_degree(node)
            info += f"入度: {in_degree}<br>"
            info += f"出度: {out_degree}<br>"
            
            # 添加其他属性
            for attr in ['pagerank', 'depth', 'in_degree', 'out_degree']:
                if attr in G.nodes[node]:
                    info += f"{attr}: {G.nodes[node][attr]:.3f}<br>"
            
            node_text.append(info)
            
            # 节点大小（基于出度）
            size = max(5, out_degree * 5 + 10)
            node_sizes.append(size)
            
            # 节点颜色（基于入度）
            color_val = min(1.0, in_degree / 10)
            node_colors.append(color_val)
        
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
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            text=node_text,
            hoverinfo='text',
            marker=dict(
                showscale=True,
                colorscale='YlOrRd',
                color=node_colors,
                size=node_sizes,
                line_width=1,
                colorbar=dict(
                    title="入度强度",
                    thickness=15,
                    xanchor='left',
                    titleside='right'
                )
            ),
            customdata=node_ids
        )
        
        # 创建图形
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title='Action 依赖关系探索器',
                           titlefont_size=16,
                           showlegend=False,
                           hovermode='closest',
                           clickmode='event+select',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, 
                                     showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, 
                                     showticklabels=False)
                       ))
        
        # 添加交互功能
        fig.update_layout(
            updatemenus=[
                dict(
                    type="dropdown",
                    direction="down",
                    x=0.1,
                    y=1.15,
                    showactive=True,
                    buttons=[
                        dict(label="所有节点",
                             method="update",
                             args=[{"marker.color": [node_colors]}]),
                        dict(label="按入度着色",
                             method="update",
                             args=[{"marker.color": [node_colors]}]),
                        dict(label="按出度着色",
                             method="update",
                             args=[{"marker.color": [[G.out_degree(n) / 10 
                                                    for n in G.nodes()]]}]),
                        dict(label="按 PageRank 着色",
                             method="update",
                             args=[{"marker.color": [[G.nodes[n].get('pagerank', 0) 
                                                    for n in G.nodes()]]}])
                    ]
                ),
                dict(
                    type="buttons",
                    direction="right",
                    x=0.3,
                    y=1.15,
                    showactive=True,
                    buttons=[
                        dict(label="显示标签",
                             method="update",
                             args=[{"mode": "markers+text"},
                                   {"text": [n if i < 20 else '' 
                                            for i, n in enumerate(G.nodes())]}]),
                        dict(label="隐藏标签",
                             method="update",
                             args=[{"mode": "markers"},
                                   {"text": [''] * len(G.nodes())}])
                    ]
                )
            ]
        )
        
        return fig
    
    def _visualize_depth_metrics(self, depth_metrics: Dict) -> Optional[go.Figure]:
        """可视化深度指标"""
        if not depth_metrics:
            return None
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=['深度分布', '累积深度'],
            specs=[[{"type": "bar"}, {"type": "scatter"}]]
        )
        
        # 深度分布
        depth_dist = depth_metrics.get('depth_distribution', {})
        
        fig.add_trace(
            go.Bar(
                x=list(depth_dist.keys()),
                y=list(depth_dist.values()),
                name='深度分布',
                marker_color='lightblue'
            ),
            row=1, col=1
        )
        
        # 累积深度
        depths = list(depth_dist.keys())
        counts = list(depth_dist.values())
        
        if depths and counts:
            cumulative_counts = np.cumsum(counts)
            
            fig.add_trace(
                go.Scatter(
                    x=depths,
                    y=cumulative_counts,
                    mode='lines+markers',
                    name='累积节点数',
                    line=dict(color='orange', width=3)
                ),
                row=1, col=2
            )
        
        fig.update_layout(
            title_text='依赖深度分析',
            height=500,
            showlegend=True
        )
        
        return fig
    
    def _visualize_complexity_metrics(self, complexity_metrics: Dict) -> Optional[go.Figure]:
        """可视化复杂度指标"""
        if not complexity_metrics:
            return None
        
        fig = make_subplots(
            rows=1, cols=2,
            subplot_titles=['复杂度分布', '最复杂节点'],
            specs=[[{"type": "histogram"}, {"type": "bar"}]]
        )
        
        # 复杂度分布
        complexity_scores = complexity_metrics.get('complexity_scores', {})
        scores = [data['complexity_score'] for data in complexity_scores.values()]
        
        if scores:
            fig.add_trace(
                go.Histogram(
                    x=scores,
                    name='复杂度分布',
                    nbinsx=20,
                    marker_color='lightgreen'
                ),
                row=1, col=1
            )
        
        # 最复杂节点
        most_complex = complexity_metrics.get('most_complex_nodes', [])[:10]
        
        if most_complex:
            nodes = [node for node, _ in most_complex]
            scores = [data['complexity_score'] for _, data in most_complex]
            
            fig.add_trace(
                go.Bar(
                    x=nodes,
                    y=scores,
                    name='最复杂节点',
                    marker_color='coral'
                ),
                row=1, col=2
            )
        
        fig.update_layout(
            title_text='依赖复杂度分析',
            height=500,
            showlegend=True,
            xaxis2=dict(tickangle=45)
        )
        
        return fig
    
    def _visualize_critical_paths(self, critical_paths: Dict) -> Optional[go.Figure]:
        """可视化关键路径"""
        if not critical_paths:
            return None
        
        paths = critical_paths.get('critical_paths', [])
        
        if not paths:
            return None
        
        fig = go.Figure()
        
        for i, path_info in enumerate(paths[:5]):  # 只显示前5个关键路径
            path = path_info.get('path', [])
            length = path_info.get('length', 0)
            
            # 创建路径连接线
            for j in range(len(path) - 1):
                fig.add_trace(go.Scatter(
                    x=[j, j+1],
                    y=[i, i],
                    mode='lines',
                    line=dict(width=3, color='blue'),
                    showlegend=False,
                    hoverinfo='none'
                ))
            
            # 添加节点标记
            for j, node in enumerate(path):
                fig.add_trace(go.Scatter(
                    x=[j],
                    y=[i],
                    mode='markers+text',
                    marker=dict(size=15, color='lightblue'),
                    text=[node],
                    textposition="top center",
                    name=f'路径 {i+1}',
                    showlegend=(j == 0),  # 只在第一个节点显示图例
                    hovertemplate=f"节点: {node}<br>路径: {i+1}<br>位置: {j}<extra></extra>"
                ))
        
        fig.update_layout(
            title=f'关键路径分析 (最长路径: {critical_paths.get("longest_path_length", 0)})',
            xaxis_title='路径位置',
            yaxis_title='路径索引',
            height=400,
            showlegend=True
        )
        
        # 隐藏y轴刻度
        fig.update_yaxes(showticklabels=False)
        
        return fig
    
    def _create_pattern_visualization(self, patterns: Dict) -> go.Figure:
        """创建模式可视化"""
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=['模式分布', '星型模式', '链式模式', '树型模式'],
            specs=[[{"type": "pie"}, {"type": "bar"}],
                   [{"type": "bar"}, {"type": "bar"}]],
            vertical_spacing=0.15
        )
        
        # 1. 模式分布饼图
        distribution = patterns.get('summary', {}).get('pattern_distribution', {})
        
        fig.add_trace(
            go.Pie(
                labels=list(distribution.keys()),
                values=list(distribution.values()),
                name='模式分布'
            ),
            row=1, col=1
        )
        
        # 2. 星型模式
        star_patterns = patterns.get('star_patterns', [])[:10]
        
        fig.add_trace(
            go.Bar(
                x=[pattern['center'] for pattern in star_patterns],
                y=[pattern['dependency_count'] for pattern in star_patterns],
                name='星型模式',
                marker_color='lightblue'
            ),
            row=1, col=2
        )
        
        # 3. 链式模式
        chain_patterns = patterns.get('chain_patterns', [])[:10]
        
        fig.add_trace(
            go.Bar(
                x=[f"链 {i+1}" for i in range(len(chain_patterns))],
                y=[pattern['length'] for pattern in chain_patterns],
                name='链式模式',
                marker_color='lightgreen'
            ),
            row=2, col=1
        )
        
        # 4. 树型模式
        tree_patterns = patterns.get('tree_patterns', [])[:10]
        
        fig.add_trace(
            go.Bar(
                x=[pattern['root'] for pattern in tree_patterns],
                y=[pattern['size'] for pattern in tree_patterns],
                name='树型模式',
                marker_color='lightcoral'
            ),
            row=2, col=2
        )
        
        fig.update_layout(
            title_text='依赖模式分析',
            height=800,
            showlegend=False,
            xaxis2=dict(tickangle=45),
            xaxis4=dict(tickangle=45)
        )
        
        return fig
    
    def _prepare_treemap_data(self, tree: Dict) -> Dict:
        """准备树状图数据"""
        labels = []
        parents = []
        values = []
        colors = []
        
        def traverse(node, parent=''):
            node_label = node.get('node', 'unknown')
            node_type = node.get('type', 'unknown')
            
            # 添加当前节点
            labels.append(node_label)
            parents.append(parent)
            
            # 计算值（基于子节点数量或类型）
            child_count = len(node.get('children', []))
            values.append(max(1, child_count * 10))
            
            # 根据类型分配颜色
            color_map = {
                'action': 'lightblue',
                'repo': 'lightgreen',
                'unknown': 'lightgray'
            }
            colors.append(color_map.get(node_type, 'lightgray'))
            
            # 遍历子节点
            for child in node.get('children', []):
                traverse(child, node_label)
        
        # 从根节点开始遍历
        traverse(tree, '')
        
        return {
            'labels': labels,
            'parents': parents,
            'values': values,
            'colors': colors
        }
    
    def _build_hierarchical_data(self, G: nx.DiGraph, root: str, max_depth: int = 4) -> List[Dict]:
        """构建层次数据"""
        data = []
        
        def add_node(node, depth, parent=None):
            if depth > max_depth:
                return
            
            # 添加当前节点
            node_data = {
                'root': root,
                f'level{depth}': node,
                'depth': depth,
                'count': 1
            }
            
            # 添加父级信息
            for d in range(1, depth):
                node_data[f'level{d}'] = parent[f'level{d}'] if parent else ''
            
            data.append(node_data)
            
            # 添加子节点
            if depth < max_depth:
                for child in G.successors(node):
                    add_node(child, depth + 1, node_data)
        
        # 从根节点开始
        add_node(root, 1)
        
        return data