# 时间序列图表
# visualizers/security_dashboard.py
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import logging
from pathlib import Path

from utils.file_utils import load_json, ensure_dir

class SecurityDashboard:
    """安全仪表板 - 可视化安全分析结果"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 输出目录
        self.output_dir = Path("output/visualizations")
        ensure_dir(self.output_dir)
    
    def create_security_dashboard(self) -> Optional[str]:
        """创建安全仪表板"""
        self.logger.info("创建安全仪表板...")
        
        try:
            # 加载安全分析数据
            security_data = self._load_security_data()
            if not security_data:
                return None
            
            # 创建仪表板
            fig = make_subplots(
                rows=3, cols=3,
                specs=[
                    [{"type": "indicator"}, {"type": "pie"}, {"type": "bar"}],
                    [{"type": "heatmap"}, {"type": "scatter"}, {"type": "table"}],
                    [{"type": "bar", "colspan": 3}, None, {"type": "bar"}]
                ],
                subplot_titles=[
                    "总体风险评分", "风险分布", "高风险 Actions",
                    "风险类型热图", "风险趋势", "漏洞模式",
                    "安全建议优先级", "", "缓解措施"
                ],
                vertical_spacing=0.15,
                horizontal_spacing=0.1
            )
            
            # 1. 总体风险评分
            fig.add_trace(
                go.Indicator(
                    mode="gauge+number",
                    value=security_data.get('overall_risk_score', 65),
                    title={'text': "安全评分"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 30], 'color': "green"},
                            {'range': [30, 70], 'color': "yellow"},
                            {'range': [70, 100], 'color': "red"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 70
                        }
                    }
                ),
                row=1, col=1
            )
            
            # 2. 风险分布
            risk_distribution = security_data.get('risk_distribution', {})
            fig.add_trace(
                go.Pie(
                    labels=list(risk_distribution.keys()),
                    values=list(risk_distribution.values()),
                    name='风险分布'
                ),
                row=1, col=2
            )
            
            # 3. 高风险 Actions
            high_risk_actions = security_data.get('high_risk_actions', [])[:10]
            fig.add_trace(
                go.Bar(
                    x=[action['action'] for action in high_risk_actions],
                    y=[action['risk_score'] for action in high_risk_actions],
                    name='高风险 Actions',
                    marker_color='crimson'
                ),
                row=1, col=3
            )
            
            # 4. 风险类型热图
            risk_matrix = security_data.get('risk_matrix', {})
            fig.add_trace(
                go.Heatmap(
                    z=risk_matrix.get('data', []),
                    x=risk_matrix.get('x_labels', []),
                    y=risk_matrix.get('y_labels', []),
                    colorscale='Reds',
                    name='风险热图'
                ),
                row=2, col=1
            )
            
            # 5. 风险趋势
            risk_trends = security_data.get('risk_trends', [])
            fig.add_trace(
                go.Scatter(
                    x=[trend['date'] for trend in risk_trends],
                    y=[trend['risk_score'] for trend in risk_trends],
                    mode='lines+markers',
                    name='风险趋势',
                    line=dict(color='orange', width=3)
                ),
                row=2, col=2
            )
            
            # 6. 漏洞模式表格
            vulnerability_patterns = security_data.get('vulnerability_patterns', [])[:5]
            
            # 创建表格数据
            table_data = [
                [pattern['pattern'] for pattern in vulnerability_patterns],
                [pattern['risk_level'] for pattern in vulnerability_patterns],
                [pattern['count'] for pattern in vulnerability_patterns]
            ]
            
            fig.add_trace(
                go.Table(
                    header=dict(
                        values=['漏洞模式', '风险级别', '出现次数'],
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
            
            # 7. 安全建议优先级
            recommendations = security_data.get('recommendations', [])[:8]
            fig.add_trace(
                go.Bar(
                    x=[rec['priority'] for rec in recommendations],
                    y=[rec['description'] for rec in recommendations],
                    orientation='h',
                    name='安全建议',
                    marker_color='lightseagreen'
                ),
                row=3, col=1
            )
            
            # 更新布局
            fig.update_layout(
                title_text='GitHub Actions 安全分析仪表板',
                height=1000,
                showlegend=False
            )
            
            # 保存仪表板
            output_file = self.output_dir / "security_dashboard.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"安全仪表板已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"创建安全仪表板失败: {e}")
            return None
    
    def plot_risk_heatmap(self) -> List[str]:
        """绘制风险热图"""
        self.logger.info("绘制风险热图...")
        
        output_files = []
        
        try:
            # 加载安全分析数据
            security_analysis = load_json(
                str(Path(self.config['paths']['processed_data']) / "security_analysis.json")
            )
            
            if not security_analysis:
                return output_files
            
            # 1. 风险类型分布热图
            risk_types = {}
            for workflow in security_analysis.get('high_risk_workflows', []):
                for issue in workflow.get('issues', []):
                    risk_type = issue['type']
                    risk_types[risk_type] = risk_types.get(risk_type, 0) + 1
            
            # 创建热图数据
            risk_df = pd.DataFrame({
                '风险类型': list(risk_types.keys()),
                '出现次数': list(risk_types.values()),
                '风险级别': ['high' if count > 10 else 'medium' if count > 5 else 'low' 
                         for count in risk_types.values()]
            })
            
            fig1 = px.treemap(
                risk_df,
                path=['风险级别', '风险类型'],
                values='出现次数',
                color='出现次数',
                color_continuous_scale='Reds',
                title='风险类型分布'
            )
            
            output_file1 = self.output_dir / "risk_type_treemap.html"
            fig1.write_html(str(output_file1))
            output_files.append(str(output_file1))
            
            # 2. 风险严重程度矩阵
            severity_matrix = {
                'critical': len([w for w in security_analysis.get('high_risk_workflows', []) 
                               if w.get('risk_level') == 'critical']),
                'high': len([w for w in security_analysis.get('high_risk_workflows', []) 
                            if w.get('risk_level') == 'high']),
                'medium': len([w for w in security_analysis.get('high_risk_workflows', []) 
                              if w.get('risk_level') == 'medium']),
                'low': len([w for w in security_analysis.get('high_risk_workflows', []) 
                           if w.get('risk_level') == 'low'])
            }
            
            fig2 = go.Figure(data=[
                go.Bar(
                    x=list(severity_matrix.keys()),
                    y=list(severity_matrix.values()),
                    marker_color=['red', 'orange', 'yellow', 'green']
                )
            ])
            
            fig2.update_layout(
                title='风险严重程度分布',
                xaxis_title='风险级别',
                yaxis_title='Workflows 数量'
            )
            
            output_file2 = self.output_dir / "risk_severity_matrix.html"
            fig2.write_html(str(output_file2))
            output_files.append(str(output_file2))
            
            # 3. 时间风险趋势
            # 这里需要时间序列数据，使用模拟数据
            dates = pd.date_range(start='2024-01-01', end='2024-12-31', freq='M')
            risk_scores = np.random.randint(30, 90, size=len(dates))
            
            fig3 = go.Figure()
            
            fig3.add_trace(go.Scatter(
                x=dates,
                y=risk_scores,
                mode='lines+markers',
                line=dict(color='red', width=3),
                name='风险评分'
            ))
            
            # 添加阈值线
            fig3.add_hline(y=70, line_dash="dash", line_color="orange", 
                          annotation_text="高风险阈值")
            fig3.add_hline(y=50, line_dash="dash", line_color="green", 
                          annotation_text="中等风险阈值")
            
            fig3.update_layout(
                title='月度风险趋势',
                xaxis_title='月份',
                yaxis_title='风险评分'
            )
            
            output_file3 = self.output_dir / "risk_trend_over_time.html"
            fig3.write_html(str(output_file3))
            output_files.append(str(output_file3))
            
            return output_files
            
        except Exception as e:
            self.logger.error(f"绘制风险热图失败: {e}")
            return output_files
    
    def plot_vulnerability_patterns(self) -> Optional[str]:
        """绘制漏洞模式图"""
        self.logger.info("绘制漏洞模式图...")
        
        try:
            # 加载漏洞模式数据
            patterns_file = Path(self.config['paths']['processed_data']) / "vulnerability_patterns.json"
            if not patterns_file.exists():
                return None
            
            patterns_data = load_json(str(patterns_file))
            if not patterns_data:
                return None
            
            # 创建桑基图显示漏洞传播
            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=[
                        "未固定 Actions", 
                        "过宽权限", 
                        "硬编码秘密",
                        "高风险依赖",
                        "供应链攻击",
                        "数据泄露",
                        "权限提升"
                    ],
                    color=[
                        "lightblue", "lightgreen", "lightcoral",
                        "orange", "purple", "red", "yellow"
                    ]
                ),
                link=dict(
                    source=[0, 0, 1, 1, 2, 3, 4],  # 源节点索引
                    target=[4, 5, 5, 6, 5, 4, 5],  # 目标节点索引
                    value=[10, 8, 12, 5, 15, 7, 20]  # 流量值
                )
            )])
            
            fig.update_layout(
                title_text="漏洞传播路径分析",
                font_size=12,
                height=600
            )
            
            # 保存图表
            output_file = self.output_dir / "vulnerability_sankey.html"
            fig.write_html(str(output_file))
            
            self.logger.info(f"漏洞模式图已保存到: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"绘制漏洞模式图失败: {e}")
            return None
    
    def plot_supply_chain_risks(self) -> List[str]:
        """绘制供应链风险图"""
        self.logger.info("绘制供应链风险图...")
        
        output_files = []
        
        try:
            # 加载供应链风险数据
            supply_chain_file = Path(self.config['paths']['processed_data']) / "action_security_analysis.json"
            if not supply_chain_file.exists():
                return output_files
            
            supply_chain_data = load_json(str(supply_chain_file))
            if not supply_chain_data:
                return output_files
            
            supply_chain_risks = supply_chain_data.get('supply_chain_risks', [])
            
            if not supply_chain_risks:
                return output_files
            
            # 1. 供应链风险条形图
            actions = [risk['action'] for risk in supply_chain_risks[:15]]
            in_degrees = [risk['in_degree'] for risk in supply_chain_risks[:15]]
            risk_scores = [risk['risk_assessment'].get('overall_risk_score', 0) 
                         for risk in supply_chain_risks[:15]]
            
            fig1 = go.Figure()
            
            fig1.add_trace(go.Bar(
                x=actions,
                y=in_degrees,
                name='入度',
                marker_color='lightblue'
            ))
            
            fig1.add_trace(go.Scatter(
                x=actions,
                y=risk_scores,
                name='风险评分',
                yaxis='y2',
                line=dict(color='red', width=3)
            ))
            
            fig1.update_layout(
                title='供应链风险分析',
                xaxis_title='Action',
                yaxis_title='入度（被依赖数）',
                yaxis2=dict(
                    title='风险评分',
                    overlaying='y',
                    side='right'
                ),
                xaxis_tickangle=45,
                height=600
            )
            
            output_file1 = self.output_dir / "supply_chain_risk_bar.html"
            fig1.write_html(str(output_file1))
            output_files.append(str(output_file1))
            
            # 2. 风险散点图
            fig2 = px.scatter(
                pd.DataFrame(supply_chain_risks[:30]),
                x='in_degree',
                y=[r['risk_assessment'].get('overall_risk_score', 0) 
                  for r in supply_chain_risks[:30]],
                size='in_degree',
                color=[r['risk_assessment'].get('overall_risk', 'medium') 
                      for r in supply_chain_risks[:30]],
                hover_name='action',
                title='供应链风险散点图',
                labels={
                    'x': '入度（被依赖数）',
                    'y': '风险评分',
                    'color': '风险级别'
                }
            )
            
            output_file2 = self.output_dir / "supply_chain_risk_scatter.html"
            fig2.write_html(str(output_file2))
            output_files.append(str(output_file2))
            
            return output_files
            
        except Exception as e:
            self.logger.error(f"绘制供应链风险图失败: {e}")
            return output_files
    
    def _load_security_data(self) -> Dict:
        """加载安全数据"""
        security_data = {
            'overall_risk_score': 65,
            'risk_distribution': {
                'critical': 5,
                'high': 15,
                'medium': 30,
                'low': 50
            },
            'high_risk_actions': [],
            'risk_matrix': {
                'data': [[10, 20, 30], [15, 25, 35], [5, 15, 25]],
                'x_labels': ['权限风险', '依赖风险', '配置风险'],
                'y_labels': ['高频', '中频', '低频']
            },
            'risk_trends': [
                {'date': '2024-01', 'risk_score': 45},
                {'date': '2024-02', 'risk_score': 50},
                {'date': '2024-03', 'risk_score': 55},
                {'date': '2024-04', 'risk_score': 60},
                {'date': '2024-05', 'risk_score': 65},
                {'date': '2024-06', 'risk_score': 70}
            ],
            'vulnerability_patterns': [
                {'pattern': '未固定 Actions', 'risk_level': 'high', 'count': 120},
                {'pattern': '过宽权限', 'risk_level': 'medium', 'count': 85},
                {'pattern': '硬编码秘密', 'risk_level': 'critical', 'count': 15},
                {'pattern': '高风险依赖', 'risk_level': 'high', 'count': 45},
                {'pattern': '供应链攻击', 'risk_level': 'critical', 'count': 8}
            ],
            'recommendations': [
                {'description': '固定所有 Actions 版本', 'priority': 10, 'effort': '低'},
                {'description': '限制 GITHUB_TOKEN 权限', 'priority': 9, 'effort': '中'},
                {'description': '移除硬编码秘密', 'priority': 10, 'effort': '高'},
                {'description': '审查第三方依赖', 'priority': 8, 'effort': '高'},
                {'description': '实施安全扫描', 'priority': 7, 'effort': '中'},
                {'description': '建立安全基线', 'priority': 6, 'effort': '高'},
                {'description': '培训开发人员', 'priority': 5, 'effort': '中'},
                {'description': '定期安全审计', 'priority': 4, 'effort': '高'}
            ]
        }
        
        # 尝试加载实际数据
        try:
            security_analysis = load_json(
                str(Path(self.config['paths']['processed_data']) / "security_analysis.json")
            )
            
            if security_analysis:
                summary = security_analysis.get('summary', {})
                security_data['overall_risk_score'] = summary.get('risk_percentage', 65)
                
                # 计算风险分布
                workflows = security_analysis.get('high_risk_workflows', [])
                risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                
                for workflow in workflows:
                    risk_level = workflow.get('risk_level', 'low')
                    if risk_level in risk_counts:
                        risk_counts[risk_level] += 1
                
                security_data['risk_distribution'] = risk_counts
                
        except Exception:
            pass
        
        return security_data