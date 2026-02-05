# 时间序列图表# processors/time_series_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

from utils.file_utils import load_json, save_json

class TimeSeriesAnalyzer:
    """时间序列分析器 - 分析依赖关系随时间的变化"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 路径
        self.processed_data_path = Path(config['paths']['processed_data'])
    
    def analyze_usage_trends(self, dependencies_data: Dict) -> Optional[pd.DataFrame]:
        """分析使用趋势"""
        self.logger.info("分析 action 使用趋势...")
        
        try:
            # 从依赖数据中提取时间信息
            # 注意：实际项目中需要仓库的创建/更新时间数据
            # 这里我们模拟生成时间序列数据
            
            # 加载 action 使用统计
            usage_file = self.processed_data_path / "action_usage_stats.csv"
            if not usage_file.exists():
                self.logger.error(f"找不到使用统计文件: {usage_file}")
                return None
            
            df = pd.read_csv(usage_file)
            
            # 模拟时间序列数据
            # 在实际项目中，这里应该使用实际的仓库创建/更新时间
            trends = self._simulate_trends(df)
            
            # 分析趋势
            trend_analysis = self._analyze_trends(trends)
            
            # 保存结果
            self._save_trend_analysis(trend_analysis, trends)
            
            return trends
            
        except Exception as e:
            self.logger.error(f"分析使用趋势失败: {e}")
            return None
    
    def detect_emerging_actions(self, trends_df: pd.DataFrame, window_days: int = 90) -> List[Dict]:
        """检测新兴的 actions"""
        self.logger.info(f"检测最近 {window_days} 天的新兴 actions...")
        
        emerging_actions = []
        
        try:
            # 确保有时间列
            if 'date' not in trends_df.columns:
                self.logger.error("趋势数据缺少时间列")
                return emerging_actions
            
            # 转换时间列
            trends_df['date'] = pd.to_datetime(trends_df['date'])
            
            # 计算最近时间窗口
            recent_date = trends_df['date'].max()
            window_start = recent_date - timedelta(days=window_days)
            
            # 筛选最近数据
            recent_data = trends_df[trends_df['date'] >= window_start].copy()
            
            if recent_data.empty:
                return emerging_actions
            
            # 按 action 分组分析
            for action in recent_data['action'].unique():
                action_data = recent_data[recent_data['action'] == action]
                
                if len(action_data) < 2:
                    continue
                
                # 计算增长率和加速度
                action_data = action_data.sort_values('date')
                usage_values = action_data['usage_count'].values
                
                # 计算增长率
                if len(usage_values) >= 2:
                    growth_rate = (usage_values[-1] - usage_values[0]) / usage_values[0] if usage_values[0] > 0 else 0
                    
                    # 计算加速度（最近两个时间点的变化）
                    if len(usage_values) >= 3:
                        recent_growth = usage_values[-1] - usage_values[-2]
                        previous_growth = usage_values[-2] - usage_values[-3]
                        acceleration = recent_growth - previous_growth
                    else:
                        acceleration = 0
                    
                    # 判断是否为新兴 action
                    is_emerging = (
                        growth_rate > 1.0 and  # 增长率超过100%
                        usage_values[-1] > 10 and  # 至少有10次使用
                        recent_growth > 0  # 最近在增长
                    )
                    
                    if is_emerging:
                        emerging_actions.append({
                            'action': action,
                            'current_usage': int(usage_values[-1]),
                            'growth_rate': float(growth_rate),
                            'acceleration': float(acceleration),
                            'time_period': f"{window_days}天",
                            'trend_data': {
                                'dates': action_data['date'].dt.strftime('%Y-%m-%d').tolist(),
                                'usage_counts': usage_values.tolist()
                            }
                        })
            
            # 按增长率排序
            emerging_actions.sort(key=lambda x: x['growth_rate'], reverse=True)
            
            # 保存结果
            save_json(
                emerging_actions[:50],  # 只保存前50个
                str(self.processed_data_path / "emerging_actions.json")
            )
            
            self.logger.info(f"检测到 {len(emerging_actions)} 个新兴 actions")
            
            return emerging_actions[:20]  # 返回前20个
            
        except Exception as e:
            self.logger.error(f"检测新兴 actions 失败: {e}")
            return []
    
    def analyze_adoption_patterns(self, trends_df: pd.DataFrame) -> Dict:
        """分析采用模式"""
        self.logger.info("分析 action 采用模式...")
        
        patterns = {
            'early_adopters': [],
            'mainstream_adopters': [],
            'laggards': [],
            'adoption_curve': {}
        }
        
        try:
            if trends_df.empty:
                return patterns
            
            # 计算每个 action 的采用时间
            adoption_data = self._calculate_adoption_times(trends_df)
            
            # 分类 adopters
            if adoption_data:
                # 计算采用时间的百分位数
                adoption_days = [data['days_to_adopt'] for data in adoption_data.values()]
                
                if adoption_days:
                    q1 = np.percentile(adoption_days, 25)
                    median = np.percentile(adoption_days, 50)
                    q3 = np.percentile(adoption_days, 75)
                    
                    for action, data in adoption_data.items():
                        days = data['days_to_adopt']
                        
                        if days <= q1:
                            patterns['early_adopters'].append({
                                'action': action,
                                'days_to_adopt': days,
                                'adoption_speed': 'early'
                            })
                        elif days <= median:
                            patterns['early_adopters'].append({
                                'action': action,
                                'days_to_adopt': days,
                                'adoption_speed': 'early_majority'
                            })
                        elif days <= q3:
                            patterns['mainstream_adopters'].append({
                                'action': action,
                                'days_to_adopt': days,
                                'adoption_speed': 'late_majority'
                            })
                        else:
                            patterns['laggards'].append({
                                'action': action,
                                'days_to_adopt': days,
                                'adoption_speed': 'laggard'
                            })
                    
                    patterns['adoption_curve'] = {
                        'q1': float(q1),
                        'median': float(median),
                        'q3': float(q3),
                        'total_actions': len(adoption_data)
                    }
            
            # 保存结果
            save_json(
                patterns,
                str(self.processed_data_path / "adoption_patterns.json")
            )
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"分析采用模式失败: {e}")
            return patterns
    
    def forecast_usage(self, trends_df: pd.DataFrame, forecast_days: int = 30) -> Dict:
        """预测未来使用情况"""
        self.logger.info(f"预测未来 {forecast_days} 天的使用情况...")
        
        forecasts = {}
        
        try:
            if trends_df.empty:
                return forecasts
            
            # 按 action 分组预测
            top_actions = trends_df.groupby('action')['usage_count'].max().nlargest(20).index
            
            for action in top_actions:
                action_data = trends_df[trends_df['action'] == action].copy()
                
                if len(action_data) < 3:
                    continue
                
                # 准备时间序列数据
                action_data = action_data.sort_values('date')
                action_data['date_ordinal'] = action_data['date'].map(datetime.toordinal)
                
                # 简单线性回归预测
                X = action_data['date_ordinal'].values.reshape(-1, 1)
                y = action_data['usage_count'].values
                
                from sklearn.linear_model import LinearRegression
                model = LinearRegression()
                model.fit(X, y)
                
                # 预测未来
                last_date = action_data['date'].max()
                future_dates = [last_date + timedelta(days=i) for i in range(1, forecast_days + 1)]
                future_ordinals = np.array([d.toordinal() for d in future_dates]).reshape(-1, 1)
                
                predictions = model.predict(future_ordinals)
                predictions = np.maximum(predictions, 0)  # 确保非负
                
                forecasts[action] = {
                    'current_usage': int(y[-1]),
                    'growth_rate': float(model.coef_[0]) if len(model.coef_) > 0 else 0,
                    'predictions': {
                        'dates': [d.strftime('%Y-%m-%d') for d in future_dates],
                        'usage': predictions.tolist()
                    },
                    'confidence': self._calculate_forecast_confidence(action_data, model)
                }
            
            # 保存预测结果
            save_json(
                forecasts,
                str(self.processed_data_path / "usage_forecasts.json")
            )
            
            return forecasts
            
        except Exception as e:
            self.logger.error(f"预测使用情况失败: {e}")
            return forecasts
    
    def _simulate_trends(self, df: pd.DataFrame) -> pd.DataFrame:
        """模拟时间序列趋势（用于演示）"""
        # 在实际项目中，这里应该使用真实的时序数据
        trends_data = []
        
        # 为每个 action 生成时间序列
        for _, row in df.iterrows():
            action = row['action']
            total_usage = row['usage_count']
            
            # 生成模拟的月度数据（过去12个月）
            base_date = datetime.now() - timedelta(days=365)
            
            # 模拟不同的采用曲线
            for month in range(12):
                date = base_date + timedelta(days=30 * month)
                
                # 模拟使用量（逻辑增长曲线）
                month_factor = month / 11  # 0 到 1
                
                # S型增长曲线
                if month_factor < 0.3:
                    # 缓慢开始
                    usage = total_usage * 0.1 * month_factor / 0.3
                elif month_factor < 0.7:
                    # 快速增长
                    usage = total_usage * (0.1 + 0.6 * (month_factor - 0.3) / 0.4)
                else:
                    # 趋于饱和
                    usage = total_usage * (0.7 + 0.3 * (month_factor - 0.7) / 0.3)
                
                # 添加随机噪声
                usage += np.random.normal(0, usage * 0.1)
                usage = max(0, usage)
                
                trends_data.append({
                    'date': date,
                    'action': action,
                    'usage_count': int(usage)
                })
        
        trends_df = pd.DataFrame(trends_data)
        trends_df['date'] = pd.to_datetime(trends_df['date'])
        
        # 保存模拟数据
        trends_df.to_csv(
            str(self.processed_data_path / "time_series_usage.csv"),
            index=False
        )
        
        return trends_df
    
    def _analyze_trends(self, trends_df: pd.DataFrame) -> Dict:
        """分析趋势数据"""
        analysis = {
            'summary': {},
            'top_trending': [],
            'seasonal_patterns': {},
            'correlation_analysis': {}
        }
        
        try:
            # 基本统计
            analysis['summary'] = {
                'time_period': {
                    'start': trends_df['date'].min().strftime('%Y-%m-%d'),
                    'end': trends_df['date'].max().strftime('%Y-%m-%d')
                },
                'total_actions': trends_df['action'].nunique(),
                'total_data_points': len(trends_df)
            }
            
            # 找出趋势最明显的 actions
            trending_actions = []
            for action in trends_df['action'].unique():
                action_data = trends_df[trends_df['action'] == action].sort_values('date')
                
                if len(action_data) >= 2:
                    # 计算增长率
                    start_usage = action_data['usage_count'].iloc[0]
                    end_usage = action_data['usage_count'].iloc[-1]
                    
                    if start_usage > 0:
                        growth_rate = (end_usage - start_usage) / start_usage
                    else:
                        growth_rate = 0 if end_usage == 0 else float('inf')
                    
                    # 计算波动性
                    volatility = action_data['usage_count'].std() / action_data['usage_count'].mean() \
                        if action_data['usage_count'].mean() > 0 else 0
                    
                    trending_actions.append({
                        'action': action,
                        'growth_rate': float(growth_rate),
                        'volatility': float(volatility),
                        'start_usage': int(start_usage),
                        'end_usage': int(end_usage)
                    })
            
            # 按增长率排序
            trending_actions.sort(key=lambda x: abs(x['growth_rate']), reverse=True)
            analysis['top_trending'] = trending_actions[:20]
            
            # 季节性分析（按月份）
            trends_df['month'] = trends_df['date'].dt.month
            monthly_trends = trends_df.groupby('month')['usage_count'].agg(['mean', 'std', 'count']).reset_index()
            analysis['seasonal_patterns']['monthly'] = monthly_trends.to_dict('records')
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"分析趋势数据失败: {e}")
            return analysis
    
    def _calculate_adoption_times(self, trends_df: pd.DataFrame) -> Dict:
        """计算采用时间"""
        adoption_times = {}
        
        # 找到每个 action 首次出现的时间
        first_appearance = trends_df.groupby('action')['date'].min()
        
        # 找到每个 action 达到10次使用的时间
        for action in trends_df['action'].unique():
            action_data = trends_df[trends_df['action'] == action].sort_values('date')
            
            # 找到达到10次使用的时间点
            cumulative_usage = 0
            adoption_date = None
            
            for _, row in action_data.iterrows():
                cumulative_usage += row['usage_count']
                if cumulative_usage >= 10 and adoption_date is None:
                    adoption_date = row['date']
                    break
            
            if adoption_date:
                first_date = first_appearance[action]
                days_to_adopt = (adoption_date - first_date).days
                
                adoption_times[action] = {
                    'first_appearance': first_date.strftime('%Y-%m-%d'),
                    'adoption_date': adoption_date.strftime('%Y-%m-%d'),
                    'days_to_adopt': days_to_adopt
                }
        
        return adoption_times
    
    def _calculate_forecast_confidence(self, data: pd.DataFrame, model) -> float:
        """计算预测置信度"""
        try:
            from sklearn.metrics import r2_score
            
            X = data['date'].map(datetime.toordinal).values.reshape(-1, 1)
            y_true = data['usage_count'].values
            y_pred = model.predict(X)
            
            r2 = r2_score(y_true, y_pred)
            confidence = max(0, min(100, r2 * 100))  # 转换为百分比
            
            return float(confidence)
        except:
            return 50.0  # 默认置信度
    
    def _save_trend_analysis(self, analysis: Dict, trends_df: pd.DataFrame):
        """保存趋势分析结果"""
        # 保存分析结果
        save_json(
            analysis,
            str(self.processed_data_path / "trend_analysis.json")
        )
        
        # 保存时间序列数据
        if not trends_df.empty:
            trends_df.to_csv(
                str(self.processed_data_path / "time_series_analysis.csv"),
                index=False
            )
        
        self.logger.info("趋势分析结果已保存")