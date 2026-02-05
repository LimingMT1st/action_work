#!/bin/bash
# run_action_dependency_pipeline.sh
# Action 依赖分析专项管道

set -e

echo "========================================"
echo "Action 依赖分析专项管道"
echo "========================================"

# 检查配置文件
CONFIG_FILE="config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "错误: 配置文件不存在"
    exit 1
fi

# 安装依赖
pip install -r requirements.txt > /dev/null 2>&1

# 创建输出目录
mkdir -p output/visualizations/action_dependencies

# 设置环境变量
export PYTHONPATH=$(pwd):$PYTHONPATH

echo "开始 Action 依赖深度分析..."
echo "========================================"

# 1. 构建依赖图
echo "1. 构建依赖图..."
python -c "
import sys
sys.path.insert(0, '.')
from processors.graph_builder import GraphBuilder
from utils.file_utils import load_config

config = load_config('config.yaml')
builder = GraphBuilder(config)
graph = builder.build_action_dependency_graph()
print(f'依赖图构建完成: {graph.number_of_nodes() if graph else 0} 个节点')
"

# 2. 检测循环依赖
echo "2. 检测循环依赖..."
python -c "
import sys
sys.path.insert(0, '.')
from processors.action_dependency_resolver import ActionDependencyResolver
from utils.file_utils import load_config

config = load_config('config.yaml')
resolver = ActionDependencyResolver(config)
cycles = resolver.detect_circular_dependencies()
print(f'检测到 {len(cycles)} 个循环依赖')
"

# 3. 计算依赖指标
echo "3. 计算依赖指标..."
python -c "
import sys
sys.path.insert(0, '.')
from processors.action_dependency_resolver import ActionDependencyResolver
from utils.file_utils import load_config

config = load_config('config.yaml')
resolver = ActionDependencyResolver(config)
metrics = resolver.calculate_dependency_metrics()
print('依赖指标计算完成')
"

# 4. 分析供应链漏洞
echo "4. 分析供应链漏洞..."
python -c "
import sys
sys.path.insert(0, '.')
from analysis.action_dependency_analysis import ActionDependencyAnalysis
from utils.file_utils import load_config

config = load_config('config.yaml')
analyzer = ActionDependencyAnalysis(config)
vulnerabilities = analyzer.analyze_supply_chain_vulnerabilities()
print('供应链漏洞分析完成')
"

# 5. 生成可视化
echo "5. 生成可视化..."
python -c "
import sys
sys.path.insert(0, '.')
from visualizers.action_dependency_viewer import ActionDependencyViewer
from utils.file_utils import load_config

config = load_config('config.yaml')
viewer = ActionDependencyViewer(config)

# 可视化特定 action
example_action = 'actions/checkout'
viz = viewer.visualize_specific_action_dependencies(example_action)
if viz:
    print(f'{example_action} 依赖关系可视化已生成')

# 创建依赖探索器
explorer = viewer.create_dependency_explorer()
if explorer:
    print('依赖探索器已生成')

# 可视化依赖模式
patterns = viewer.visualize_dependency_patterns()
if patterns:
    print('依赖模式可视化已生成')
"

# 6. 生成健康评分
echo "6. 生成健康评分..."
python -c "
import sys
sys.path.insert(0, '.')
from analysis.action_dependency_analysis import ActionDependencyAnalysis
from utils.file_utils import load_config

config = load_config('config.yaml')
analyzer = ActionDependencyAnalysis(config)
health_scores = analyzer.generate_dependency_health_score()
print(f'依赖健康评分: {health_scores.get(\"overall_score\", 0)}/100')
"

echo "========================================"
echo "Action 依赖分析完成！"
echo ""
echo "输出文件:"
echo "  - 可视化: output/visualizations/action_dependencies/"
echo "  - 分析结果: data/processed/"
echo ""
echo "查看具体分析结果:"
echo "  cat data/processed/vulnerability_analysis.json | jq '.summary'"
echo "  cat data/processed/dependency_health_scores.json | jq '.overall_score'"
echo "========================================"