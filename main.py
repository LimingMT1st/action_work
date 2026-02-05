# main.py
#!/usr/bin/env python3
"""
GitHub Actions 供应链分析工具主程序

功能：
1. 爬取 GitHub 热门仓库和 Actions
2. 分析依赖关系和供应链风险
3. 生成可视化图表和报告
4. 提供安全建议和最佳实践

使用方法：
python main.py --step all  # 运行所有步骤
python main.py --step crawl  # 仅运行爬虫
python main.py --step process  # 仅运行数据处理
python main.py --step analyze  # 仅运行分析
python main.py --step visualize  # 仅运行可视化
python main.py --step report  # 仅生成报告
"""

import argparse
import sys
import os
import logging
from pathlib import Path


# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def import_module_safely(module_path, class_name=None):
    """安全导入模块"""
    try:
        if "." in module_path:
            # 处理点分导入，如 "crawler.github_api_client"
            parts = module_path.split(".")
            module = __import__(parts[0])
            for part in parts[1:]:
                module = getattr(module, part)
        else:
            module = __import__(module_path)
        
        if class_name:
            return getattr(module, class_name)
        return module
    except ImportError as e:
        print(f"导入错误 {module_path}: {e}")
        return None
    except AttributeError as e:
        print(f"属性错误 {module_path}.{class_name}: {e}")
        return None

class GitHubActionsAnalyzer:
    """GitHub Actions 分析器主类"""
    
    def __init__(self, config_path="config.yaml"):
        """
        初始化分析器
        
        Args:
            config_path: 配置文件路径
        """
        self.config_path = config_path
        self.config = None
        self.api_client = None
        self.modules = {}
        
        print("初始化 GitHub Actions 分析器...")
        self._load_config()
        self._setup_logging()
        
    def _load_config(self):
        """加载配置文件"""
        try:
            from utils.file_utils import load_config
            self.config = load_config(self.config_path)
            print(f"配置文件加载成功: {self.config_path}")
        except Exception as e:
            print(f"加载配置文件失败: {e}")
            sys.exit(1)
        
        # 检查 GitHub token
        token = self.config['github']['token']
        if token == "your_github_personal_access_token_here":
            print("错误: 请在 config.yaml 中配置 GitHub Personal Access Token")
            sys.exit(1)
    
    def _setup_logging(self):
        """设置日志"""
        try:
            from utils.logging_config import setup_logging
            log_dir = Path(self.config['paths']['logs'])
            log_dir.mkdir(parents=True, exist_ok=True)
            setup_logging(str(log_dir), "INFO")
            self.logger = logging.getLogger(__name__)
            print(f"日志系统初始化完成，日志目录: {log_dir}")
        except Exception as e:
            print(f"日志初始化失败: {e}")
            # 使用基础日志
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            self.logger = logging.getLogger(__name__)
    
    def _init_github_client(self):
        """初始化 GitHub API 客户端"""
        try:
            from crawler.github_api_client import GitHubAPIClient
            self.api_client = GitHubAPIClient(
                token=self.config['github']['token'],
                rate_limit_wait=self.config['github']['rate_limit_wait'],
                max_retries=self.config['github']['max_retries']
            )
            
            # 测试连接
            if self.api_client.test_connection():
                print("GitHub API 客户端初始化成功")
                return True
            else:
                print("GitHub API 连接测试失败")
                return False
        except Exception as e:
            print(f"初始化 GitHub API 客户端失败: {e}")
            return False
    
    def run_crawler(self):
        """运行爬虫模块"""
        print("\n" + "="*60)
        print("开始运行爬虫模块")
        print("="*60)
        
        try:
            # 初始化 GitHub 客户端
            if not self._init_github_client():
                return False
            
            # 导入爬虫模块
            from crawler.repo_crawler import RepoCrawler
            from crawler.actions_crawler import ActionsCrawler
            from crawler.dependency_extractor import DependencyExtractor
            from crawler.action_dependency_crawler import ActionDependencyCrawler
            
            print("1. 创建爬虫实例...")
            repo_crawler = RepoCrawler(self.api_client, self.config)
            actions_crawler = ActionsCrawler(self.api_client, self.config)
            dependency_extractor = DependencyExtractor(self.config)
            
            # 1. 爬取热门仓库
            print("\n2. 爬取热门仓库...")
            top_repos_count = min(50, self.config['crawler']['top_repos_count'])  # 先爬取少量用于测试
            self.config['crawler']['top_repos_count'] = top_repos_count
            top_repos = repo_crawler.crawl_top_repositories()
            print(f"  爬取完成: {len(top_repos)} 个仓库")
            
            if not top_repos:
                print("  错误: 没有爬取到仓库数据")
                return False
            
            # 2. 爬取 workflows
            print("\n3. 爬取仓库 workflows...")
            # 只爬取前20个仓库的 workflows 用于测试
            test_repos = top_repos[:20]
            workflows_data = actions_crawler.crawl_workflows_from_repos(test_repos)
            print(f"  爬取完成: {len(workflows_data)} 个仓库的 workflows")
            
            if not workflows_data:
                print("  警告: 没有爬取到 workflows 数据")
            
            # 3. 提取依赖关系
            print("\n4. 提取依赖关系...")
            if workflows_data:
                dependencies = dependency_extractor.extract_from_workflows(workflows_data)
                if dependencies:
                    print(f"  提取完成: {dependencies.get('total_unique_actions', 0)} 个唯一 actions")
                    
                    # 保存到模块缓存
                    self.modules['dependencies'] = dependencies
                    
                    # 4. 爬取 Action 嵌套依赖
                    print("\n5. 爬取 Action 嵌套依赖...")
                    action_deps_crawler = ActionDependencyCrawler(self.api_client, self.config)
                    
                    # 获取高频 actions
                    action_usage = dependencies.get('action_usage_stats', [])
                    if action_usage and len(action_usage) > 0:
                        # 只分析前10个高频 actions
                        top_actions = action_usage[:10]
                        action_dependencies = action_deps_crawler.crawl_action_dependencies(top_actions)
                        if action_dependencies:
                            print(f"  嵌套依赖分析完成: {len(action_dependencies.get('dependencies', {}))} 个 actions")
                            self.modules['action_dependencies'] = action_dependencies
                else:
                    print("  警告: 没有提取到依赖关系")
            
            print("\n" + "="*60)
            print("爬虫模块执行完成!")
            print("="*60)
            return True
            
        except Exception as e:
            print(f"\n爬虫模块执行失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_processor(self):
        """运行处理模块"""
        print("\n" + "="*60)
        print("开始运行处理模块")
        print("="*60)
        
        try:
            from processors.graph_builder import GraphBuilder
            from processors.time_series_analyzer import TimeSeriesAnalyzer
            
            print("1. 创建处理器实例...")
            graph_builder = GraphBuilder(self.config)
            time_series_analyzer = TimeSeriesAnalyzer(self.config)
            
            # 1. 构建依赖图
            print("\n2. 构建依赖图...")
            repo_action_graph = graph_builder.build_repo_action_graph()
            if repo_action_graph:
                print(f"  仓库-Action 依赖图构建完成: {repo_action_graph.number_of_nodes()} 个节点")
                self.modules['repo_action_graph'] = repo_action_graph
            
            action_dependency_graph = graph_builder.build_action_dependency_graph()
            if action_dependency_graph:
                print(f"  Action-Action 依赖图构建完成: {action_dependency_graph.number_of_nodes()} 个节点")
                self.modules['action_dependency_graph'] = action_dependency_graph
            
            # 2. 分析图指标
            print("\n3. 分析图指标...")
            if action_dependency_graph:
                metrics = graph_builder.analyze_graph_metrics(action_dependency_graph)
                if metrics:
                    print(f"  图指标分析完成: {metrics.get('basic', {}).get('nodes', 0)} 个节点")
                    self.modules['graph_metrics'] = metrics
            
            # 3. 检测社区结构
            print("\n4. 检测社区结构...")
            if action_dependency_graph:
                communities = graph_builder.detect_communities(action_dependency_graph)
                if communities:
                    print(f"  社区检测完成: {communities.get('num_communities', 0)} 个社区")
                    self.modules['communities'] = communities
            
            # 4. 时间序列分析
            print("\n5. 时间序列分析...")
            # 尝试加载依赖数据
            try:
                from utils.file_utils import load_json
                dependencies_file = Path(self.config['paths']['raw_data']) / "dependencies.json"
                if dependencies_file.exists():
                    dependencies_data = load_json(str(dependencies_file))
                    if dependencies_data:
                        trends = time_series_analyzer.analyze_usage_trends(dependencies_data)
                        if trends is not None:
                            print("  时间序列分析完成")
                            self.modules['trends'] = trends
            except Exception as e:
                print(f"  时间序列分析跳过: {e}")
            
            print("\n" + "="*60)
            print("处理模块执行完成!")
            print("="*60)
            return True
            
        except Exception as e:
            print(f"\n处理模块执行失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_analyzer(self):
        """运行分析器模块"""
        print("\n" + "="*60)
        print("开始运行分析器模块")
        print("="*60)
        
        try:
            from processors.security_analyzer import SecurityAnalyzer
            from processors.action_dependency_resolver import ActionDependencyResolver
            from analysis.action_dependency_analysis import ActionDependencyAnalysis
            
            print("1. 创建分析器实例...")
            security_analyzer = SecurityAnalyzer(self.config)
            dependency_resolver = ActionDependencyResolver(self.config)
            dependency_analysis = ActionDependencyAnalysis(self.config)
            
            # 1. 安全分析
            print("\n2. 安全分析...")
            try:
                from utils.file_utils import load_json
                workflows_file = Path(self.config['paths']['raw_data']) / "repo_workflows.json"
                if workflows_file.exists():
                    workflows_data = load_json(str(workflows_file))
                    if workflows_data:
                        security_findings = security_analyzer.analyze_workflow_security(workflows_data)
                        if security_findings:
                            risky_count = security_findings.get('summary', {}).get('risky_workflows', 0)
                            print(f"  安全分析完成: 发现 {risky_count} 个高风险 workflows")
                            self.modules['security_findings'] = security_findings
                            
                            # 检测 secrets
                            secrets = security_analyzer.detect_secrets_in_workflows(workflows_data)
                            if secrets:
                                print(f"  Secrets 检测完成: 发现 {len(secrets)} 个潜在秘密")
                                self.modules['secrets'] = secrets
                else:
                    print("  跳过安全分析: 未找到 workflows 数据文件")
            except Exception as e:
                print(f"  安全分析跳过: {e}")
            
            # 2. 依赖解析
            print("\n3. 依赖解析...")
            try:
                example_action = "actions/checkout"
                dependency_resolution = dependency_resolver.resolve_dependencies(example_action)
                if dependency_resolution:
                    print(f"  依赖解析完成: {example_action}")
                    self.modules['dependency_resolution'] = dependency_resolution
            except Exception as e:
                print(f"  依赖解析跳过: {e}")
            
            # 3. 供应链漏洞分析
            print("\n4. 供应链漏洞分析...")
            try:
                vulnerabilities = dependency_analysis.analyze_supply_chain_vulnerabilities()
                if vulnerabilities:
                    single_points = len(vulnerabilities.get('single_points_of_failure', []))
                    print(f"  供应链漏洞分析完成: 发现 {single_points} 个单点故障")
                    self.modules['vulnerabilities'] = vulnerabilities
            except Exception as e:
                print(f"  供应链漏洞分析跳过: {e}")
            
            print("\n" + "="*60)
            print("分析器模块执行完成!")
            print("="*60)
            return True
            
        except Exception as e:
            print(f"\n分析器模块执行失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_visualizer(self):
        """运行可视化模块"""
        print("\n" + "="*60)
        print("开始运行可视化模块")
        print("="*60)
        
        try:
            from visualizers.graph_visualizer import GraphVisualizer
            from visualizers.time_series_plotter import TimeSeriesPlotter
            from visualizers.security_dashboard import SecurityDashboard
            from visualizers.action_dependency_viewer import ActionDependencyViewer
            
            print("1. 创建可视化器实例...")
            graph_visualizer = GraphVisualizer(self.config)
            time_series_plotter = TimeSeriesPlotter(self.config)
            security_dashboard = SecurityDashboard(self.config)
            action_dependency_viewer = ActionDependencyViewer(self.config)
            
            visualization_results = {}
            
            # 1. 图可视化
            print("\n2. 生成图可视化...")
            try:
                repo_action_viz = graph_visualizer.visualize_repo_action_graph(interactive=True)
                if repo_action_viz:
                    print(f"  仓库-Action 图可视化: {repo_action_viz}")
                    visualization_results['repo_action'] = repo_action_viz
                
                action_dep_viz = graph_visualizer.visualize_action_dependency_graph(interactive=True)
                if action_dep_viz:
                    print(f"  Action 依赖图可视化: {action_dep_viz}")
                    visualization_results['action_dependency'] = action_dep_viz
            except Exception as e:
                print(f"  图可视化跳过: {e}")
            
            # 2. 中心性指标可视化
            print("\n3. 生成中心性指标可视化...")
            try:
                centrality_viz = graph_visualizer.visualize_centrality_metrics()
                if centrality_viz:
                    print(f"  中心性指标可视化: {len(centrality_viz)} 个文件")
                    visualization_results['centrality'] = centrality_viz
            except Exception as e:
                print(f"  中心性指标可视化跳过: {e}")
            
            # 3. 时间序列可视化
            print("\n4. 生成时间序列可视化...")
            try:
                time_series_viz = time_series_plotter.plot_usage_trends()
                if time_series_viz:
                    print(f"  时间序列可视化: {len(time_series_viz)} 个文件")
                    visualization_results['time_series'] = time_series_viz
            except Exception as e:
                print(f"  时间序列可视化跳过: {e}")
            
            # 4. 安全仪表板
            print("\n5. 生成安全仪表板...")
            try:
                dashboard = security_dashboard.create_security_dashboard()
                if dashboard:
                    print(f"  安全仪表板: {dashboard}")
                    visualization_results['security_dashboard'] = dashboard
            except Exception as e:
                print(f"  安全仪表板跳过: {e}")
            
            self.modules['visualizations'] = visualization_results
            
            print("\n" + "="*60)
            print("可视化模块执行完成!")
            print(f"生成 {len(visualization_results)} 类可视化文件")
            print("="*60)
            return True
            
        except Exception as e:
            print(f"\n可视化模块执行失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_reporter(self):
        """运行报告生成模块"""
        print("\n" + "="*60)
        print("开始运行报告生成模块")
        print("="*60)
        
        try:
            from analysis.supply_chain_risk_report import SupplyChainRiskReport
            from analysis.recommendations import SecurityRecommendations
            from analysis.action_dependency_analysis import ActionDependencyAnalysis
            
            print("1. 创建报告生成器实例...")
            supply_chain_report = SupplyChainRiskReport(self.config)
            security_recommendations = SecurityRecommendations(self.config)
            dependency_analysis = ActionDependencyAnalysis(self.config)
            
            report_results = {}
            
            # 1. 生成供应链风险报告
            print("\n2. 生成供应链风险报告...")
            try:
                report = supply_chain_report.generate_report('comprehensive')
                if report:
                    print(f"  供应链风险报告生成完成")
                    report_results['supply_chain_report'] = report
            except Exception as e:
                print(f"  供应链风险报告跳过: {e}")
            
            # 2. 生成组织建议
            print("\n3. 生成组织建议...")
            try:
                recommendations = security_recommendations.generate_organization_recommendations()
                if recommendations:
                    print(f"  组织建议生成完成")
                    report_results['recommendations'] = recommendations
            except Exception as e:
                print(f"  组织建议跳过: {e}")
            
            # 3. 生成依赖健康评分
            print("\n4. 生成依赖健康评分...")
            try:
                health_scores = dependency_analysis.generate_dependency_health_score()
                if health_scores:
                    score = health_scores.get('overall_score', 0)
                    print(f"  依赖健康评分: {score}/100")
                    report_results['health_scores'] = health_scores
            except Exception as e:
                print(f"  依赖健康评分跳过: {e}")
            
            self.modules['reports'] = report_results
            
            print("\n" + "="*60)
            print("报告生成模块执行完成!")
            print(f"生成 {len(report_results)} 类报告")
            print("="*60)
            return True
            
        except Exception as e:
            print(f"\n报告生成模块执行失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_all(self):
        """运行所有模块"""
        print("\n" + "="*60)
        print("开始运行完整分析流程")
        print("="*60)
        
        success_count = 0
        total_steps = 5
        
        # 运行爬虫
        if self.run_crawler():
            success_count += 1
        
        # 运行处理
        if self.run_processor():
            success_count += 1
        
        # 运行分析
        if self.run_analyzer():
            success_count += 1
        
        # 运行可视化
        if self.run_visualizer():
            success_count += 1
        
        # 运行报告
        if self.run_reporter():
            success_count += 1
        
        print("\n" + "="*60)
        print("完整分析流程执行完成!")
        print(f"成功步骤: {success_count}/{total_steps}")
        
        # 生成执行摘要
        self._generate_executive_summary()
        
        print("="*60)
        return success_count == total_steps
    
    def _generate_executive_summary(self):
        """生成执行摘要"""
        try:
            summary_file = Path("output/executive_summary.md")
            summary_file.parent.mkdir(parents=True, exist_ok=True)
            
            summary = """# GitHub Actions 供应链分析执行摘要

## 分析概览
- **分析时间**: 自动生成
- **分析范围**: GitHub Actions 供应链安全
- **工具版本**: 1.0.0

## 模块执行情况
"""
            
            # 添加模块状态
            modules_status = {
                '爬虫模块': 'repo_action_graph' in self.modules,
                '处理模块': 'graph_metrics' in self.modules,
                '分析模块': 'security_findings' in self.modules,
                '可视化模块': 'visualizations' in self.modules,
                '报告模块': 'reports' in self.modules
            }
            
            for module, status in modules_status.items():
                summary += f"- {module}: {'✓ 成功' if status else '✗ 未完成'}\n"
            
            summary += "\n## 关键发现\n"
            
            # 添加安全发现
            if 'security_findings' in self.modules:
                findings = self.modules['security_findings']
                risky_count = findings.get('summary', {}).get('risky_workflows', 0)
                summary += f"- 发现 {risky_count} 个高风险 workflows\n"
            
            # 添加依赖发现
            if 'vulnerabilities' in self.modules:
                vulns = self.modules['vulnerabilities']
                single_points = len(vulns.get('single_points_of_failure', []))
                summary += f"- 识别 {single_points} 个供应链单点故障\n"
            
            summary += "\n## 建议\n"
            summary += "1. 立即审查并固定所有 Action 版本\n"
            summary += "2. 实施最小权限原则配置 workflows\n"
            summary += "3. 建立供应链安全监控机制\n"
            summary += "4. 定期进行依赖安全审计\n"
            
            summary += "\n---\n"
            summary += "*报告自动生成，详细信息请查看各模块输出文件*"
            
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(summary)
            
            print(f"执行摘要已保存到: {summary_file}")
            
        except Exception as e:
            print(f"生成执行摘要失败: {e}")
    

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='GitHub Actions 供应链分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py --step all           # 运行完整分析流程
  python main.py --step crawl         # 仅运行数据爬取
  python main.py --step process       # 仅运行数据处理
  python main.py --step analyze       # 仅运行安全分析
  python main.py --step visualize     # 仅生成可视化图表
  python main.py --step report        # 仅生成报告
  python main.py --config custom.yaml # 使用自定义配置文件
        """
    )
    
    parser.add_argument(
        '--step',
        type=str,
        default='all',
        choices=['all', 'crawl', 'process', 'analyze', 'visualize', 'report'],
        help='运行特定步骤或所有步骤'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='配置文件路径'
    )
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("GitHub Actions 供应链分析工具")
    print(f"版本: 1.0.0")
    print(f"步骤: {args.step}")
    print(f"配置: {args.config}")
    print("="*60)
    
    try:
        # 初始化分析器
        analyzer = GitHubActionsAnalyzer(args.config)
        
        # 运行指定步骤
        if args.step == 'all':
            analyzer.run_all()
        elif args.step == 'crawl':
            analyzer.run_crawler()
        elif args.step == 'process':
            analyzer.run_processor()
        elif args.step == 'analyze':
            analyzer.run_analyzer()
        elif args.step == 'visualize':
            analyzer.run_visualizer()
        elif args.step == 'report':
            analyzer.run_reporter()
        else:
            print(f"未知步骤: {args.step}")
            
    except KeyboardInterrupt:
        print("\n\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"\n程序执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()