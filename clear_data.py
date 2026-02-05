# clear_data.py
#!/usr/bin/env python3
"""
数据清理工具 - 清理 GitHub Actions 分析过程中生成的数据

使用方法:
python clear_data.py --all              # 清理所有数据
python clear_data.py --crawled          # 仅清理爬取的数据
python clear_data.py --analysis         # 仅清理分析结果
python clear_data.py --logs             # 仅清理日志
python clear_data.py --status           # 查看存储使用情况
python clear_data.py --help             # 显示帮助信息
"""

import argparse
import sys
import logging
from pathlib import Path

# 添加项目根目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from utils.logging_config import setup_logging, get_logger
from utils.cleaner import DataCleaner

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='GitHub Actions 分析数据清理工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python clear_data.py --all              # 清理所有数据
  python clear_data.py --crawled          # 仅清理爬取的数据
  python clear_data.py --analysis         # 仅清理分析结果
  python clear_data.py --logs             # 仅清理日志
  python clear_data.py --status           # 查看存储使用情况
  python clear_data.py --config custom.yaml  # 使用自定义配置文件
        """
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='清理所有数据（爬取数据、分析结果、日志）'
    )
    
    parser.add_argument(
        '--crawled',
        action='store_true',
        help='仅清理爬取的数据'
    )
    
    parser.add_argument(
        '--analysis',
        action='store_true',
        help='仅清理分析结果'
    )
    
    parser.add_argument(
        '--logs',
        action='store_true',
        help='仅清理日志文件'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='查看存储使用情况'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='配置文件路径'
    )
    
    parser.add_argument(
        '--keep-logs',
        action='store_true',
        help='清理时保留日志文件（仅与 --all 一起使用）'
    )
    
    parser.add_argument(
        '--yes',
        '-y',
        action='store_true',
        help='自动确认，不显示确认提示'
    )
    
    parser.add_argument(
        '--output-report',
        type=str,
        help='将清理报告保存到指定文件'
    )
    
    args = parser.parse_args()
    
    # 检查是否有任何清理选项
    if not any([args.all, args.crawled, args.analysis, args.logs, args.status]):
        parser.print_help()
        print("\n错误: 请指定清理选项")
        sys.exit(1)
    
    # 设置日志
    setup_logging("logs", "INFO")
    logger = get_logger(__name__)
    
    try:
        # 初始化数据清理器
        cleaner = DataCleaner(args.config)
        
        # 查看存储使用情况
        if args.status:
            usage = cleaner.get_storage_usage()
            print("\n" + "=" * 60)
            print("存储使用情况")
            print("=" * 60)
            print(f"总使用空间: {usage.get('total_size_human', '0 B')}")
            print()
            
            if usage['directories']:
                print("各目录使用情况:")
                for dir_info in usage['directories']:
                    if dir_info['size'] > 0:
                        print(f"  {dir_info['path']}:")
                        print(f"    大小: {dir_info.get('size_human', '0 B')}")
                        print(f"    文件数: {dir_info['file_count']}")
                        print(f"    目录数: {dir_info['dir_count']}")
            
            if usage['file_types']:
                print("\n文件类型分布:")
                for file_type, type_info in usage['file_types'].items():
                    print(f"  {file_type}: {type_info['human']}")
            
            print("=" * 60)
            return
        
        # 确认清理操作
        if not args.yes:
            if args.all:
                print("\n警告: 这将清理所有数据，包括:")
                print("  - 爬取的原始数据")
                print("  - 分析结果和图表")
                print("  - 生成的报告")
                if not args.keep_logs:
                    print("  - 日志文件")
            elif args.crawled:
                print("\n警告: 这将清理所有爬取的数据")
            elif args.analysis:
                print("\n警告: 这将清理所有分析结果")
            elif args.logs:
                print("\n警告: 这将清理所有日志文件")
            
            confirm = input("\n确定要继续吗？(y/N): ")
            if confirm.lower() != 'y':
                print("清理操作已取消")
                return
        
        # 执行清理操作
        if args.all:
            logger.info("开始清理所有数据...")
            stats = cleaner.clear_all_data(keep_logs=args.keep_logs)
            operation = "all"
        
        elif args.crawled:
            logger.info("开始清理爬取数据...")
            stats = cleaner.clear_crawled_data_only()
            operation = "crawled"
        
        elif args.analysis:
            logger.info("开始清理分析结果...")
            stats = cleaner.clear_analysis_results_only()
            operation = "analysis"
        
        elif args.logs:
            logger.info("开始清理日志文件...")
            stats = cleaner.clear_logs_only()
            operation = "logs"
        
        else:
            return  # 理论上不会执行到这里
        
        # 生成清理报告
        report = cleaner.create_clean_report(stats)
        
        # 显示报告
        print("\n" + report)
        
        # 保存报告到文件
        if args.output_report:
            report_file = Path(args.output_report)
            report_file.parent.mkdir(parents=True, exist_ok=True)
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n清理报告已保存到: {report_file}")
        
        # 保存报告到默认位置
        default_report_file = Path(f"output/clean_report_{operation}_{cleaner._get_current_timestamp().replace(' ', '_').replace(':', '-')}.txt")
        default_report_file.parent.mkdir(parents=True, exist_ok=True)
        with open(default_report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"清理操作完成，报告保存到: {default_report_file}")
        
    except FileNotFoundError as e:
        print(f"错误: 配置文件不存在 - {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n用户中断操作")
        sys.exit(0)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()