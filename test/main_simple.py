# main_simple.py
#!/usr/bin/env python3
"""
简单版本的主程序，避免导入问题
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def import_module_safely(module_name, class_name=None):
    """安全导入模块"""
    try:
        module = __import__(module_name, fromlist=[class_name] if class_name else [])
        if class_name:
            return getattr(module, class_name)
        return module
    except ImportError as e:
        print(f"导入错误: {e}")
        return None

def run_crawler_simple():
    """简单版本的爬虫运行函数"""
    print("运行爬虫模块...")
    
    # 直接导入需要的模块
    try:
        import yaml
        import json
        import requests
        
        # 加载配置文件
        config_path = "config.yaml"
        if not os.path.exists(config_path):
            print(f"配置文件不存在: {config_path}")
            return
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # 检查 token
        token = config['github']['token']
        if token == "your_github_personal_access_token_here":
            print("请先在 config.yaml 中配置 GitHub Personal Access Token")
            return
        
        print("配置加载成功")
        
        # 这里可以添加简单的爬虫逻辑
        print("爬虫模块准备就绪")
        
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("GitHub Actions 分析工具")
    
    # 如果提供了命令行参数
    if len(sys.argv) > 1:
        step = sys.argv[1]
        if step == "crawl":
            run_crawler_simple()
        else:
            print(f"未知步骤: {step}")
    else:
        run_crawler_simple()