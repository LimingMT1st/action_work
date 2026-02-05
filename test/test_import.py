# test_import.py
#!/usr/bin/env python3
"""
测试导入的脚本
"""

import sys
from pathlib import Path

# 添加当前目录到 Python 路径
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

print("测试导入模块...")

try:
    from crawler.github_api_client import GitHubAPIClient
    print("✓ 成功导入 GitHubAPIClient")
except ImportError as e:
    print(f"✗ 导入 GitHubAPIClient 失败: {e}")

try:
    from crawler.repo_crawler import RepoCrawler
    print("✓ 成功导入 RepoCrawler")
except ImportError as e:
    print(f"✗ 导入 RepoCrawler 失败: {e}")

try:
    from utils.file_utils import load_config
    print("✓ 成功导入 load_config")
except ImportError as e:
    print(f"✗ 导入 load_config 失败: {e}")

# 测试相对导入
print("\n测试相对导入...")
try:
    import crawler.github_api_client
    print("✓ 成功导入 crawler.github_api_client")
except ImportError as e:
    print(f"✗ 导入失败: {e}")