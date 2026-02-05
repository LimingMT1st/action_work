#数据校验
# utils/validation.py
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

def validate_github_url(url: str) -> bool:
    """验证 GitHub URL 格式"""
    patterns = [
        r'^https://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+(/.*)?$',
        r'^github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+$',
        r'^[a-zA-Z0-9-]+/[a-zA-Z0-9-_.]+$'  # owner/repo 格式
    ]
    
    for pattern in patterns:
        if re.match(pattern, url):
            return True
    return False

def parse_action_reference(action_ref: str) -> Optional[Tuple[str, str, str]]:
    """
    解析 Action 引用字符串
    
    Args:
        action_ref: 如 "actions/checkout@v3" 或 "owner/repo@v1.2.3"
        
    Returns:
        tuple: (owner, repo, version) 或 None
    """
    # 移除可能的路径前缀
    if action_ref.startswith('./'):
        return None
    
    # 匹配 owner/repo@version 格式
    pattern = r'^([a-zA-Z0-9-]+)/([a-zA-Z0-9-_.]+)(?:@([a-zA-Z0-9._-]+))?$'
    match = re.match(pattern, action_ref)
    
    if match:
        owner, repo, version = match.groups()
        return owner, repo, version or 'latest'
    
    return None

def validate_workflow_yaml(content: dict) -> bool:
    """验证 workflow YAML 结构"""
    required_keys = ['name', 'on', 'jobs']
    
    if not isinstance(content, dict):
        return False
    
    for key in required_keys:
        if key not in content:
            return False
    
    return True

def is_sensitive_variable(var_name: str, patterns: list = None) -> bool:
    """检查变量名是否可能包含敏感信息"""
    if patterns is None:
        patterns = [
            'SECRET', 'TOKEN', 'PASSWORD', 'KEY', 
            'AWS_', 'AZURE_', 'GCP_', 'API_',
            'PRIVATE', 'ACCESS', 'CREDENTIAL'
        ]
    
    var_upper = var_name.upper()
    return any(pattern in var_upper for pattern in patterns)

def validate_github_token(token: str) -> bool:
    """基本验证 GitHub token 格式"""
    # GitHub token 通常是 40 个字符的十六进制字符串
    # 但较新的 token 格式可能不同
    if not token or len(token) < 20:
        return False
    return True