# GitHub API 客户端封装（认证、请求、限流处理）
# crawler/github_api_client.py
import requests
import time
import logging
from typing import Optional, Dict, Any, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timedelta

class GitHubAPIClient:
    """GitHub API 客户端封装"""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: str, rate_limit_wait: int = 60, max_retries: int = 3):
        """
        初始化 GitHub API 客户端
        
        Args:
            token: GitHub Personal Access Token
            rate_limit_wait: 限流等待时间(秒)
            max_retries: 最大重试次数
        """
        self.token = token
        self.rate_limit_wait = rate_limit_wait
        self.logger = logging.getLogger(__name__)
        
        # 设置会话
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Actions-Analysis/1.0'
        })
        
        # 设置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        
        # 速率限制信息
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = datetime.now()
        
    def _handle_rate_limit(self) -> None:
        """处理速率限制"""
        if self.rate_limit_remaining <= 10:
            wait_time = (self.rate_limit_reset - datetime.now()).total_seconds()
            if wait_time > 0:
                self.logger.warning(f"Rate limit接近耗尽，等待 {wait_time:.1f} 秒")
                time.sleep(wait_time + 1)
    
    def _update_rate_limit(self, headers: Dict) -> None:
        """更新速率限制信息"""
        if 'X-RateLimit-Remaining' in headers:
            self.rate_limit_remaining = int(headers['X-RateLimit-Remaining'])
        
        if 'X-RateLimit-Reset' in headers:
            reset_timestamp = int(headers['X-RateLimit-Reset'])
            self.rate_limit_reset = datetime.fromtimestamp(reset_timestamp)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """发送 API 请求"""
        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        
        self._handle_rate_limit()
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            # 更新速率限制信息
            self._update_rate_limit(response.headers)
            
            # 记录 API 调用
            self.logger.debug(f"API Call: {method} {endpoint} - Status: {response.status_code}")
            
            return response.json() if response.content else {}
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API请求失败: {method} {endpoint} - {e}")
            
            # 检查是否是速率限制
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 403 and 'X-RateLimit-Remaining' in e.response.headers:
                    if int(e.response.headers['X-RateLimit-Remaining']) == 0:
                        reset_time = datetime.fromtimestamp(
                            int(e.response.headers['X-RateLimit-Reset'])
                        )
                        wait_time = (reset_time - datetime.now()).total_seconds()
                        self.logger.warning(f"速率限制触发，等待 {wait_time:.1f} 秒")
                        time.sleep(wait_time + 1)
                        return self._make_request(method, endpoint, **kwargs)
            
            return None
    
    def get(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """发送 GET 请求"""
        return self._make_request('GET', endpoint, params=params)
    
    def post(self, endpoint: str, data: Dict = None) -> Optional[Dict]:
        """发送 POST 请求"""
        return self._make_request('POST', endpoint, json=data)
    
    def search_repositories(self, query: str, sort: str = 'stars', order: str = 'desc', 
                           per_page: int = 100, page: int = 1) -> Dict:
        """搜索仓库"""
        endpoint = "search/repositories"
        params = {
            'q': query,
            'sort': sort,
            'order': order,
            'per_page': per_page,
            'page': page
        }
        return self.get(endpoint, params=params) or {}
    
    def get_repository(self, owner: str, repo: str) -> Optional[Dict]:
        """获取仓库信息"""
        endpoint = f"repos/{owner}/{repo}"
        return self.get(endpoint)
    
    def get_workflows(self, owner: str, repo: str) -> List[Dict]:
        """获取仓库的 workflows"""
        endpoint = f"repos/{owner}/{repo}/actions/workflows"
        result = self.get(endpoint)
        return result.get('workflows', []) if result else []
    
    def get_workflow_content(self, owner: str, repo: str, workflow_path: str) -> Optional[str]:
        """获取 workflow 文件内容"""
        endpoint = f"repos/{owner}/{repo}/contents/{workflow_path}"
        result = self.get(endpoint)
        
        if result and 'content' in result:
            import base64
            content = base64.b64decode(result['content']).decode('utf-8')
            return content
        
        return None
    
    def get_repo_contents(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """获取仓库目录内容"""
        endpoint = f"repos/{owner}/{repo}/contents/{path}"
        result = self.get(endpoint)
        return result if isinstance(result, list) else []
    
    def get_action_files(self, owner: str, repo: str) -> Dict:
        """获取 Action 相关文件"""
        files = {}
        
        # 检查 action.yml 或 action.yaml
        for filename in ['action.yml', 'action.yaml']:
            content = self.get_workflow_content(owner, repo, filename)
            if content:
                files[filename] = content
        
        # 检查 Dockerfile
        docker_content = self.get_workflow_content(owner, repo, 'Dockerfile')
        if docker_content:
            files['Dockerfile'] = docker_content
        
        return files
    
    def test_connection(self) -> bool:
        """测试 API 连接"""
        try:
            response = self.get("rate_limit")
            return response is not None and 'resources' in response
        except Exception:
            return False