# 爬取前1000个热门仓库（按星数/项目流行度）
# crawler/repo_crawler.py
import time
import logging
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from utils.file_utils import save_json, ensure_dir
# from .github_api_client import GitHubAPIClient
try:
    from .github_api_client import GitHubAPIClient
except ImportError:
    # 如果相对导入失败，尝试绝对导入
    from crawler.github_api_client import GitHubAPIClient
    
class RepoCrawler:
    """仓库爬取器 - 获取热门 GitHub 仓库"""
    
    def __init__(self, api_client: GitHubAPIClient, config: Dict):
        self.api = api_client
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 爬取配置
        self.top_repos_count = config['crawler']['top_repos_count']
        self.min_stars = config['crawler']['min_stars']
        self.languages = config['crawler']['languages']
        self.max_workers = config['crawler']['max_workers']
        
        # 输出路径
        self.raw_data_path = config['paths']['raw_data']
        ensure_dir(self.raw_data_path)
    
    def crawl_top_repositories(self) -> List[Dict]:
        """爬取热门仓库列表"""
        self.logger.info(f"开始爬取前 {self.top_repos_count} 个热门仓库...")
        
        all_repos = []
        per_page = 100  # GitHub API 每页最大数量
        pages_needed = (self.top_repos_count + per_page - 1) // per_page
        
        for page in range(1, pages_needed + 1):
            self.logger.info(f"爬取第 {page} 页仓库...")
            
            # 构建搜索查询
            query_parts = [f"stars:>={self.min_stars}"]
            if self.languages:
                lang_query = " OR ".join([f"language:{lang}" for lang in self.languages])
                query_parts.append(f"({lang_query})")
            
            query = " ".join(query_parts)
            
            # 搜索仓库
            result = self.api.search_repositories(
                query=query,
                sort='stars',
                order='desc',
                per_page=per_page,
                page=page
            )
            
            if not result or 'items' not in result:
                self.logger.warning(f"第 {page} 页搜索失败或无结果")
                break
            
            repos = result['items']
            all_repos.extend(repos)
            
            # 保存进度
            if page % 5 == 0:
                self._save_progress(all_repos)
            
            # 避免速率限制
            time.sleep(1)
            
            # 如果已获取足够数量，则停止
            if len(all_repos) >= self.top_repos_count:
                all_repos = all_repos[:self.top_repos_count]
                break
        
        # 处理并保存最终结果
        processed_repos = self._process_repositories(all_repos)
        self._save_final_results(processed_repos)
        
        self.logger.info(f"成功爬取 {len(processed_repos)} 个仓库")
        return processed_repos
    
    def _process_repositories(self, repos: List[Dict]) -> List[Dict]:
        """处理仓库数据，提取所需信息"""
        processed = []
        
        for repo in repos:
            processed_repo = {
                'id': repo.get('id'),
                'name': repo.get('name'),
                'full_name': repo.get('full_name'),
                'owner': repo.get('owner', {}).get('login'),
                'description': repo.get('description'),
                'html_url': repo.get('html_url'),
                'language': repo.get('language'),
                'stars': repo.get('stargazers_count', 0),
                'forks': repo.get('forks_count', 0),
                'watchers': repo.get('watchers_count', 0),
                'created_at': repo.get('created_at'),
                'updated_at': repo.get('updated_at'),
                'pushed_at': repo.get('pushed_at'),
                'size': repo.get('size', 0),
                'open_issues': repo.get('open_issues_count', 0),
                'license': repo.get('license', {}).get('key') if repo.get('license') else None,
                'topics': repo.get('topics', []),
                'has_issues': repo.get('has_issues', False),
                'has_projects': repo.get('has_projects', False),
                'has_downloads': repo.get('has_downloads', False),
                'has_wiki': repo.get('has_wiki', False),
                'has_pages': repo.get('has_pages', False),
                'archived': repo.get('archived', False),
                'disabled': repo.get('disabled', False),
                'fork': repo.get('fork', False)
            }
            processed.append(processed_repo)
        
        # 按星数排序
        processed.sort(key=lambda x: x['stars'], reverse=True)
        return processed
    
    def crawl_repository_details(self, repos: List[Dict]) -> List[Dict]:
        """并行获取仓库的详细信息"""
        self.logger.info("开始获取仓库详细信息...")
        
        detailed_repos = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交任务
            future_to_repo = {
                executor.submit(self._get_repo_details, repo): repo
                for repo in repos[:100]  # 限制数量，避免过多 API 调用
            }
            
            # 处理结果
            for future in tqdm(as_completed(future_to_repo), total=len(future_to_repo)):
                repo = future_to_repo[future]
                try:
                    details = future.result(timeout=30)
                    if details:
                        detailed_repos.append(details)
                except Exception as e:
                    self.logger.error(f"获取仓库 {repo['full_name']} 详情失败: {e}")
        
        return detailed_repos
    
    def _get_repo_details(self, repo: Dict) -> Optional[Dict]:
        """获取单个仓库的详细信息"""
        try:
            owner = repo['owner']
            repo_name = repo['name']
            
            # 获取 README
            readme_content = self._get_readme(owner, repo_name)
            
            # 获取贡献者信息（前5个）
            contributors = self._get_contributors(owner, repo_name, count=5)
            
            # 获取最新发布
            latest_release = self._get_latest_release(owner, repo_name)
            
            # 合并信息
            repo_details = repo.copy()
            repo_details['readme_summary'] = readme_content[:500] if readme_content else ''
            repo_details['contributors'] = contributors
            repo_details['latest_release'] = latest_release
            
            return repo_details
            
        except Exception as e:
            self.logger.error(f"处理仓库 {repo.get('full_name')} 时出错: {e}")
            return None
    
    def _get_readme(self, owner: str, repo: str) -> Optional[str]:
        """获取 README 内容"""
        try:
            content = self.api.get_workflow_content(owner, repo, "README.md")
            return content
        except Exception:
            return None
    
    def _get_contributors(self, owner: str, repo: str, count: int = 5) -> List[Dict]:
        """获取贡献者列表"""
        try:
            endpoint = f"repos/{owner}/{repo}/contributors"
            result = self.api.get(endpoint, params={'per_page': count})
            if isinstance(result, list):
                return [{'login': c.get('login'), 'contributions': c.get('contributions')} 
                       for c in result[:count]]
        except Exception:
            pass
        return []
    
    def _get_latest_release(self, owner: str, repo: str) -> Optional[Dict]:
        """获取最新发布"""
        try:
            endpoint = f"repos/{owner}/{repo}/releases/latest"
            result = self.api.get(endpoint)
            if result:
                return {
                    'tag_name': result.get('tag_name'),
                    'name': result.get('name'),
                    'published_at': result.get('published_at')
                }
        except Exception:
            pass
        return None
    
    def _save_progress(self, repos: List[Dict]):
        """保存爬取进度"""
        temp_file = f"{self.raw_data_path}/top_repos_temp.json"
        save_json(repos, temp_file)
        self.logger.debug(f"已保存临时进度到 {temp_file}")
    
    def _save_final_results(self, repos: List[Dict]):
        """保存最终结果"""
        output_file = f"{self.raw_data_path}/top_repos.json"
        save_json(repos, output_file)
        self.logger.info(f"仓库列表已保存到 {output_file}")
        
        # 同时保存简化版本用于后续处理
        simple_repos = [{
            'full_name': r['full_name'],
            'owner': r['owner'],
            'name': r['name'],
            'stars': r['stars'],
            'language': r['language']
        } for r in repos]
        
        simple_file = f"{self.raw_data_path}/top_repos_simple.json"
        save_json(simple_repos, simple_file)