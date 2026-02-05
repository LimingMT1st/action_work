# 爬取仓库中的 Actions 工作流文件
# crawler/actions_crawler.py
import time
import logging
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from pathlib import Path
import yaml

from utils.file_utils import save_json, ensure_dir
from .github_api_client import GitHubAPIClient

class ActionsCrawler:
    """Actions 爬取器 - 获取仓库中的 workflows"""
    
    def __init__(self, api_client: GitHubAPIClient, config: Dict):
        self.api = api_client
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # 配置
        self.max_workers = config['crawler']['max_workers']
        
        # 路径
        self.raw_data_path = Path(config['paths']['raw_data'])
        self.workflows_dir = self.raw_data_path / "workflows"
        ensure_dir(self.workflows_dir)
    
    def crawl_workflows_from_repos(self, repos: List[Dict]) -> Dict:
        """
        从仓库列表中爬取 workflows
        
        Args:
            repos: 仓库列表
            
        Returns:
            包含每个仓库 workflow 信息的字典
        """
        self.logger.info(f"开始从 {len(repos)} 个仓库爬取 workflows...")
        
        all_workflows = {}
        repo_workflows = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交任务
            future_to_repo = {
                executor.submit(self._crawl_single_repo_workflows, repo): repo
                for repo in repos[:200]  # 限制数量，避免过多 API 调用
            }
            
            # 处理结果
            for future in tqdm(as_completed(future_to_repo), total=len(future_to_repo)):
                repo = future_to_repo[future]
                try:
                    workflows = future.result(timeout=60)
                    if workflows:
                        full_name = repo['full_name']
                        repo_workflows[full_name] = workflows
                        
                        # 合并到总列表
                        for workflow in workflows:
                            workflow_id = workflow.get('id')
                            if workflow_id:
                                all_workflows[workflow_id] = {
                                    'repo': full_name,
                                    'name': workflow.get('name'),
                                    'path': workflow.get('path'),
                                    'state': workflow.get('state'),
                                    'created_at': workflow.get('created_at'),
                                    'updated_at': workflow.get('updated_at')
                                }
                        
                        # 定期保存进度
                        if len(repo_workflows) % 20 == 0:
                            self._save_workflows_progress(repo_workflows)
                            
                except Exception as e:
                    self.logger.error(f"爬取仓库 {repo['full_name']} 的 workflows 失败: {e}")
        
        # 保存最终结果
        self._save_final_results(repo_workflows, all_workflows)
        
        self.logger.info(f"成功爬取 {len(repo_workflows)} 个仓库的 workflows")
        return repo_workflows
    
    def _crawl_single_repo_workflows(self, repo: Dict) -> Optional[List[Dict]]:
        """爬取单个仓库的 workflows"""
        try:
            owner = repo['owner']
            repo_name = repo['name']
            full_name = repo['full_name']
            
            self.logger.debug(f"爬取仓库 {full_name} 的 workflows...")
            
            # 获取 workflows 列表
            workflows = self.api.get_workflows(owner, repo_name)
            if not workflows:
                return []
            
            # 获取每个 workflow 的内容
            detailed_workflows = []
            for workflow in workflows:
                workflow_path = workflow.get('path')
                if not workflow_path:
                    continue
                
                # 获取 workflow 文件内容
                content = self.api.get_workflow_content(owner, repo_name, workflow_path)
                if not content:
                    continue
                
                # 解析 workflow
                try:
                    workflow_yaml = yaml.safe_load(content)
                except yaml.YAMLError as e:
                    self.logger.warning(f"解析 {full_name}/{workflow_path} 失败: {e}")
                    workflow_yaml = {}
                
                # 保存 workflow 文件
                self._save_workflow_file(full_name, workflow_path, content)
                
                # 构建详细 workflow 信息
                detailed_workflow = {
                    'id': workflow.get('id'),
                    'name': workflow.get('name'),
                    'path': workflow_path,
                    'state': workflow.get('state'),
                    'created_at': workflow.get('created_at'),
                    'updated_at': workflow.get('updated_at'),
                    'content': content,
                    'parsed_yaml': workflow_yaml
                }
                detailed_workflows.append(detailed_workflow)
            
            # 避免速率限制
            time.sleep(0.5)
            
            return detailed_workflows
            
        except Exception as e:
            self.logger.error(f"爬取 {repo.get('full_name')} workflows 时出错: {e}")
            return None
    
    def _save_workflow_file(self, repo_full_name: str, workflow_path: str, content: str):
        """保存 workflow 文件到本地"""
        try:
            # 创建仓库目录
            repo_dir = self.workflows_dir / repo_full_name.replace('/', '_')
            ensure_dir(repo_dir)
            
            # 生成文件名（处理路径中的斜杠）
            filename = workflow_path.replace('/', '_')
            filepath = repo_dir / filename
            
            # 保存文件
            filepath.write_text(content, encoding='utf-8')
            
        except Exception as e:
            self.logger.error(f"保存 workflow 文件失败: {e}")
    
    def _save_workflows_progress(self, repo_workflows: Dict):
        """保存爬取进度"""
        temp_file = self.raw_data_path / "repo_workflows_temp.json"
        save_json(repo_workflows, str(temp_file))
        self.logger.debug(f"已保存临时进度到 {temp_file}")
    
    def _save_final_results(self, repo_workflows: Dict, all_workflows: Dict):
        """保存最终结果"""
        # 保存按仓库分组的 workflows
        repo_file = self.raw_data_path / "repo_workflows.json"
        save_json(repo_workflows, str(repo_file))
        
        # 保存所有 workflows 的索引
        all_file = self.raw_data_path / "all_workflows.json"
        save_json(all_workflows, str(all_file))
        
        # 保存统计信息
        stats = {
            'total_repos': len(repo_workflows),
            'total_workflows': len(all_workflows),
            'repos_with_workflows': list(repo_workflows.keys()),
            'timestamp': time.time()
        }
        
        stats_file = self.raw_data_path / "workflows_stats.json"
        save_json(stats, str(stats_file))
        
        self.logger.info(f"Workflows 数据已保存")
        self.logger.info(f"  仓库数量: {len(repo_workflows)}")
        self.logger.info(f"  Workflow 总数: {len(all_workflows)}")