# 【新增】专门解析 action.yml 和复合 action 依赖
# utils/action_parser.py
import yaml
import re
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

class ActionParser:
    """解析 GitHub Action 文件的工具类"""
    
    def __init__(self):
        self.action_patterns = {
            'uses': r'^\s*uses:\s*(.+)$',
            'composite': r'^\s*using:\s*["\']?composite["\']?',
            'docker': r'^\s*using:\s*["\']?docker["\']?',
            'node': r'^\s*using:\s*["\']?node(\d+)?["\']?'
        }
    
    def parse_action_yml(self, content: str) -> Dict:
        """
        解析 action.yml 或 action.yaml 文件
        
        Returns:
            包含 action 元数据和依赖的字典
        """
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return {}
            
            result = {
                'name': data.get('name', ''),
                'description': data.get('description', ''),
                'author': data.get('author', ''),
                'inputs': data.get('inputs', {}),
                'outputs': data.get('outputs', {}),
                'runs': data.get('runs', {}),
                'dependencies': []
            }
            
            # 解析依赖
            if 'runs' in data:
                runs = data['runs']
                using = runs.get('using', '')
                
                # 复合 Action 中的依赖
                if using == 'composite' and 'steps' in runs:
                    for step in runs['steps']:
                        if isinstance(step, dict) and 'uses' in step:
                            action_ref = step['uses']
                            parsed = self._parse_action_ref(action_ref)
                            if parsed:
                                result['dependencies'].append({
                                    'action': action_ref,
                                    'owner': parsed[0],
                                    'repo': parsed[1],
                                    'version': parsed[2],
                                    'type': 'composite_dependency'
                                })
                
                # Docker Action 中的依赖
                elif using == 'docker':
                    image = runs.get('image', '')
                    if image:
                        result['dependencies'].append({
                            'action': image,
                            'type': 'docker_image'
                        })
            
            return result
            
        except yaml.YAMLError as e:
            print(f"Error parsing action YAML: {e}")
            return {}
    
    def parse_workflow_yml(self, content: str) -> List[Dict]:
        """
        解析 workflow YAML 文件，提取使用的 Actions
        
        Returns:
            包含所有使用的 Actions 的列表
        """
        try:
            data = yaml.safe_load(content)
            actions = []
            
            if not isinstance(data, dict):
                return actions
            
            # 遍历所有 jobs
            jobs = data.get('jobs', {})
            for job_name, job_config in jobs.items():
                if isinstance(job_config, dict):
                    steps = job_config.get('steps', [])
                    for step in steps:
                        if isinstance(step, dict) and 'uses' in step:
                            action_ref = step['uses']
                            parsed = self._parse_action_ref(action_ref)
                            if parsed:
                                actions.append({
                                    'job': job_name,
                                    'action': action_ref,
                                    'owner': parsed[0],
                                    'repo': parsed[1],
                                    'version': parsed[2],
                                    'step_name': step.get('name', '')
                                })
            
            return actions
            
        except yaml.YAMLError as e:
            print(f"Error parsing workflow YAML: {e}")
            return []
    
    def parse_dockerfile(self, content: str) -> List[str]:
        """
        解析 Dockerfile，提取基础镜像依赖
        
        Returns:
            基础镜像列表
        """
        images = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('FROM'):
                parts = line.split()
                if len(parts) >= 2:
                    image = parts[1].split(':')[0]  # 移除标签
                    images.append(image)
        
        return images
    
    def extract_from_text(self, text: str, pattern_type: str = 'uses') -> List[str]:
        """从文本中提取特定模式的内容"""
        if pattern_type not in self.action_patterns:
            return []
        
        pattern = self.action_patterns[pattern_type]
        matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        return [match.strip() for match in matches]
    
    def _parse_action_ref(self, action_ref: str) -> Optional[Tuple[str, str, str]]:
        """解析 Action 引用字符串"""
        # 移除本地路径
        if action_ref.startswith('./') or action_ref.startswith('../'):
            return None
        
        # 匹配 owner/repo@version 格式
        match = re.match(r'^([a-zA-Z0-9-]+)/([a-zA-Z0-9-_.]+)(?:@([a-zA-Z0-9._-]+))?$', action_ref)
        if match:
            owner, repo, version = match.groups()
            return owner, repo or '', version or 'latest'
        
        return None
    
    def find_dependencies_in_file(self, filepath: Path) -> Dict:
        """从文件中查找依赖"""
        if not filepath.exists():
            return {}
        
        content = filepath.read_text(encoding='utf-8')
        
        if filepath.suffix in ['.yml', '.yaml']:
            if filepath.name in ['action.yml', 'action.yaml']:
                return self.parse_action_yml(content)
            else:
                return {'workflow_actions': self.parse_workflow_yml(content)}
        elif filepath.name == 'Dockerfile':
            return {'docker_images': self.parse_dockerfile(content)}
        
        return {}