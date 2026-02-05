# 文件读写辅助
# utils/file_utils.py
import json
import yaml
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional
import gzip

def load_config(config_path: str = "config.yaml") -> Dict:
    """加载配置文件"""
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    return config

def save_json(data: Any, filepath: str, compress: bool = False) -> None:
    """保存 JSON 数据"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    
    if compress:
        with gzip.open(filepath, 'wt', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

def load_json(filepath: str, compressed: bool = False) -> Any:
    """加载 JSON 数据"""
    if not os.path.exists(filepath):
        return None
    
    try:
        if compressed:
            with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None

def save_pickle(data: Any, filepath: str) -> None:
    """保存 pickle 数据"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'wb') as f:
        pickle.dump(data, f)

def load_pickle(filepath: str) -> Any:
    """加载 pickle 数据"""
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'rb') as f:
        return pickle.load(f)

def ensure_dir(directory: str) -> None:
    """确保目录存在"""
    Path(directory).mkdir(parents=True, exist_ok=True)

def list_files(directory: str, pattern: str = "*.json") -> List[str]:
    """列出目录下匹配模式的文件"""
    return [str(p) for p in Path(directory).glob(pattern)]

def read_yaml(filepath: str) -> Dict:
    """读取 YAML 文件"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def write_yaml(data: Dict, filepath: str) -> None:
    """写入 YAML 文件"""
    ensure_dir(Path(filepath).parent)
    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False)