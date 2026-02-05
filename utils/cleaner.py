# utils/cleaner.py
import shutil
import os
import logging
from pathlib import Path
from typing import List, Optional
import json

class DataCleaner:
    """数据清理器 - 清理爬取和分析过程中生成的数据"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        初始化数据清理器
        
        Args:
            config_path: 配置文件路径
        """
        self.logger = logging.getLogger(__name__)
        
        # 加载配置
        from .file_utils import load_config
        self.config = load_config(config_path)
        
        # 获取需要清理的目录
        self.data_dirs = []
        self.output_dirs = []
        
        if 'paths' in self.config:
            paths = self.config['paths']
            self.data_dirs = [
                paths.get('raw_data', 'data/raw'),
                paths.get('processed_data', 'data/processed'),
                paths.get('graphs', 'data/graphs')
            ]
        
        # 固定的输出目录
        self.output_dirs = [
            'output/reports',
            'output/visualizations',
            'output'
        ]
        
        # 日志目录
        self.log_dir = self.config.get('paths', {}).get('logs', 'logs')
        
    def clear_all_data(self, keep_config: bool = True, keep_logs: bool = False) -> dict:
        """
        清除所有爬取和分析数据
        
        Args:
            keep_config: 是否保留配置文件
            keep_logs: 是否保留日志文件
            
        Returns:
            清理结果的统计信息
        """
        self.logger.info("开始清理所有数据...")
        
        stats = {
            'directories_cleaned': [],
            'files_removed': 0,
            'total_size_freed': 0,
            'errors': []
        }
        
        try:
            # 1. 清理数据目录
            for dir_path in self.data_dirs:
                result = self._clear_directory(dir_path, keep_files=['.gitkeep'])
                if result['success']:
                    stats['directories_cleaned'].append(dir_path)
                    stats['files_removed'] += result['files_removed']
                    stats['total_size_freed'] += result['size_freed']
                else:
                    stats['errors'].append(f"清理目录失败: {dir_path} - {result.get('error')}")
            
            # 2. 清理输出目录
            for dir_path in self.output_dirs:
                result = self._clear_directory(dir_path, keep_files=['.gitkeep'])
                if result['success']:
                    stats['directories_cleaned'].append(dir_path)
                    stats['files_removed'] += result['files_removed']
                    stats['total_size_freed'] += result['size_freed']
                else:
                    stats['errors'].append(f"清理目录失败: {dir_path} - {result.get('error')}")
            
            # 3. 清理日志目录（可选）
            if not keep_logs:
                result = self._clear_directory(self.log_dir)
                if result['success']:
                    stats['directories_cleaned'].append(self.log_dir)
                    stats['files_removed'] += result['files_removed']
                    stats['total_size_freed'] += result['size_freed']
            
            # 4. 清理临时文件
            temp_files = self._find_temp_files()
            for temp_file in temp_files:
                try:
                    size = temp_file.stat().st_size if temp_file.exists() else 0
                    temp_file.unlink()
                    stats['files_removed'] += 1
                    stats['total_size_freed'] += size
                except Exception as e:
                    stats['errors'].append(f"删除临时文件失败: {temp_file} - {e}")
            
            # 转换大小为易读格式
            stats['total_size_freed_human'] = self._format_file_size(stats['total_size_freed'])
            
            self.logger.info(f"数据清理完成: 清理了 {stats['files_removed']} 个文件, "
                           f"释放了 {stats['total_size_freed_human']}")
            
            if stats['errors']:
                self.logger.warning(f"清理过程中出现 {len(stats['errors'])} 个错误")
            
            return stats
            
        except Exception as e:
            self.logger.error(f"数据清理过程发生错误: {e}")
            stats['errors'].append(str(e))
            return stats
    
    def clear_crawled_data_only(self) -> dict:
        """
        仅清除爬取的数据，保留分析结果
        
        Returns:
            清理结果的统计信息
        """
        self.logger.info("开始清理爬取数据...")
        
        stats = {
            'directories_cleaned': [],
            'files_removed': 0,
            'total_size_freed': 0,
            'errors': []
        }
        
        try:
            # 只清理原始数据目录
            raw_data_dir = self.config.get('paths', {}).get('raw_data', 'data/raw')
            
            if raw_data_dir:
                result = self._clear_directory(raw_data_dir, keep_files=['.gitkeep'])
                if result['success']:
                    stats['directories_cleaned'].append(raw_data_dir)
                    stats['files_removed'] += result['files_removed']
                    stats['total_size_freed'] += result['size_freed']
                    self.logger.info(f"爬取数据清理完成: {raw_data_dir}")
                else:
                    stats['errors'].append(f"清理目录失败: {raw_data_dir}")
            
            # 转换大小为易读格式
            stats['total_size_freed_human'] = self._format_file_size(stats['total_size_freed'])
            
            return stats
            
        except Exception as e:
            self.logger.error(f"清理爬取数据失败: {e}")
            stats['errors'].append(str(e))
            return stats
    
    def clear_analysis_results_only(self) -> dict:
        """
        仅清除分析结果，保留爬取的数据
        
        Returns:
            清理结果的统计信息
        """
        self.logger.info("开始清理分析结果...")
        
        stats = {
            'directories_cleaned': [],
            'files_removed': 0,
            'total_size_freed': 0,
            'errors': []
        }
        
        try:
            # 清理处理后的数据和图数据
            dirs_to_clear = []
            
            if 'paths' in self.config:
                paths = self.config['paths']
                dirs_to_clear.extend([
                    paths.get('processed_data', 'data/processed'),
                    paths.get('graphs', 'data/graphs')
                ])
            
            # 清理输出目录
            dirs_to_clear.extend(self.output_dirs)
            
            for dir_path in dirs_to_clear:
                result = self._clear_directory(dir_path, keep_files=['.gitkeep'])
                if result['success']:
                    stats['directories_cleaned'].append(dir_path)
                    stats['files_removed'] += result['files_removed']
                    stats['total_size_freed'] += result['size_freed']
                else:
                    stats['errors'].append(f"清理目录失败: {dir_path} - {result.get('error')}")
            
            # 转换大小为易读格式
            stats['total_size_freed_human'] = self._format_file_size(stats['total_size_freed'])
            
            self.logger.info(f"分析结果清理完成: 清理了 {stats['files_removed']} 个文件")
            
            return stats
            
        except Exception as e:
            self.logger.error(f"清理分析结果失败: {e}")
            stats['errors'].append(str(e))
            return stats
    
    def clear_logs_only(self) -> dict:
        """
        仅清除日志文件
        
        Returns:
            清理结果的统计信息
        """
        self.logger.info("开始清理日志文件...")
        
        stats = {
            'directories_cleaned': [],
            'files_removed': 0,
            'total_size_freed': 0,
            'errors': []
        }
        
        try:
            result = self._clear_directory(self.log_dir)
            if result['success']:
                stats['directories_cleaned'].append(self.log_dir)
                stats['files_removed'] += result['files_removed']
                stats['total_size_freed'] += result['size_freed']
            
            # 转换大小为易读格式
            stats['total_size_freed_human'] = self._format_file_size(stats['total_size_freed'])
            
            self.logger.info(f"日志清理完成: 清理了 {stats['files_removed']} 个日志文件")
            
            return stats
            
        except Exception as e:
            self.logger.error(f"清理日志失败: {e}")
            stats['errors'].append(str(e))
            return stats
    
    def get_storage_usage(self) -> dict:
        """
        获取存储使用情况
        
        Returns:
            各目录的存储使用统计
        """
        self.logger.info("正在统计存储使用情况...")
        
        usage_stats = {
            'total_size': 0,
            'directories': [],
            'file_types': {}
        }
        
        try:
            # 统计所有相关目录
            all_dirs = self.data_dirs + self.output_dirs + [self.log_dir]
            
            for dir_path in all_dirs:
                dir_info = self._get_directory_size(dir_path)
                if dir_info['size'] > 0:
                    usage_stats['directories'].append(dir_info)
                    usage_stats['total_size'] += dir_info['size']
                    
                    # 统计文件类型
                    for file_type, size in dir_info.get('file_types', {}).items():
                        usage_stats['file_types'][file_type] = usage_stats['file_types'].get(file_type, 0) + size
            
            # 转换为易读格式
            usage_stats['total_size_human'] = self._format_file_size(usage_stats['total_size'])
            for dir_info in usage_stats['directories']:
                dir_info['size_human'] = self._format_file_size(dir_info['size'])
            
            for file_type in usage_stats['file_types']:
                usage_stats['file_types'][file_type] = {
                    'bytes': usage_stats['file_types'][file_type],
                    'human': self._format_file_size(usage_stats['file_types'][file_type])
                }
            
            return usage_stats
            
        except Exception as e:
            self.logger.error(f"统计存储使用情况失败: {e}")
            return usage_stats
    
    def _clear_directory(self, dir_path: str, keep_files: List[str] = None) -> dict:
        """
        清理目录内容
        
        Args:
            dir_path: 目录路径
            keep_files: 需要保留的文件名列表
            
        Returns:
            清理结果的统计信息
        """
        result = {
            'success': False,
            'files_removed': 0,
            'size_freed': 0,
            'error': None
        }
        
        if keep_files is None:
            keep_files = []
        
        dir_path_obj = Path(dir_path)
        
        if not dir_path_obj.exists():
            result['error'] = f"目录不存在: {dir_path}"
            result['success'] = True  # 目录不存在也算清理成功
            return result
        
        if not dir_path_obj.is_dir():
            result['error'] = f"不是目录: {dir_path}"
            return result
        
        try:
            # 遍历目录中的所有文件和子目录
            for item in dir_path_obj.iterdir():
                # 检查是否需要保留
                if item.name in keep_files:
                    continue
                
                try:
                    if item.is_file():
                        # 删除文件
                        size = item.stat().st_size
                        item.unlink()
                        result['files_removed'] += 1
                        result['size_freed'] += size
                    
                    elif item.is_dir():
                        # 删除整个子目录
                        size = self._get_directory_size(item)['size']
                        shutil.rmtree(item)
                        result['files_removed'] += 1  # 目录算一个文件
                        result['size_freed'] += size
                
                except Exception as e:
                    self.logger.warning(f"删除失败 {item}: {e}")
                    # 继续清理其他文件
            
            result['success'] = True
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def _get_directory_size(self, dir_path: Path) -> dict:
        """
        获取目录大小和文件统计
        
        Args:
            dir_path: 目录路径
            
        Returns:
            目录统计信息
        """
        total_size = 0
        file_count = 0
        dir_count = 0
        file_types = {}
        
        if not dir_path.exists() or not dir_path.is_dir():
            return {
                'path': str(dir_path),
                'size': 0,
                'file_count': 0,
                'dir_count': 0,
                'file_types': {}
            }
        
        try:
            for item in dir_path.rglob('*'):
                try:
                    if item.is_file():
                        size = item.stat().st_size
                        total_size += size
                        file_count += 1
                        
                        # 统计文件类型
                        ext = item.suffix.lower()
                        if ext:
                            file_types[ext] = file_types.get(ext, 0) + size
                    
                    elif item.is_dir():
                        dir_count += 1
                except (OSError, PermissionError):
                    continue
            
            return {
                'path': str(dir_path),
                'size': total_size,
                'file_count': file_count,
                'dir_count': dir_count,
                'file_types': file_types
            }
            
        except Exception as e:
            self.logger.warning(f"获取目录大小失败 {dir_path}: {e}")
            return {
                'path': str(dir_path),
                'size': 0,
                'file_count': 0,
                'dir_count': 0,
                'file_types': {},
                'error': str(e)
            }
    
    def _find_temp_files(self) -> List[Path]:
        """
        查找临时文件
        
        Returns:
            临时文件路径列表
        """
        temp_files = []
        
        # 常见的临时文件模式
        temp_patterns = [
            '*.tmp',
            '*.temp',
            '*.bak',
            '*.backup',
            '*.swp',
            '*.swo',
            '*.pyc',
            '__pycache__',
            '.ipynb_checkpoints'
        ]
        
        # 在当前目录和子目录中查找
        for pattern in temp_patterns:
            for file_path in Path('.').rglob(pattern):
                temp_files.append(file_path)
        
        return temp_files
    
    def _format_file_size(self, size_bytes: int) -> str:
        """
        格式化文件大小为易读格式
        
        Args:
            size_bytes: 字节大小
            
        Returns:
            格式化后的字符串
        """
        if size_bytes == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        
        size = float(size_bytes)
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.2f} {units[unit_index]}"
    
    def create_clean_report(self, stats: dict) -> str:
        """
        创建清理报告
        
        Args:
            stats: 清理统计信息
            
        Returns:
            格式化后的报告字符串
        """
        report_lines = [
            "=" * 60,
            "数据清理报告",
            "=" * 60,
            f"清理时间: {self._get_current_timestamp()}",
            ""
        ]
        
        if stats['directories_cleaned']:
            report_lines.append("已清理的目录:")
            for dir_path in stats['directories_cleaned']:
                report_lines.append(f"  - {dir_path}")
            report_lines.append("")
        
        report_lines.extend([
            f"删除文件总数: {stats['files_removed']}",
            f"释放存储空间: {stats.get('total_size_freed_human', '0 B')}",
            ""
        ])
        
        if stats['errors']:
            report_lines.append("清理过程中出现的错误:")
            for error in stats['errors']:
                report_lines.append(f"  - {error}")
            report_lines.append("")
        
        report_lines.append("=" * 60)
        
        return "\n".join(report_lines)
    
    def _get_current_timestamp(self) -> str:
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')