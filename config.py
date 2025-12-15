from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os
from cache_manager import CacheManager

@dataclass
class Config:
    rules_dir :Path = Path("rules")
    generated_rules_dir: Path = Path("generated_rules")
    patches_dir: Path = Path("cvedataset-patches")
    repos_cache_dir: Path = Path("cache/repos")
    max_files_changed: int = 1
    max_retries: int = 8
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY")
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    # LLM models for different tasks
    generation_model: str = "deepseek/deepseek-chat"
    backup_model: Optional[str] = None
    validation_model: str = "deepseek/deepseek-chat"
    log_rules_csv: bool = False
    max_workers: int = 2
    enhanced_retry_feedback: bool = False
    # RAG system configuration
    enable_rag: bool = False
    opengrep_rules_path: Optional[Path] = None
    rag_top_k: int = 3
    rag_auto_clone: bool = True
    cache_manager: CacheManager = field(init=False)

    def __post_init__(self):
        self.cache_manager = CacheManager(self.repos_cache_dir)