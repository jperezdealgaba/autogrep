from dataclasses import dataclass, field
from pathlib import Path
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
    log_rules_csv: bool = False
    cache_manager: CacheManager = field(init=False)

    def __post_init__(self):
        self.cache_manager = CacheManager(self.repos_cache_dir)