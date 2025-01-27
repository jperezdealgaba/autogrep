from dataclasses import dataclass
from pathlib import Path
import os

@dataclass
class Config:
    rules_dir: Path = Path("rules")
    generated_rules_dir: Path = Path("generated_rules")
    patches_dir: Path = Path("cvedataset-patches")
    repos_cache_dir: Path = Path("cache/repos")
    max_files_changed: int = 1
    max_retries: int = 5
    openrouter_api_key: str = os.getenv("OPENROUTER_API_KEY")
    openrouter_base_url: str = "https://openrouter.ai/api/v1"