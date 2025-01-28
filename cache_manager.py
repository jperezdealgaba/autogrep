from pathlib import Path
import json
import logging
from typing import Set, Dict, Optional
from datetime import datetime

class CacheManager:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.processed_patches_file = cache_dir / "processed_patches.json"
        self.failed_repos_file = cache_dir / "failed_repos.json"
        self.processed_patches: Set[str] = set()
        self.failed_repos: Dict[str, dict] = {}
        self._load_caches()

    def _load_caches(self):
        """Load cached data from disk."""
        try:
            if self.processed_patches_file.exists():
                with open(self.processed_patches_file) as f:
                    self.processed_patches = set(json.load(f))
            if self.failed_repos_file.exists():
                with open(self.failed_repos_file) as f:
                    self.failed_repos = json.load(f)
        except Exception as e:
            logging.error(f"Error loading caches: {e}")
            # Initialize empty caches if loading fails
            self.processed_patches = set()
            self.failed_repos = {}

    def _save_caches(self):
        """Save cached data to disk."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.processed_patches_file, 'w') as f:
                json.dump(list(self.processed_patches), f)
            with open(self.failed_repos_file, 'w') as f:
                json.dump(self.failed_repos, f)
        except Exception as e:
            logging.error(f"Error saving caches: {e}")

    def is_patch_processed(self, patch_filename: str) -> bool:
        """Check if a patch has been processed."""
        return patch_filename in self.processed_patches

    def mark_patch_processed(self, patch_filename: str):
        """Mark a patch as processed."""
        self.processed_patches.add(patch_filename)
        self._save_caches()

    def is_repo_failed(self, repo_key: str) -> bool:
        """Check if a repository has failed processing."""
        return repo_key in self.failed_repos

    def mark_repo_failed(self, repo_key: str, error: str):
        """Mark a repository as failed with error details."""
        self.failed_repos[repo_key] = {
            "error": error,
            "timestamp": datetime.now().isoformat(),
            "attempts": self.failed_repos.get(repo_key, {}).get("attempts", 0) + 1
        }
        self._save_caches()

    def get_repo_error(self, repo_key: str) -> Optional[str]:
        """Get the error message for a failed repository."""
        if repo_key in self.failed_repos:
            return self.failed_repos[repo_key]["error"]
        return None

    def clear_failed_repo(self, repo_key: str):
        """Remove a repository from the failed list."""
        if repo_key in self.failed_repos:
            del self.failed_repos[repo_key]
            self._save_caches()