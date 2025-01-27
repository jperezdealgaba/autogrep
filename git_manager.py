import git
import shutil
from pathlib import Path
from config import Config
from patch_processor import PatchInfo
from typing import Optional
import logging
import subprocess

class GitManager:
    def __init__(self, config: Config):
        self.config = config
        self._check_git_installation()
    
    def _check_git_installation(self):
        """Check if git is installed and accessible."""
        try:
            subprocess.run(["git", "--version"], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE, 
                         check=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Git command failed. Please ensure Git is installed and in your PATH.")
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not found in PATH. Please install Git first.")
    
    def _sanitize_repo_path(self, owner: str, name: str) -> str:
        """Create a safe repository directory name."""
        return f"{owner}_{name}".replace('/', '_').replace('\\', '_')
    
    def prepare_repo(self, patch_info: PatchInfo) -> Optional[Path]:
        """Clone or update repository and checkout the relevant commits."""
        safe_path = self._sanitize_repo_path(patch_info.repo_owner, patch_info.repo_name)
        repo_path = self.config.repos_cache_dir / safe_path
        
        try:
            if not repo_path.exists():
                logging.info(f"Cloning repository: {patch_info.repo_owner}/{patch_info.repo_name}")
                # Try HTTPS first
                repo_url = f"https://github.com/{patch_info.repo_owner}/{patch_info.repo_name}"
                try:
                    repo = git.Repo.clone_from(
                        repo_url,
                        repo_path,
                        progress=git.RemoteProgress()
                    )
                except git.exc.GitCommandError as e:
                    # If HTTPS fails, clean up and try SSH
                    if repo_path.exists():
                        shutil.rmtree(repo_path)
                    logging.info("HTTPS clone failed, trying SSH...")
                    repo_url = f"git@github.com:{patch_info.repo_owner}/{patch_info.repo_name}.git"
                    repo = git.Repo.clone_from(
                        repo_url,
                        repo_path,
                        progress=git.RemoteProgress()
                    )
            else:
                logging.info(f"Using cached repository at {repo_path}")
                repo = git.Repo(repo_path)
                try:
                    repo.remote().fetch()
                except git.exc.GitCommandError as e:
                    logging.warning(f"Failed to fetch updates: {e}")
                    # Continue with cached version
            
            # Verify the commit exists
            try:
                commit = repo.commit(patch_info.commit_id)
                logging.info(f"Found commit: {commit.hexsha}")
            except git.exc.BadName:
                logging.error(f"Commit {patch_info.commit_id} not found in repository")
                return None
            
            return repo_path
            
        except Exception as e:
            logging.error(f"Error preparing repository: {str(e)}", exc_info=True)
            # Clean up failed clone
            if repo_path.exists():
                shutil.rmtree(repo_path)
            return None
    
    def reset_repo(self, repo_path: Path) -> bool:
        """Reset repository to clean state, discarding all local changes."""
        try:
            repo = git.Repo(repo_path)
            repo.git.reset('--hard')  # Reset any staged changes
            repo.git.clean('-fd')     # Remove untracked files and directories
            return True
        except Exception as e:
            logging.error(f"Error resetting repository: {e}")
            return False

    def cleanup_repo(self, repo_path: Path):
        """Clean up repository directory if needed."""
        try:
            if repo_path.exists():
                shutil.rmtree(repo_path)
        except Exception as e:
            logging.error(f"Error cleaning up repository: {e}")